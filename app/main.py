"""Lead Rescue: small multi-tenant lead and review workflow MVP.

Twilio webhooks require the proper signature; demo actions never send messages.
"""
from __future__ import annotations

import hashlib
import base64
import html
import hmac
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, select, func, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware
import httpx

ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT.parent / 'data' / 'lead_rescue.sqlite3'}")
APP_SECRET = os.getenv("APP_SECRET", "development-only-secret-not-for-production")
SMS_MODE = os.getenv("SMS_MODE", "demo").lower()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8135").rstrip("/")
TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "")
REQUIRE_TWILIO_SIGNATURE = os.getenv("REQUIRE_TWILIO_SIGNATURE", "true").lower() == "true"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

if SMS_MODE not in {"demo", "live"}:
    raise RuntimeError("SMS_MODE must be demo or live")
if SMS_MODE == "live" and (not TWILIO_SID or not TWILIO_TOKEN or not TWILIO_NUMBER or not REQUIRE_TWILIO_SIGNATURE or not PUBLIC_BASE_URL.startswith("https://")):
    raise RuntimeError("Live mode requires Twilio credentials, signature checking, and a public HTTPS base URL")
if SMS_MODE == "live" and (APP_SECRET == "development-only-secret-not-for-production" or len(APP_SECRET) < 32):
    raise RuntimeError("Set a strong APP_SECRET before enabling live mode")

class Base(DeclarativeBase):
    pass

class Business(Base):
    __tablename__ = "businesses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    twilio_number: Mapped[str] = mapped_column(String(24), default="")
    review_url: Mapped[str] = mapped_column(String(1200), default="")
    auto_reply_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    welcome_text: Mapped[str] = mapped_column(String(600), default="Thanks for calling! We missed you. How can we help?")

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    business_id: Mapped[int] = mapped_column(ForeignKey("businesses.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    business: Mapped[Business] = relationship()

class Lead(Base):
    __tablename__ = "leads"
    __table_args__ = (UniqueConstraint("business_id", "phone", name="uq_lead_business_phone"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    business_id: Mapped[int] = mapped_column(ForeignKey("businesses.id"), index=True)
    name: Mapped[str] = mapped_column(String(130), default="")
    phone: Mapped[str] = mapped_column(String(25))
    service: Mapped[str] = mapped_column(String(220), default="")
    stage: Mapped[str] = mapped_column(String(32), default="new")
    # Requires affirmative, documented opt-in from the person before outbound SMS.
    sms_consent: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_note: Mapped[str] = mapped_column(String(500), default="")
    opted_out: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    business_id: Mapped[int] = mapped_column(ForeignKey("businesses.id"), index=True)
    lead_id: Mapped[int] = mapped_column(ForeignKey("leads.id"), index=True)
    direction: Mapped[str] = mapped_column(String(12))
    kind: Mapped[str] = mapped_column(String(32), default="sms")
    body: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="logged")
    provider_sid: Mapped[str] = mapped_column(String(100), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    business_id: Mapped[int] = mapped_column(ForeignKey("businesses.id"), index=True)
    provider_sid: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)
app = FastAPI(title="Reboot Lead Rescue", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, https_only=COOKIE_SECURE, same_site="lax")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
templates = Jinja2Templates(directory=str(ROOT / "templates"))

STAGES = ("new", "contacted", "quoted", "won", "lost")
E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def valid_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt, digest = stored.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def db_session():
    with SessionFactory() as db:
        yield db


def page(request: Request, template: str, **kwargs):
    return templates.TemplateResponse(request, template, {"request": request, "mode": SMS_MODE, **kwargs})


def redirect(path: str):
    return RedirectResponse(path, status_code=303)


def current_user(request: Request, db: Session) -> User:
    uid = request.session.get("uid")
    user = db.get(User, uid) if isinstance(uid, int) else None
    if not user:
        raise HTTPException(401, "Sign in required")
    return user


def business_for(request: Request, db: Session) -> Business:
    return current_user(request, db).business


def csrf(request: Request, token: str):
    expected = request.session.get("csrf")
    if not expected or not hmac.compare_digest(token or "", expected):
        raise HTTPException(403, "Invalid form token")


def context(request: Request, db: Session):
    b = business_for(request, db)
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return {"business": b, "token": request.session["csrf"]}


def lead_for(db: Session, business_id: int, lead_id: int) -> Lead:
    lead = db.scalar(select(Lead).where(Lead.id == lead_id, Lead.business_id == business_id))
    if not lead:
        raise HTTPException(404, "Lead not found")
    return lead


def get_or_create_lead(db: Session, b: Business, phone: str) -> Lead:
    lead = db.scalar(select(Lead).where(Lead.business_id == b.id, Lead.phone == phone))
    if not lead:
        lead = Lead(business_id=b.id, phone=phone)
        db.add(lead)
        db.flush()
    return lead


def log_message(db: Session, b: Business, lead: Lead, direction: str, body: str, kind: str="sms", status: str="logged", provider_sid: str=""):
    msg = Message(business_id=b.id, lead_id=lead.id, direction=direction, body=body, kind=kind, status=status, provider_sid=provider_sid)
    db.add(msg)
    return msg


def send_sms(db: Session, b: Business, lead: Lead, body: str, kind: str="sms") -> str:
    if not lead.sms_consent or lead.opted_out:
        raise ValueError("Outbound SMS requires recorded consent and no opt-out")
    if SMS_MODE == "demo":
        log_message(db, b, lead, "outbound", body, kind, "demo-only")
        return "demo-only"
    if not b.twilio_number or b.twilio_number != TWILIO_NUMBER:
        raise ValueError("Verified Twilio sending number not configured for this business")
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json", auth=(TWILIO_SID, TWILIO_TOKEN), data={"To": lead.phone, "From": b.twilio_number, "Body": body})
            resp.raise_for_status()
            provider_sid = resp.json().get("sid", "")
        log_message(db, b, lead, "outbound", body, kind, "submitted", provider_sid)
        return "submitted"
    except Exception:
        log_message(db, b, lead, "outbound", body, kind, "failed")
        return "failed"


def verify_twilio(request: Request, payload: dict):
    if SMS_MODE != "live":
        raise HTTPException(403, "Provider webhooks disabled in demo mode")
    signature = request.headers.get("X-Twilio-Signature", "")
    # Must match the exact publicly accessible URL configured in Twilio.
    url = PUBLIC_BASE_URL + request.url.path
    if request.url.query:
        url += "?" + request.url.query
    # Twilio's form-encoded request scheme: URL followed by alphabetical key/value pairs.
    signed = url + "".join(k + str(payload[k]) for k in sorted(payload))
    expected = base64.b64encode(hmac.new(TWILIO_TOKEN.encode(), signed.encode(), hashlib.sha1).digest()).decode()
    if not signature or not hmac.compare_digest(expected, signature):
        raise HTTPException(403, "Bad webhook signature")


def inbound_business(db: Session, to_number: str):
    b = db.scalar(select(Business).where(Business.twilio_number == to_number))
    if not b:
        raise HTTPException(404, "Unknown destination")
    return b


@app.on_event("startup")
def init():
    Base.metadata.create_all(engine)
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if email and password:
        if len(password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")
        with SessionFactory() as db:
            user = db.scalar(select(User).where(User.email == email))
            if not user:
                slug = "initial-business"
                b = db.scalar(select(Business).where(Business.slug == slug))
                if not b:
                    b = Business(name=os.getenv("BUSINESS_NAME", "My Business"), slug=slug)
                    db.add(b)
                    db.flush()
                db.add(User(business_id=b.id, email=email, password_hash=hash_password(password)))
                db.commit()


@app.get("/health")
def health():
    return {"status": "ok", "mode": SMS_MODE}


@app.get("/login", response_class=HTMLResponse)
def login_view(request: Request):
    return page(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if not user or not valid_password(password, user.password_hash):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Incorrect email or password", "mode": SMS_MODE}, status_code=401)
    request.session.clear()
    request.session["uid"] = user.id
    request.session["csrf"] = secrets.token_urlsafe(32)
    return redirect("/")


@app.post("/logout")
def logout(request: Request, token: str = Form(...)):
    csrf(request, token)
    request.session.clear()
    return redirect("/login")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(db_session)):
    c = context(request, db)
    b = c["business"]
    leads = db.scalars(select(Lead).where(Lead.business_id == b.id).order_by(Lead.created_at.desc())).all()
    messages = db.scalars(select(Message).where(Message.business_id == b.id).order_by(Message.created_at.desc()).limit(7)).all()
    stats = {"leads": len(leads), "new": sum(l.stage == "new" for l in leads), "won": sum(l.stage == "won" for l in leads), "messages": db.scalar(select(func.count(Message.id)).where(Message.business_id == b.id)) or 0}
    return page(request, "dashboard.html", **c, leads=leads, messages=messages, stats=stats)


@app.post("/leads/new")
def add_lead(request: Request, phone: str = Form(...), name: str = Form(""), service: str = Form(""), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    phone = phone.strip()
    if not E164.fullmatch(phone):
        raise HTTPException(400, "Phone must be in E.164 format, e.g. +13215550123")
    lead = get_or_create_lead(db, b, phone)
    lead.name = name[:130].strip()
    lead.service = service[:220].strip()
    db.commit()
    return redirect(f"/leads/{lead.id}")


@app.get("/leads/{lead_id}", response_class=HTMLResponse)
def lead_view(request: Request, lead_id: int, db: Session = Depends(db_session)):
    c = context(request, db)
    lead = lead_for(db, c["business"].id, lead_id)
    messages = db.scalars(select(Message).where(Message.lead_id == lead.id, Message.business_id == c["business"].id).order_by(Message.created_at.asc())).all()
    return page(request, "lead.html", **c, lead=lead, messages=messages, stages=STAGES)


@app.post("/leads/{lead_id}/update")
def update_lead(request: Request, lead_id: int, stage: str = Form(...), name: str = Form(""), service: str = Form(""), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    lead = lead_for(db, b.id, lead_id)
    if stage not in STAGES:
        raise HTTPException(400, "Invalid stage")
    lead.stage, lead.name, lead.service = stage, name[:130].strip(), service[:220].strip()
    db.commit()
    return redirect(f"/leads/{lead_id}")


@app.post("/leads/{lead_id}/consent")
def record_consent(request: Request, lead_id: int, consent_note: str = Form(""), consent: str = Form("no"), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    lead = lead_for(db, b.id, lead_id)
    if consent == "yes" and len(consent_note.strip()) < 12:
        raise HTTPException(400, "Record how and when the person consented (at least 12 characters)")
    lead.sms_consent = consent == "yes"
    lead.consent_note = consent_note[:500].strip() if lead.sms_consent else ""
    # Opt-outs cannot be overridden through this admin UI; the person must text START again.
    db.commit()
    return redirect(f"/leads/{lead_id}")


@app.post("/leads/{lead_id}/send")
def manual_send(request: Request, lead_id: int, body: str = Form(...), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    lead = lead_for(db, b.id, lead_id)
    if not body.strip() or len(body) > 1000:
        raise HTTPException(400, "Message must be 1–1000 characters")
    try:
        send_sms(db, b, lead, body.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.commit()
    return redirect(f"/leads/{lead_id}")


@app.post("/leads/{lead_id}/review")
def request_review(request: Request, lead_id: int, token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    lead = lead_for(db, b.id, lead_id)
    if not b.review_url.startswith("https://"):
        raise HTTPException(400, "Configure an HTTPS review link in Settings")
    body = f"Thanks for choosing {b.name}! If you'd like to share your experience, please leave an honest Google review: {b.review_url} Reply STOP to opt out."
    try:
        send_sms(db, b, lead, body, "review")
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.commit()
    return redirect(f"/leads/{lead_id}")


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request, db: Session = Depends(db_session)):
    return page(request, "settings.html", **context(request, db))


@app.post("/settings")
def save_settings(request: Request, name: str = Form(...), review_url: str = Form(""), welcome_text: str = Form(""), twilio_number: str = Form(""), auto_reply_enabled: str = Form("no"), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    b = business_for(request, db)
    if not name.strip() or len(name) > 160 or len(welcome_text) > 600:
        raise HTTPException(400, "Invalid business name or text length")
    review_url = review_url.strip()
    if review_url and (not review_url.startswith("https://") or len(review_url) > 1200):
        raise HTTPException(400, "Review URL must be HTTPS")
    phone = twilio_number.strip()
    if phone and not E164.fullmatch(phone):
        raise HTTPException(400, "Invalid sending phone number")
    if SMS_MODE == "live" and phone and phone != TWILIO_NUMBER:
        raise HTTPException(400, "Phone must match the configured, verified Twilio number")
    b.name, b.review_url, b.welcome_text, b.twilio_number = name.strip(), review_url, welcome_text.strip(), phone
    b.auto_reply_enabled = auto_reply_enabled == "yes"
    db.commit()
    return redirect("/settings")


@app.post("/demo/missed-call")
def demo_missed_call(request: Request, phone: str = Form(...), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    if SMS_MODE != "demo":
        raise HTTPException(404)
    b = business_for(request, db)
    phone = phone.strip()
    if not E164.fullmatch(phone):
        raise HTTPException(400, "Use E.164 phone format")
    lead = get_or_create_lead(db, b, phone)
    log_message(db, b, lead, "inbound", "Missed call (simulated)", "call", "demo-only")
    if b.auto_reply_enabled and lead.sms_consent and not lead.opted_out:
        send_sms(db, b, lead, b.welcome_text)
    db.commit()
    return redirect(f"/leads/{lead.id}")


@app.post("/demo/inbound")
def demo_inbound(request: Request, phone: str = Form(...), body: str = Form(...), token: str = Form(...), db: Session = Depends(db_session)):
    csrf(request, token)
    if SMS_MODE != "demo":
        raise HTTPException(404)
    b = business_for(request, db)
    if not E164.fullmatch(phone.strip()):
        raise HTTPException(400, "Invalid phone")
    lead = get_or_create_lead(db, b, phone.strip())
    process_inbound_sms(db, b, lead, body[:1600], "")
    db.commit()
    return redirect(f"/leads/{lead.id}")


def process_inbound_sms(db: Session, b: Business, lead: Lead, body: str, provider_sid: str):
    normalized = body.strip().upper()
    if normalized in {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}:
        lead.opted_out = True
        lead.sms_consent = False
    elif normalized in {"START", "UNSTOP"}:
        lead.opted_out = False
        # START clears provider opt-out; don't assume consent to unrelated review marketing.
    log_message(db, b, lead, "inbound", body, provider_sid=provider_sid)


@app.post("/webhooks/twilio/voice")
async def twilio_voice(request: Request, db: Session = Depends(db_session)):
    form = dict(await request.form())
    verify_twilio(request, form)
    b = inbound_business(db, form.get("To", ""))
    caller = form.get("From", "")
    sid = form.get("CallSid", "")
    if not E164.fullmatch(caller):
        raise HTTPException(400, "Invalid caller")
    if sid and db.scalar(select(Event).where(Event.provider_sid == sid)):
        return Response('<Response><Say>Please leave a message after the tone.</Say><Record maxLength="90" playBeep="true" /></Response>', media_type="application/xml")
    lead = get_or_create_lead(db, b, caller)
    log_message(db, b, lead, "inbound", "Call forwarded to Lead Rescue", "call", "received", sid)
    if sid:
        db.add(Event(business_id=b.id, provider_sid=sid, kind="call"))
    if b.auto_reply_enabled and lead.sms_consent and not lead.opted_out:
        send_sms(db, b, lead, b.welcome_text)
    db.commit()
    return Response('<Response><Say>Sorry we missed your call. Please leave a message after the tone.</Say><Record maxLength="90" playBeep="true" /></Response>', media_type="application/xml")


@app.post("/webhooks/twilio/sms")
async def twilio_sms(request: Request, db: Session = Depends(db_session)):
    form = dict(await request.form())
    verify_twilio(request, form)
    b = inbound_business(db, form.get("To", ""))
    sender, body, sid = form.get("From", ""), form.get("Body", ""), form.get("MessageSid", "")
    if not E164.fullmatch(sender):
        raise HTTPException(400, "Invalid sender")
    if not sid:
        raise HTTPException(400, "Missing message ID")
    if not db.scalar(select(Event).where(Event.provider_sid == sid)):
        lead = get_or_create_lead(db, b, sender)
        process_inbound_sms(db, b, lead, body[:1600], sid)
        db.add(Event(business_id=b.id, provider_sid=sid, kind="sms"))
        db.commit()
    return Response("<Response></Response>", media_type="application/xml")
