import importlib
import os
from pathlib import Path
from fastapi.testclient import TestClient


def test_demo_flow(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'test.sqlite3'))
    monkeypatch.setenv('APP_SECRET', 's' * 48)
    monkeypatch.setenv('ADMIN_EMAIL', 'admin@example.com')
    monkeypatch.setenv('ADMIN_PASSWORD', 'a-strong-demo-password')
    monkeypatch.setenv('SMS_MODE', 'demo')
    import app.main as main
    importlib.reload(main)
    with TestClient(main.app) as client:
        assert client.get('/health').json()['mode'] == 'demo'
        assert client.get('/').status_code == 401
        r = client.post('/login', data={'email':'admin@example.com','password':'a-strong-demo-password'}, follow_redirects=False)
        assert r.status_code == 303
        assert 'Good to see you' in client.get('/').text
        with main.SessionFactory() as db:
            user = db.scalar(main.select(main.User).where(main.User.email == 'admin@example.com'))
            assert user
        token = client.cookies.get('session')
        assert token
        # CSRF required
        assert client.post('/leads/new', data={'phone':'+13215550123','token':'wrong'}).status_code == 403
        # Token is rendered into authenticated page
        import re
        token = re.search('name="token" value="([^"]+)"',client.get('/').text).group(1)
        r = client.post('/leads/new', data={'token':token,'phone':'+13215550123','name':'Taylor','service':'HVAC'}, follow_redirects=False)
        assert r.status_code == 303
        detail = r.headers['location']
        assert 'Taylor' in client.get(detail).text
        assert client.post('/webhooks/twilio/sms', data={'To':'+13215550123'}).status_code == 403
        # No SMS without consent
        assert client.post(detail+'/send', data={'token':token,'body':'Test'}).status_code == 400
        r = client.post(detail+'/consent', data={'token':token,'consent':'yes','consent_note':'Customer opted in on website 2026-11-09'},follow_redirects=False)
        assert r.status_code == 303
        assert client.post(detail+'/send', data={'token':token,'body':'Hello'},follow_redirects=False).status_code == 303
        assert 'demo-only' in client.get(detail).text
        assert client.post('/demo/inbound',data={'token':token,'phone':'+13215550123','body':'STOP'},follow_redirects=False).status_code == 303
        assert client.post(detail+'/send', data={'token':token,'body':'Hello again'}).status_code == 400
