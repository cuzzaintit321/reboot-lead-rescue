FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
RUN mkdir -p /app/data && useradd -r -u 10001 app && chown -R app:app /app/data
USER app
EXPOSE 8135
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8135", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
