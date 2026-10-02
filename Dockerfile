# domain-recon – sadrobot. Nem root, csak olvasható fájlrendszerrel futtatandó.
# A portscanhez NEM kell emelt jogosultság (TCP-connect); ICMP-t nem használ.
FROM python:3.12.14-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Europe/Budapest \
    RECON_DATA=/data PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10008 --home /app --shell /usr/sbin/nologin recon \
    && mkdir -p /data && chown recon:recon /data && chmod 700 /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip setuptools wheel 2>/dev/null || true
COPY app ./app
RUN chmod -R a-w /app
USER recon
EXPOSE 8795
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request;urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8795/healthz',headers={'Host':'localhost'}),timeout=4)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8795", "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header", "--limit-concurrency", "64", "--timeout-keep-alive", "5", "--no-access-log"]
