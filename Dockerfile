FROM python:3.12-slim

LABEL org.opencontainers.image.title="haotian-miguan (好甜的蜜罐) go2rtc honeypot"
LABEL org.opencontainers.image.description="Deception honeypot impersonating an unpatched go2rtc 1.8.5 to catch config-file attackers. Nothing attacker-supplied is ever executed."

WORKDIR /app

COPY honeypot.py report.py dashboard.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# /data keeps evidence; world-writable so bind mounts work with any UID
RUN mkdir -p /data && chmod 777 /data

# unprivileged runtime, no capabilities needed: 1984/8554 are high ports
USER 65534:65534

EXPOSE 1984 8554

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:1984/api',timeout=3)"]

CMD ["python3", "honeypot.py", "--host", "0.0.0.0", "--data-dir", "/data"]
