FROM python:3.12-slim
WORKDIR /app
COPY controller/server.py controller/page.html ./
COPY audit.py ./
COPY start.py ./
RUN mkdir -p /data && chown 10001:10001 /data
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 BAYORA_DB_PATH=/data/bayora.sqlite3
EXPOSE 8083
CMD ["python", "-u", "start.py", "server.py"]
