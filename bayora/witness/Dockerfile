FROM python:3.12-slim
WORKDIR /app
COPY audit.py ./audit.py
COPY witness/server.py ./server.py
COPY start.py ./
RUN mkdir -p /data && chown 10001:10001 /data
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WITNESS_DB_PATH=/data/witness.sqlite3
EXPOSE 8100
CMD ["python", "-u", "start.py", "server.py"]
