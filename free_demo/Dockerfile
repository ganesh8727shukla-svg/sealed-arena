FROM python:3.12-slim

WORKDIR /app
COPY broker/ ./broker/
COPY blue/ ./blue/
COPY dashboard/ ./dashboard/
COPY dashboard_addon/server.py ./dashboard_addon/server.py
COPY llm/ ./llm/
COPY red/ ./red/
COPY bayora/ ./bayora/
COPY free_demo/ ./free_demo/
COPY schema.sql legacy_events.json ./
RUN pip install --no-cache-dir -r broker/requirements.txt \
    && mkdir -p /data \
    && chown -R 10001:10001 /app /data

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 10000
CMD ["python", "-u", "free_demo/supervisor.py"]
