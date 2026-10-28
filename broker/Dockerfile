FROM python:3.12-slim

WORKDIR /app

COPY broker/server.py broker/database.py broker/contracts.py broker/requirements.txt ./
COPY schema.sql legacy_events.json ./
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001

CMD ["python", "server.py"]
