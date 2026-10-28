FROM python:3.12-slim

WORKDIR /app

COPY client.py server.py scenarios.py ./

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001

EXPOSE 8003
CMD ["python", "-u", "server.py"]
