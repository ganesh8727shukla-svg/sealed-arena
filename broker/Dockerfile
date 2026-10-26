FROM python:3.12-slim

WORKDIR /app

COPY server.py .
COPY database.py contracts.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001

CMD ["python", "server.py"]
