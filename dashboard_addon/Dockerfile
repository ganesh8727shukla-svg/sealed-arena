FROM python:3.12-slim

WORKDIR /app
COPY --chown=10001:10001 server.py .

USER 10001:10001
EXPOSE 8082
CMD ["python", "-u", "server.py"]
