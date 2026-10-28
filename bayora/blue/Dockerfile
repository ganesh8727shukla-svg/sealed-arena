FROM python:3.12-slim
WORKDIR /app
COPY server.py logic.py ./
COPY private/defense-plan.json ./private/defense-plan.json
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8100
CMD ["python", "-u", "server.py"]
