FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV CONFIG_PATH=/app/config.yaml
ENV LOG_LEVEL=INFO

EXPOSE 8080

CMD ["python", "-m", "src.main"]
