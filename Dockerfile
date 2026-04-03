FROM python:3.11-slim

WORKDIR /app

# No external dependencies - stdlib only
COPY relay_remote_client.py .

CMD ["python3", "-u", "relay_remote_client.py"]
