FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY relay_remote_client.py .
COPY index.html .

CMD ["python3", "-u", "relay_remote_client.py"]
