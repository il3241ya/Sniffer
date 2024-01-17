FROM python:3.8

WORKDIR /app

COPY src/ ./src
COPY sniffer.py .

CMD ["python", "sniffer.py"]
