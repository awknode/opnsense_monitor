FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    requests \
    urllib3 \
    flask \
    ollama \
    psutil \
    dotenv \
    slack_sdk
COPY monitor.py /app/monitor.py
CMD ["python", "-u", "/app/monitor.py"]

#FROM python:3.11-slim
#WORKDIR /app
#RUN pip install requests
#COPY monitor.py .
#CMD ["python", "monitor.py"]
