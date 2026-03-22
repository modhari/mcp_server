FROM python:3.11-slim

WORKDIR /app

COPY . .

ENV PYTHONPATH=/app/src

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["python", "main.py"]
