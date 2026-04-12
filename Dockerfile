FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -m app.cli build-index --input data/677.xml --top25 data/1435.xml --output output/cwe_index.json
EXPOSE 8000
CMD ["python", "run.py"]
