FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install dependencies
COPY license_server/requirements.txt ./license_server/requirements.txt
RUN pip install --no-cache-dir -r license_server/requirements.txt

# Copy source
COPY license_server/ ./license_server/
COPY backend/version.py ./backend/version.py

EXPOSE 8787

CMD ["uvicorn", "license_server.app:app", "--host", "0.0.0.0", "--port", "8787"]
