FROM python:3.11-slim

WORKDIR /app

# Install system packages required for psycopg2
RUN apt-get update && apt-get install -y build-essential libpq-dev

# Copy and install Python dependencies
COPY ../api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the API code
COPY ../api .

# Start FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
