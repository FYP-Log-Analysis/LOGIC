FROM python:3.11-slim

WORKDIR /app

# Install dependencies — copy both requirement files for full coverage
COPY requirements.txt ./requirements.txt
COPY api/requirements.txt ./api/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r api/requirements.txt

# Copy the entire project so all pipeline scripts are available
COPY . .

EXPOSE 4000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "4000", "--workers", "2", "--timeout-keep-alive", "75"]
