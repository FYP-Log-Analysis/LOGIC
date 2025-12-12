FROM python:3.11-slim

WORKDIR /app

COPY api/ api/
COPY data/ data/

RUN pip install fastapi uvicorn

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "5000"]