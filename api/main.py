from fastapi import FastAPI
from routes.logs import router as logs_router

app = FastAPI(
    title="Forensics API",
    version="1.0.0",
    description="API for logs"
)

# logs API now
app.include_router(logs_router, prefix="/api/logs")

@app.get("/")
def root():
    return {"status": "running", "routes": ["/api/logs"]}
