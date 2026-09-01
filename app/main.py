from fastapi import FastAPI

app = FastAPI(title="Tamper-Evident Audit Log Service")


@app.get("/")
def read_root():
    return {"service": "audit-log-service", "status": "running"}
