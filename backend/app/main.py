from fastapi import FastAPI

app = FastAPI(title="SAVEMit")


@app.get("/health")
def health():
    return {
        "status": "ok"
    }