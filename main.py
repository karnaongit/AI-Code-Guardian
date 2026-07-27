from fastapi import FastAPI

from api.analysis import router as analysis_router
from api.github import router as github_router
from api.security import router as security_router

app = FastAPI(
    title="AI Code Guardian",
    version="1.0.0"
)

app.include_router(github_router)
app.include_router(analysis_router)
app.include_router(security_router)


@app.get("/")
def home():
    return {
        "message": "AI Code Guardian API",
        "status": "running"
    }