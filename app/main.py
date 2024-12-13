from fastapi import FastAPI, HTTPException, Depends
from app.core.config import settings

from app.middleware.cors import add_cors_middleware
from app.utils.logger import setup_logging
from app.api.router import router

app = FastAPI()

def include_router(app):
    app.include_router(
        router,
        prefix="/api/canvas",
        tags=["User Backend"],
    )

def start_application():
    app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)
    setup_logging()
    add_cors_middleware(app)
    include_router(app)
    return app

app = start_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)