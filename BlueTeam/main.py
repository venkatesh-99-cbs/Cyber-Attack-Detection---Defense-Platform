from contextlib import asynccontextmanager

from fastapi import FastAPI

from BlueTeam.database.database import init_db
from BlueTeam.database.models import event as _event_model  # noqa: F401 – registers ORM model
from BlueTeam.api.routes import health, events


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    init_db()
    yield


app = FastAPI(
    title="CyberSentinel Blue Team API",
    description="Security event ingestion and defense platform.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(health.router, tags=["Health"])
app.include_router(events.router, tags=["Events"])
