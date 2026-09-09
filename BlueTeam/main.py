from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from BlueTeam.database.database import init_db
from BlueTeam.database.models import event as _event_model  # noqa: F401 – registers ORM model
from BlueTeam.api.routes import health, events, websocket, dashboard, alerts, incidents


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["Health"])
app.include_router(events.router, tags=["Events"])
app.include_router(websocket.router, tags=["WebSocket"])
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(alerts.router, tags=["Alerts"])
app.include_router(incidents.router, tags=["Incidents"])
