import pathlib
import re

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from BlueTeam.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


connect_args = {}

if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False


engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def init_db() -> None:
    """Create the database directory (if needed) and initialize all tables.

    Safe to call repeatedly — uses create_all(checkfirst=True) so existing
    tables and their data are never dropped or modified.

    All ORM models must be imported before this function is called so that
    SQLAlchemy's mapper registry knows about them.
    """
    if settings.database_url.startswith("sqlite"):
        # Extract the file path from the URL, e.g. sqlite:///./data/db.sqlite
        match = re.match(r"sqlite:///(.+)", settings.database_url)
        if match:
            db_path = pathlib.Path(match.group(1))
            db_path.parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)
