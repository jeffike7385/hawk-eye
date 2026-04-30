"""FastAPI application factory."""

from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from hawk_scan.web.config import get_settings
from hawk_scan.web.db import Base
from hawk_scan.web.routes import scans as scans_module
from hawk_scan.web.routes import auth as auth_router


def create_app(testing: bool = False, db_engine=None) -> FastAPI:
    app = FastAPI(title="Hawk Scan", version="0.1.0")

    if db_engine is None:
        settings = get_settings()
        # Replace async driver with sync for SQLAlchemy sync sessions.
        url = settings.database_url.replace("+asyncpg", "")
        db_engine = create_engine(url)

    Base.metadata.create_all(db_engine)

    factory = sessionmaker(bind=db_engine)

    # Expose session factory on app state so tests can seed data.
    app.state.session_factory = factory

    def get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[scans_module._get_db] = get_db
    app.include_router(scans_module.router)
    app.include_router(auth_router.router)
    if testing:
        app.state._testing = True

    return app
