"""Gunicorn entry point. Database initialization is idempotent."""
from app import app, startup
startup()
application = app
