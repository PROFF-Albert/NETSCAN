from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import DATABASE_URL as CONFIG_DATABASE_URL

ROOT = Path(__file__).resolve().parents[1]
DATABASE_URL = CONFIG_DATABASE_URL

# Resolve the documented relative SQLite URL from the project root rather than
# from whichever directory happened to launch Uvicorn.
if DATABASE_URL.startswith("sqlite:///"):
    database_path = DATABASE_URL.removeprefix("sqlite:///")
    if not Path(database_path).is_absolute():
        DB_PATH = ROOT / database_path
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
