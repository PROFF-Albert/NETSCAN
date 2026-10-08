from logging.config import fileConfig
from pathlib import Path
import sys
from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic executes this file with ``alembic/`` on sys.path, not necessarily
# the project root. Add the root explicitly so `alembic upgrade head` works
# from the documented project directory and from an installed console script.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.database import Base, DATABASE_URL
from backend import models  # noqa: F401: registers all metadata

config = context.config
config.set_main_option("sqlalchemy.url", DATABASE_URL)
if config.config_file_name: fileConfig(config.config_file_name)
target_metadata = Base.metadata

def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction(): context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction(): context.run_migrations()

if context.is_offline_mode(): run_migrations_offline()
else: run_migrations_online()
