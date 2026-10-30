from pathlib import Path

from alembic import command
from alembic.config import Config

from reconix_api.services import findings

ALEMBIC_INI = Path(__file__).parents[2] / "alembic.ini"


def test_migrations_keep_the_apps_loggers_on(capsys):
    """alembic/env.py sets up logging from alembic.ini. Python's default switches off every
    logger made before it, so after migrations in the same process (the integration tests,
    or the app) warnings such as "the AI memory is down" were silently lost."""
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))

    command.upgrade(config, "head", sql=True)  # offline: runs env.py, prints SQL, no database

    assert not findings.logger.disabled
