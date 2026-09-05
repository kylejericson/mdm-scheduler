import os
import tempfile

import pytest

# The app reads its config at import time, so the environment has to be set first.
DATA_DIR = tempfile.mkdtemp(prefix="mdm-scheduler-tests-")
os.environ.update(
    DATA_DIR=DATA_DIR,
    SECRET_KEY="test-secret-key",
    ADMIN_PASSWORD="test-password",
    TZ="America/Chicago",
)

from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

from . import mock_iru, mock_jamf  # noqa: E402


@pytest.fixture(scope="session")
def jamf():
    base_url, server = mock_jamf.start()
    yield base_url
    server.shutdown()


@pytest.fixture(scope="session")
def iru():
    base_url, server = mock_iru.start()
    yield base_url
    server.shutdown()


@pytest.fixture(scope="session")
def _app_client():
    """One TestClient for the whole session.

    Entering the context manager runs the app's lifespan, which starts the
    scheduler. APScheduler cannot be restarted once shut down, so the lifespan
    must run exactly once - per-test isolation comes from clean_state below.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client(_app_client):
    _app_client.cookies.clear()
    return _app_client


@pytest.fixture(autouse=True)
def clean_state():
    """Fresh database, scheduler and fake-Jamf state for every test."""
    from app import scheduler as sched

    mock_jamf.reset()
    mock_iru.reset()
    sched.scheduler.remove_all_jobs()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def auth(client):
    resp = client.post("/login", data={"password": "test-password"}, follow_redirects=False)
    assert resp.status_code == 303
    return client


@pytest.fixture
def instance(auth, jamf):
    resp = auth.post(
        "/instances",
        data={
            "name": "Mock Jamf",
            "base_url": jamf,
            "auth_type": "client",
            "client_id": "abc",
            "client_secret": "shhh",
            "verify_ssl": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    return 1


@pytest.fixture
def iru_instance(auth, iru):
    """An Iru instance, created after the Jamf one so it lands at id 2."""
    resp = auth.post(
        "/instances",
        data={
            "name": "Mock Iru",
            "vendor": "iru",
            "base_url": iru,
            "api_token": mock_iru.TOKEN,
            "verify_ssl": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    from app.database import session_scope
    from app.models import Instance

    with session_scope() as session:
        return session.query(Instance).filter_by(vendor="iru").one().id
