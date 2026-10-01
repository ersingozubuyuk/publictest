import base64
import importlib

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_core import _adv  # noqa: E402

CSV = ("hostname,os,version,kernel,architecture,platform\n"
       "LPAR001,SLES,15 SP6,6.4.0-150600.23.25-default,ppc64le,IBM Power\n")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("KERNELASSESS_DATA", str(tmp_path))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    from kernelassess.web import app as app_module
    app_module = importlib.reload(app_module)
    app_module.state.indexes["15"] = {"source": "test", "advisories": [
        _adv(1, "150600.23.25.1", "2024-10-09", ["CVE-2024-1"]),
        _adv(2, "150600.23.30.1", "2024-12-13", ["CVE-2024-2"]),
    ]}
    app_module.state.status = "ready"
    # No `with` block: startup (which downloads SUSE data) does not run.
    return TestClient(app_module.app)


def _auth(pw="s3cret"):
    return {"Authorization": "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()}


def test_requires_auth(client):
    assert client.get("/").status_code == 401
    assert client.get("/", headers=_auth("wrong")).status_code == 401
    assert client.get("/healthz").status_code == 200


def test_upload_and_browse(client):
    r = client.post("/assess", headers=_auth(), files={"file": ("inv.csv", CSV, "text/csv")},
                    data={"date": "2026-10-01"}, follow_redirects=False)
    assert r.status_code == 303 and "run=" in r.headers["location"]
    run_id = r.headers["location"].split("run=")[1]

    page = client.get(f"/?run={run_id}", headers=_auth())
    assert page.status_code == 200 and "HOST-0001" in page.text and "LPAR001" in page.text

    host = client.get(f"/runs/{run_id}/hosts/HOST-0001", headers=_auth())
    assert host.status_code == 200 and "CVE-2024-2" in host.text

    js = client.get(f"/runs/{run_id}/hosts/HOST-0001.json", headers=_auth())
    assert js.status_code == 200 and "LPAR001" not in js.text


def test_rejects_path_traversal(client):
    assert client.get("/runs/..%2F..%2Fetc/hosts/HOST-0001", headers=_auth()).status_code == 404
