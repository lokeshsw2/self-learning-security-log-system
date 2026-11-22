"""The UI's learning run: background thread, shared engine lock, budget, stop."""
import threading
import time

from logparser.web import App
from tests.test_engine import SSH, feed, make
from tests.test_harness import GOOD, FakeClient


def app_for(eng, client):
    app = App.__new__(App)
    app.eng, app.ch, app.lock, app.streams = eng, None, threading.RLock(), {}
    app.learn_run, app.learn_client, app.last_audit = None, client, None
    return app


def wait(app):
    for _ in range(200):
        if not app.learn_status()["run"]["running"]:
            return app.learn_status()
        time.sleep(0.02)
    raise AssertionError("run did not finish")


def test_learn_run_saves_and_reports(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    key = eng.store.queue_items("needs-parser")[0]["key"]
    app = app_for(eng, FakeClient([{"tool": "save_parser", "input": {"rule": GOOD, "labels": {}}}]))
    assert app.learn_status()["waiting"]["parser-gen"] == 1
    app.learn_start(["parser-gen"], 5, 1.0)
    st = wait(app)
    run = st["run"]
    assert run["error"] is None and run["summary"]["parser-gen"] == {"items": 1, "saved": 1, "flagged": 0}
    assert run["results"][0]["key"] == key and run["spent_usd"] > 0
    assert st["waiting"]["parser-gen"] == 0


def test_learn_stop_leaves_items_open(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    app = app_for(eng, FakeClient([]))
    app.learn_start(["parser-gen"], 5, 1.0)
    app.learn_stop()
    st = wait(app)
    assert st["run"]["error"] is None
    assert st["waiting"]["parser-gen"] + len(eng.store.queue_items("needs-parser", status="flagged")) == 1
