import json

from logparser import review
from logparser.harness import corrections_text
from logparser.tools import Tools
from tests.test_engine import SSH, feed, make

P = {"kind": "regex", "pattern": r"^Failed password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"}
M = {"class": "authentication", "constants": {"activity_id": 1, "status_id": 1, "service.name": "sshd"},
     "fields": [{"to": "user.name", "from": "user", "confidence": "high", "note": "user after 'for'"}]}


def test_human_correction_replaces_rule_replays_and_is_shown_to_the_agent(tmp_path):
    eng = make(tmp_path)
    feed(eng, tmp_path, SSH)
    sig = eng.store.queue_items("needs-parser")[0]["key"]
    t = Tools(eng, "agent")
    t.save_parser(sig, P)
    t.save_mapping(sig, M)                       # schema-valid, but a failed password is not a Success
    assert f"mapping:{sig}" in [p["rule_id"] for p in review.pending(eng.store)]
    fixed = json.loads(json.dumps(M))
    fixed["constants"]["status_id"] = 2
    out = review.correct(eng, f"mapping:{sig}", fixed, "a failed password is status Failure, not Success", "ana")
    assert out["version"] == 2 and out["replay"]["parsed"] == 8
    assert all(json.loads(r["ocsf"])["status"] == "Failure" for r in eng.store.q("SELECT ocsf FROM events"))
    assert f"mapping:{sig}" not in [p["rule_id"] for p in review.pending(eng.store)]
    text = corrections_text(eng.store, "ocsf-mapping")
    assert "status Failure, not Success" in text and f"mapping:{sig}" in text
