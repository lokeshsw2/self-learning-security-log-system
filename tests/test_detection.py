"""Detection repair: agents add header rules for unread lines; the rules are boxed in by
construction (tried only on unread lines of their own shape) and checked by code."""
import json

import pytest

from logparser import detection, registry
from logparser.detect import detect
from logparser.harness import Harness
from logparser.tools import Refused, Tools
from tests.test_engine import feed, make
from tests.test_harness import FakeClient


def read_ok(i):        # read today by the built-in syslog_iso rule
    return f"2026-09-20T14:{i % 60:02d}:01.000001+05:30 pc sshd[{100 + i}]: Accepted password for u{i % 3} from 10.0.0.{i} port 22"


def odd(i):            # gdm writes its program name with a stray bracket: no built-in rule reads it
    return f"2026-09-20T15:{i % 60:02d}:02.000002+05:30 pc gdm-password]: pam_unix(gdm-password:auth): authentication failure; user=u{i % 4}"


def vpc(i):            # a format with no header at all: starts with a digit
    return f"2 1786480617{i:02d} eni-4dc57f03 10.10.2.{i} 194.26.29.77 3306 4444 6 9 6714 1793611663 1793611723 REJECT OK"


GOOD = {"name": "ai_syslog_iso_odd_app", "order": 50, "type": "envelope", "app": ["app"], "test": {
    "kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) "
                                r"(?P<host>[A-Za-z0-9][A-Za-z0-9._\-]*) (?P<app>[^\s:\[\]]+)\]?(?:\[(?P<pid>\d+)\])?: "
                                r"(?P<payload>.*)$"}}
# matches every line that starts with a token: as a fallback it still cannot touch what is read today
BROAD = {"name": "ai_anything", "order": 1, "type": "envelope", "app": [], "test": {
    "kind": "regex", "pattern": r"^(?P<timestamp>\S+) (?P<payload>.*)$"}}
SHAPE = "0-0-0a0:0:0.0+0:0"


LATER = 1795400000.0    # 2026-11-23: the engine clock after every line in these tests (the default test clock is 2026-01-01)


def setup(tmp_path, n_odd=25, extra=()):
    eng = make(tmp_path, group_threshold=50)
    eng.now = LATER
    feed(eng, tmp_path, [read_ok(i) for i in range(30)] + [odd(i) for i in range(n_odd)] + list(extra))
    return eng


def item_of(eng):
    it = eng.store.queue_items(detection.QUEUE)[0]
    return it["key"], it["payload"]


def test_scan_queues_unread_headed_lines_only(tmp_path):
    eng = setup(tmp_path)
    assert detection.scan(eng) == {"sources": 1, "shapes": 1, "queued": 1}
    _, item = item_of(eng)
    assert item["count"] == 25 and item["shape"] == SHAPE and all("gdm-password]" in s for s in item["samples"])
    assert detection.scan(eng)["queued"] == 0                    # queued once


def test_scan_ignores_few_headerless_or_digit_first_lines(tmp_path):
    eng = make(tmp_path, group_threshold=50)
    eng.now = LATER
    feed(eng, tmp_path, [odd(i) for i in range(5)] + [f"free text line number {i} without a header" for i in range(40)]
         + [vpc(i) for i in range(40)])
    assert detection.scan(eng)["queued"] == 0


def test_good_rule_reads_samples_and_changes_nothing_else(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    _, item = item_of(eng)
    res = detection.evaluate(eng, item, GOOD)
    assert res["ok"] and res["regressions"] == 0 and res["target"]["read"] == 25
    assert res["target"]["first"]["header"]["@app"] == "gdm-password"
    assert set(res["relearn_estimate"]) >= {"groups_with_rules", "lines", "stored_events_with_a_class"}


def test_added_rule_is_a_fallback_scoped_to_its_shape(tmp_path):
    """The guarantee a replay of stored lines cannot give: an added rule never reads a line that
    another rule reads (stored or not), nor an unread line of another shape."""
    eng = setup(tmp_path, extra=[vpc(i) for i in range(3)])
    detection.scan(eng)
    _, item = item_of(eng)
    res = detection.evaluate(eng, item, BROAD)                    # order 1, matches everything
    assert res["ok"] and res["regressions"] == 0
    snap = detection._snap_with(eng.snap, detection.scoped(BROAD, item))
    never_stored = "2026-09-21T01:02:03.000004+05:30 other-host sudo[77]: alice : TTY=pts/0 ; COMMAND=/bin/ls"
    assert detect(snap, never_stored).bucket == detect(eng.snap, never_stored).bucket == "syslog_iso>unstructured|sudo"
    assert detect(snap, vpc(9)).chain == ["unstructured"]          # unread, but another shape: not taken
    assert detect(snap, odd(99)).chain[0] == "ai_anything"


@pytest.mark.parametrize("change,why", [
    ({"name": "syslog_iso"}, "start with `ai_`"),
    ({"test": {"kind": "regex", "pattern": "(?P<timestamp>x) (?P<payload>.*)"}}, "anchored"),
    ({"test": {"kind": "regex", "pattern": "^(?P<timestamp>\\S+) .*$"}}, "payload"),
    ({"test": {"kind": "regex", "pattern": "^(?P<x>\\S+) (?P<payload>.*)$"}}, "at least one of"),
    ({"type": "format", "format": "kv"}, "envelope"),
])
def test_static_refusals(tmp_path, change, why):
    eng = setup(tmp_path)
    with pytest.raises(detection.DetectRefused, match=why):
        detection.check_rule(eng, {**GOOD, **change})


def test_timestamp_must_parse(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    _, item = item_of(eng)
    rule = {**GOOD, "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\S+) (?P<host>\S+) (?P<payload>.*)$"}}
    from logparser.detect import shape
    bad = [s.replace("2026-09-20T", "XX-09-20T") for s in item["samples"]]
    item2 = {**item, "samples": bad, "shape": shape(bad[0])}
    res = detection.evaluate(eng, item2, rule)
    assert not res["ok"] and res["target"]["bad_time"]


def test_agents_cannot_overwrite_a_rule_they_did_not_write(tmp_path):
    eng = setup(tmp_path)
    registry.save_rule(eng.store, "detect:ai_by_human", {**GOOD, "name": "ai_by_human"}, {"created_by": "human"})
    with pytest.raises(detection.DetectRefused, match="not written by the detection agent"):
        detection.check_rule(eng, {**GOOD, "name": "ai_by_human"})


def test_save_moves_lines_keeps_counts_and_closes_stale_work(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key, _ = item_of(eng)
    old_groups = {g["signature"] for g in eng.store.groups("source='-|unstructured|-' AND merged_into IS NULL")}
    total_before = sum(g["count"] for g in eng.groups.values() if not g["merged_into"])
    res = Tools(eng, "harness:detection").save_detect(key, GOOD, "stray ] after the program")
    assert res["reprocessed"]["moved"] == 25 and res["reprocessed"]["groups_superseded"] == len(old_groups)
    assert eng.store.q("SELECT COUNT(*) n FROM raw WHERE source='-|unstructured|-'")[0]["n"] == 0
    # counts move with the lines: nothing is counted twice
    assert sum(g["count"] for g in eng.groups.values() if not g["merged_into"]) == total_before
    assert eng._source("-|unstructured|-")["lines"] == 0
    assert eng._source("-|ai_syslog_iso_odd_app>unstructured|gdm-password")["lines"] == 25
    assert all(eng.groups[s]["merged_into"] for s in old_groups)
    assert not [i for i in eng.store.queue_items("longtail") if i["key"] in old_groups]
    assert eng.store.active_rule("detect:ai_syslog_iso_odd_app")["body"]["when_shape"] == [SHAPE]
    # the hot path reads new lines with the rule at once; lines read before are untouched
    feed(eng, tmp_path, [odd(99), read_ok(99)])
    srcs = [r["source"] for r in eng.store.q("SELECT source FROM raw ORDER BY id DESC LIMIT 2")]
    assert sorted(srcs) == ["-|ai_syslog_iso_odd_app>unstructured|gdm-password", "-|syslog_iso>unstructured|sshd"]
    assert eng.store.queue_items(detection.QUEUE) == []


def test_learned_long_tail_rule_is_carried_over_and_now_gets_the_line_time(tmp_path):
    eng = setup(tmp_path)
    sigs = [g["signature"] for g in eng.store.groups("source='-|unstructured|-' AND merged_into IS NULL")]
    for sig in sigs:                                           # what the agents had learned before
        Tools(eng, "t").save_longtail(sig, {"action": "authentication failure"}, "gdm authentication failure")
    eng.store.enqueue(detection.QUEUE, "k", {"source": "-|unstructured|-", "shape": SHAPE, "count": 25,
                                             "samples": [odd(i) for i in range(25)]})
    res = Tools(eng, "harness:detection").save_detect("k", GOOD)
    assert res["carried_over"]["longtail"] == len(sigs) and res["carried_over"]["to_learn_again"] == 0
    rows = eng.store.q("SELECT r.raw, r.status, e.ocsf FROM raw r LEFT JOIN events e ON e.raw_id=r.id "
                       "WHERE r.raw LIKE '%gdm-password]%'")
    assert len(rows) == 25 and all(r["status"] == "parsed" for r in rows)      # nothing to learn again
    ev = json.loads(rows[0]["ocsf"])
    assert ev["metadata"]["original_time"].startswith("2026-09-20T15:")      # the line's own time, from the header


def test_scan_queues_a_shape_again_only_if_lines_are_still_unread(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key, _ = item_of(eng)
    eng.store.queue_done(detection.QUEUE, key)                 # say a rule was saved but did not read them
    assert detection.scan(eng)["queued"] == 1
    eng.store.queue_done(detection.QUEUE, key, "flagged")      # a human was asked: never again by code
    assert detection.scan(eng)["queued"] == 0


def test_harness_detection_role_saves_through_the_gate(tmp_path):
    eng = setup(tmp_path)
    detection.scan(eng)
    key, _ = item_of(eng)
    fake = FakeClient([
        {"tool": "get_samples", "input": {"item": "something-else"}},
        {"tool": "save_detect", "input": {"rule": {**GOOD, "test": {"kind": "regex", "pattern": "(?P<payload>.*)"}}}},
        {"tool": "save_detect", "input": {"rule": GOOD, "note": "stray ]"}},
    ])
    res = Harness(eng, client=fake).run_queue("detection")
    assert res == [{"key": key, "saved": True, "reason": None}]
    first = json.loads(fake.requests[1]["messages"][2]["content"][0]["content"])
    assert first["item"] == key and "scope" in first               # pinned to its own item
    refused = json.loads(fake.requests[2]["messages"][4]["content"][0]["content"])
    assert refused["saved"] is False and "anchored" in refused["refused"]
    assert "Role: detection" in fake.requests[0]["system"]


# --------------------------------------------------------------------- times, zones and shapes
def eu(i):        # day-first dotted date: the engine cannot read it without a format
    return f"22.11.2026 10:{i % 60:02d}:33,{i:03d} mx{i % 3} postfix/smtpd[{300 + i}]: connect from unknown[203.0.113.{i}]"


def ist(i):       # a zone name after the time
    return f"2026-11-22 10:{i % 60:02d}:39 IST db-0{i % 3} mysqld[{400 + i}]: Access denied for user 'u{i % 4}'@'10.0.0.{i}'"


def tod(i):       # a time of day with no date
    return f"10:{i % 60:02d}:52.516 lb-0{i % 3} keepalived: VRRP state change to MASTER on eth{i % 2}"


def pipe(i):      # a header with no spaces; the program name varies in shape
    return f"17953221{i:05d}|edge-fw-0{i % 3}|{('vpnd', 'ikev2d', 'authd')[i % 3]}|session opened for u{i % 4}"


HOST_APP = r"(?P<host>[A-Za-z0-9][A-Za-z0-9._\-]*) (?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?: (?P<payload>.*)$"


def queued(tmp_path, lines, **settings):
    eng = make(tmp_path, group_threshold=50, **settings)
    eng.now = LATER
    feed(eng, tmp_path, lines)
    detection.scan(eng)
    return eng, eng.store.queue_items(detection.QUEUE)


def test_a_matched_time_must_be_captured(tmp_path):
    eng, items = queued(tmp_path, [eu(i) for i in range(25)])
    dropped = {"name": "ai_eu", "order": 50, "type": "envelope", "app": ["app"],
               "test": {"kind": "regex", "pattern": r"^\d\d\.\d\d\.\d{4} \d\d:\d\d:\d\d,\d+ " + HOST_APP}}
    with pytest.raises(detection.DetectRefused, match="start with a time"):
        detection.evaluate(eng, items[0]["payload"], dropped)


def test_time_format_reads_a_day_first_date(tmp_path):
    eng, items = queued(tmp_path, [eu(i) for i in range(25)])
    rule = {"name": "ai_eu", "order": 50, "type": "envelope", "app": ["app"], "time_format": "%d.%m.%Y %H:%M:%S,%f",
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d\.\d\d\.\d{4} \d\d:\d\d:\d\d,\d+) " + HOST_APP}}
    res = detection.evaluate(eng, items[0]["payload"], rule)
    assert res["ok"], res
    h = res["target"]["first"]["header"]
    assert h["@timestamp"].startswith("2026-11-22T10:") and h["@timestamp_raw"].startswith("22.11.2026 ")
    Tools(eng, "harness:detection").save_detect(items[0]["key"], rule)
    feed(eng, tmp_path, [eu(77)])
    det = detect(eng.snap, eu(77))
    assert det.chain[0] == "ai_eu" and det.header["@timestamp"] == "2026-11-22T10:17:33.077000"


@pytest.mark.parametrize("fmt,why", [
    ("%d.%m %H:%M", "four-digit year"), ("%d.%m.%Y %H:%M:%S %Z", "strptime format"), ("%d.%m.%Y", "hour and minute"),
    ("%d.%m.%y %H:%M", "strptime format"), ("%m/%d/%Y %I:%M", "AM/PM"), ("%Y %b %H:%M", "needs the day"),
    ("%Y %H:%M", "month and day"), ("%d %Y %H:%M", "needs the month")])
def test_time_format_is_checked(tmp_path, fmt, why):
    eng = setup(tmp_path)
    rule = {**GOOD, "time_format": fmt}
    with pytest.raises(detection.DetectRefused, match=why):
        detection.check_rule(eng, rule)


def test_a_written_zone_must_be_captured_and_known(tmp_path):
    eng, items = queued(tmp_path, [ist(i) for i in range(25)], tz_names={"IST": "+05:30"})
    item = items[0]["payload"]
    no_tz = {"name": "ai_ist", "order": 50, "type": "envelope", "app": ["app"],
             "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) [A-Z]{2,5} " + HOST_APP}}
    res = detection.evaluate(eng, item, no_tz)
    assert not res["ok"] and "capture it as `tz`" in res["target"]["bad_time"][0]
    with_tz = {**no_tz, "test": {"kind": "regex", "pattern":
                                 r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?P<tz>[A-Z]{2,5}) " + HOST_APP}}
    res = detection.evaluate(eng, item, with_tz)
    assert res["ok"] and res["target"]["first"]["header"]["@timestamp"].endswith(" IST")
    eng.settings.tz_names = {}                                  # a name nobody has defined: a human decides
    res = detection.evaluate(eng, item, with_tz)
    assert not res["ok"] and res["target"]["bad_time"]


def test_time_of_day_gets_the_arrival_date(tmp_path):
    from logparser import transforms
    eng, items = queued(tmp_path, [tod(i) for i in range(25)])
    rule = {"name": "ai_tod", "order": 50, "type": "envelope", "app": ["app"],
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d:\d\d:\d\d(?:\.\d+)?) " + HOST_APP}}
    assert detection.evaluate(eng, items[0]["payload"], rule)["ok"]
    ctx = {"default_tz": "UTC", "now": 1795342000}
    assert transforms.parse_timestamp("T08:05:00", {}, ctx) == 1795334700000 and "date_assumed" in ctx["flags"]
    assert detect(eng.snap, tod(1)).chain == ["unstructured"]          # no rule saved yet: unread
    with pytest.raises(transforms.TransformError):                     # an unmarked 01:30:00 may be a duration
        transforms.parse_timestamp("01:30:00", {}, ctx)


def test_pipe_header_is_one_shape_whatever_the_program(tmp_path):
    eng, items = queued(tmp_path, [pipe(i) for i in range(30)])
    assert len(items) == 1 and items[0]["payload"]["count"] == 30 and items[0]["payload"]["shape"] == "0|"


def test_audit_sees_day_first_dates_and_times_of_day():
    import types
    from logparser import checks
    det = types.SimpleNamespace(header={})
    for text in ("22.11.2026 10:05:33,293 mx2 postfix", "10:09:52.516 lb-03 keepalived: up"):
        assert checks.problems(det, {"_text": text}, {"time": 1}, ["time_from_ingest"], {})


# --------------------------------------------------------------------- review 3 findings
def us(i, day=None):     # month/day order: with every day <= 12 the samples cannot tell
    return f"{(day or (i % 12) + 1):02d}/11/2026 10:{i % 60:02d}:00 hostx app[{i}]: event {i}"


def mdy_rule(fmt):
    return {"name": "ai_mdy", "order": 50, "type": "envelope", "app": ["app"], "time_format": fmt,
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d/\d\d/\d{4} \d\d:\d\d:\d\d) " + HOST_APP}}


def test_day_month_order_must_be_settled_by_the_samples(tmp_path):
    eng, items = queued(tmp_path, [us(i) for i in range(25)])
    res = detection.evaluate(eng, items[0]["payload"], mdy_rule("%d/%m/%Y %H:%M:%S"))
    assert not res["ok"] and "either way round" in res["target"]["ambiguous"]
    item = {**items[0]["payload"], "samples": items[0]["payload"]["samples"] + [us(99, day=23)]}
    assert detection.evaluate(eng, item, mdy_rule("%d/%m/%Y %H:%M:%S"))["ok"]       # day 23: settled


def test_a_time_in_the_future_is_refused(tmp_path):
    eng, items = queued(tmp_path, [eu(i) for i in range(25)])
    rule = {"name": "ai_eu", "order": 50, "type": "envelope", "app": ["app"], "time_format": "%m.%d.%Y %H:%M:%S,%f",
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d\.\d\d\.\d{4} \d\d:\d\d:\d\d,\d+) " + HOST_APP}}
    res = detection.evaluate(eng, items[0]["payload"], rule)       # month 22 does not exist: nothing reads
    assert not res["ok"]
    eng.now = 1767225600.0                                         # clock before the lines: they are "future"
    good = {**rule, "time_format": "%d.%m.%Y %H:%M:%S,%f"}
    res = detection.evaluate(eng, items[0]["payload"], good)
    assert not res["ok"] and "future" in res["target"]["bad_time"][0]


def test_zone_check_ignores_words_and_sees_attached_offsets():
    for after, zone in ((" GET /x", False), (" CRIT disk", False), (" TEST run", False), (" IST db-01", True),
                        ("+0530 host", True), ("Z host", True), (" +05:30 h", True), (" MSK h", True), (" host", False)):
        assert bool(detection.ZONE_AFTER.match(after)) is zone, after


def test_priority_prefix_and_plausible_epochs_in_the_time_guard():
    ctx = {"now": LATER, "default_tz": "UTC"}
    assert detection.leads_with_time("<34>2026-11-22T10:15:03Z host app: x", ctx)
    assert not detection.leads_with_time("1234567890 order shipped", ctx)        # 2009: not near now
    assert detection.leads_with_time("1795322103123|edge|vpnd|x", ctx)
    assert not detection.leads_with_time("2.1.15 started", ctx)


def test_rules_saved_with_the_old_shape_still_apply(tmp_path):
    eng = setup(tmp_path)
    body = {"name": "ai_pipe", "order": 50, "type": "envelope", "app": ["app"], "when_shape": ["0|a-a-0|a|a"],
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{13})\|(?P<host>[\w-]+)\|(?P<app>\w+)\|(?P<payload>.*)$"}}
    registry.save_rule(eng.store, "detect:ai_pipe", body, {"created_by": "harness:detection"})
    eng.reload()
    assert detect(eng.snap, "1795322103123|edge-fw-02|vpnd|x").chain[0] == "ai_pipe"


def test_zone_database_names_work_again_and_durations_are_not_flagged():
    import types
    from logparser import checks, transforms
    assert transforms.parse_timestamp("2026-11-22 10:00:00", {"tz": "CET"}, {}) == 1795338000000
    with pytest.raises(transforms.TransformError, match="human decides"):
        transforms.parse_timestamp("2026-11-22 10:00:00 IST", {}, {})          # not a zone-database name
    det = types.SimpleNamespace(header={})
    assert not checks.problems(det, {"duration": "01:30:00"}, {"time": 1}, ["time_from_ingest"], {})


def test_export_leaves_out_agent_detection_rules_and_says_so(tmp_path):
    from logparser import logstash
    eng = setup(tmp_path)
    registry.save_rule(eng.store, "detect:ai_x", {**GOOD, "name": "ai_x"}, {"created_by": "harness:detection"})
    eng.reload()
    comp = logstash.Compiler(eng)
    text = comp.distributor_filter({}, [])
    assert comp.not_exported == ["ai_x"] and "ai_x" not in text


def test_zone_names_in_lines_are_fixed_offsets_and_bad_dates_refuse(tmp_path):
    from logparser import transforms
    assert transforms.parse_timestamp("2026-07-01 12:00:00 CET", {}, {}) == 1782903600000      # 11:00Z, not 10:00Z
    for bad in ("2026-07-01 12:00:00 GB", "2026-07-01 12:00:00 PRC"):
        with pytest.raises(transforms.TransformError):
            transforms.parse_timestamp(bad, {}, {})
    for bad in ("2026-13-45 10:00:00", "T25:00:00"):
        with pytest.raises(transforms.TransformError, match="not a real date"):
            transforms.parse_timestamp(bad, {}, {"now": LATER})


def test_constant_capital_word_after_the_time_is_refused(tmp_path):
    lines = [f"2026-11-22 10:{i % 60:02d}:39 PKT db-0{i % 3} mysqld[{400 + i}]: login ok" for i in range(25)]
    eng, items = queued(tmp_path, lines)
    rule = {"name": "ai_pkt", "order": 50, "type": "envelope", "app": ["app"],
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) [A-Z]{2,5} " + HOST_APP}}
    res = detection.evaluate(eng, items[0]["payload"], rule)
    assert not res["ok"] and "'PKT'" in res["target"]["bad_time"][-1]


def test_trigger_sees_a_time_after_a_weekday():
    assert detection.HEADED.match("Fri Nov 13 09:50:43 2026 app-09 cupsd: job 39 printed")
    assert detection.HEADED.match("Fri, Nov 13 09:50:43 2026 host x")
    assert not detection.HEADED.match("Friday was fine")


# --------------------------------------------------------------------- one item, several header formats
def us12(i):
    return f"11-{13 + i % 10:02d}-2026 {(i % 12) + 1:02d}:15:0{i % 10} PM app-0{i % 3} sshd[{100 + i}]: Failed password for u{i}"


def att(i):
    return f"2026-11-{13 + i % 10:02d} 09:{i % 60:02d}:31+0530 app-0{i % 3} squid[{200 + i}]: TCP_DENIED/403 10.0.0.{i}"


def pkt(i):
    return f"2026-11-{13 + i % 10:02d} 09:{i % 60:02d}:40 PKT app-0{i % 3} vsftpd[{300 + i}]: FAIL LOGIN: Client 10.0.1.{i}"


R_US = {"name": "ai_us12", "order": 50, "type": "envelope", "app": ["app"], "time_format": "%m-%d-%Y %I:%M:%S %p",
        "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d-\d\d-\d{4} \d\d:\d\d:\d\d [AP]M) " + HOST_APP}}
R_ATT = {"name": "ai_att", "order": 50, "type": "envelope", "app": ["app"], "time_format": "%Y-%m-%d %H:%M:%S%z",
         "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[+-]\d{4}) " + HOST_APP}}
R_PKT = {"name": "ai_pkt", "order": 50, "type": "envelope", "app": ["app"],
         "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (?P<tz>[A-Z]{2,5}) " + HOST_APP}}


def mixed(tmp_path):
    lines = [f(i) for i in range(20) for f in (us12, att, pkt)]
    eng, items = queued(tmp_path, lines)
    assert len(items) == 1 and items[0]["payload"]["shape"] == "0-0-0"      # three formats, one item
    return eng, items[0]["key"], items[0]["payload"]


def test_one_rule_per_format_in_a_mixed_item(tmp_path):
    eng, key, item = mixed(tmp_path)
    res = detection.evaluate(eng, item, R_US)
    assert res["ok"] and res["target"]["read"] == res["target"]["matched"] and res["target"]["remaining"] > 0
    out = Tools(eng, "harness:detection").save_detect(key, R_US)
    assert out["remaining"] > 0 and "next" in out
    item2 = eng.store.queue_items(detection.QUEUE)[0]["payload"]
    assert item2["rules_saved"] == ["detect:ai_us12"] and not any(" PM " in s or " AM " in s for s in item2["samples"])
    out = Tools(eng, "harness:detection").save_detect(key, R_ATT)
    left = eng.store.queue_items(detection.QUEUE)[0]["payload"]["samples"]
    assert out["remaining"] == len(left) and all(" PKT " in s for s in left)
    with pytest.raises(Refused, match="human decides"):                    # PKT is in no table: flag it
        Tools(eng, "harness:detection").save_detect(key, R_PKT)
    t = detect(eng.snap, us12(3)).header["@timestamp"]
    assert t.startswith("2026-11-16T16:15")                                # 04 PM -> 16h, month first


def test_a_rule_must_read_enough_and_everything_it_matches(tmp_path):
    eng, key, item = mixed(tmp_path)
    narrow = {**R_US, "test": {"kind": "regex", "pattern": r"^(?P<timestamp>11-13-2026 \d\d:\d\d:\d\d [AP]M) " + HOST_APP}}
    res = detection.evaluate(eng, item, narrow)
    assert not res["ok"] and res["target"]["read"] < 5
    both = {**R_ATT, "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\S* \S+ " + HOST_APP}}
    res = detection.evaluate(eng, item, {**both, "time_format": None} if False else {k: v for k, v in both.items() if k != "time_format"})
    assert not res["ok"] and res["target"]["bad"] > 0                       # matches PKT/+0530 lines but drops their zone


def test_harness_writes_several_rules_then_flags_the_rest(tmp_path):
    eng, key, item = mixed(tmp_path)
    fake = FakeClient([
        {"tool": "save_detect", "input": {"rule": R_US}},
        {"tool": "save_detect", "input": {"rule": R_ATT}},
        {"text": "FLAG: PKT is not a zone the deployment defines; a human decides"},
    ])
    res = Harness(eng, client=fake).run_queue("detection")
    assert res == [{"key": key, "saved": True, "reason": None}]
    it = eng.store.q("SELECT status, payload FROM queue WHERE name=? AND key=?", (detection.QUEUE, key))[0]
    assert it["status"] == "flagged" and "PKT" in json.loads(it["payload"])["flag_reason"]
    assert detection.scan(eng)["queued"] == 0                              # flagged: nobody pays to ask again
    assert len(fake.requests) == 3


# --------------------------------------------------------------------- review 5
def test_am_pm_left_out_of_the_time_is_refused(tmp_path):
    eng, key, item = mixed(tmp_path)
    no_p = {**R_US, "time_format": "%m-%d-%Y %H:%M:%S",
            "test": {"kind": "regex", "pattern": r"^(?P<timestamp>\d\d-\d\d-\d{4} \d\d:\d\d:\d\d) [AP]M " + HOST_APP}}
    res = detection.evaluate(eng, item, no_p)
    assert not res["ok"] and "AM/PM" in res["target"]["bad_time"][0]


def test_a_pattern_naming_a_host_is_refused(tmp_path):
    eng, key, item = mixed(tmp_path)
    narrow = {**R_US, "test": {"kind": "regex", "pattern":
                               r"^(?P<timestamp>\d\d-\d\d-\d{4} \d\d:\d\d:\d\d [AP]M) (?P<host>app-01) (?P<app>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?: (?P<payload>.*)$"}}
    res = detection.evaluate(eng, item, narrow)
    assert not res["ok"] and any("names a host" in b for b in res["target"]["bad_time"])


def test_samples_show_a_minority_layout(tmp_path):
    lines = [att(i) for i in range(60)] + [pkt(i) for i in range(2)]      # PKT is 2 of 62 lines
    eng, items = queued(tmp_path, lines)
    assert any(" PKT " in s for s in items[0]["payload"]["samples"])
