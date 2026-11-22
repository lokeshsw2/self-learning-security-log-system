"""Phase 5 comparison helpers (the Logstash runs are covered by the deploy checks)."""
from logparser import compare


def test_sample_spans_every_file(tmp_path):
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("".join(f"a{i}\n" for i in range(1000)))
    b.write_text("".join(f"b{i}\n" for i in range(10)))
    s = compare.sample_lines([str(a), str(b)], 20)
    assert len(s) == 20 and any(x.startswith("b") for x in s) and any(x.startswith("a9") for x in s)


def test_leaves_count_mapped_attributes_not_unmapped():
    ev = {"class_uid": 1, "src_endpoint": {"ip": "1.2.3.4", "port": 2}, "unmapped": {"x": 1, "y": 2},
          "metadata": {"version": "1"}, "observables": [{"name": "a"}, {"name": "b"}], "empty": ""}
    assert compare._leaves(ev) == 5


def test_cost_per_group_reads_the_call_log(tmp_path):
    from tests.test_engine import make
    e = make(tmp_path)
    for agent, target, d in (("harness:ls-direct", "g1", "iteration 1, stop tool_use, m, $0.0400"),
                             ("harness:ls-direct", "g1", "iteration 2, stop end_turn, m, $0.0100"),
                             ("harness:ocsf-mapping", "g1", "iteration 1, m, $0.5"),
                             ("harness:ls-direct", "g2", "no price")):
        e.store.log_tool(agent, "model_call", target, True, d, 0, 0)
    assert compare.cost_per_group(e.store, ("ls-direct",)) == {"g1": 0.05}
    assert compare.cost_per_group(e.store, ("parser-gen", "ocsf-mapping")) == {"g1": 0.5}
