from logparser.envfile import load_env


def test_env_file_fills_missing_keys_only(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text('# comment\nexport A_KEY="abc"\nEMPTY=\nB_KEY=from-file\n')
    monkeypatch.delenv("A_KEY", raising=False)
    monkeypatch.delenv("EMPTY", raising=False)
    monkeypatch.setenv("B_KEY", "from-shell")
    assert load_env(str(f)) == ["A_KEY"]
    import os
    assert os.environ["A_KEY"] == "abc" and os.environ["B_KEY"] == "from-shell" and "EMPTY" not in os.environ
