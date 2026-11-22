"""A warm Logstash for testing Variant B filters: started once, reloaded per test (about 2-4 s instead of a
JVM start). One test at a time.

  sandbox.conf  http input (JSON records: id, payload, header) -> prelude -> the candidate filter
                -> file output (one JSON line per event, the run id in the file name)
  Reload success or failure comes from the Logstash API (/_node/stats/pipelines/sandbox); a failure's
  message (a config error) goes back to the agent.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.request
import uuid

from .logstash import rb
from .logstash_rb import RUBY_LIB

BREW = "/opt/homebrew/Cellar/logstash"
# Logstash substitutes ${VAR} from its environment: the sandbox gets only what a JVM needs, no secrets
ENV_KEEP = ("PATH", "HOME", "JAVA_HOME", "LS_JAVA_HOME", "TMPDIR", "LANG", "LC_ALL", "USER")


def caps_for(schema, cname: str) -> dict:
    """Caption table of a class (enum value -> caption of its sibling), as Variant A ships it."""
    attrs = schema.cls(cname)["attributes"]
    d = {}
    for k, a in attrs.items():
        if a.get("enum") and a.get("sibling") and a["sibling"] in attrs:
            d[k] = {"sibling": a["sibling"], "enum": {kk: v.get("caption") for kk, v in a["enum"].items()}}
    return {cname: d}


def tables_for(schema, cname: str) -> dict:
    """What LP.fin reads as `T`: {"CAPS": {class: caption table}}."""
    return {"CAPS": caps_for(schema, cname)}


_ERR = re.compile(r'error: "((?:[^"\\]|\\.)*)"|Ruby exception occurred: ([^{]+)')


class Sandbox:
    def __init__(self, workdir: str, http_port: int = 18080, api_port: int = 9611, heap: str = "1g",
                 logstash: str = "/opt/homebrew/bin/logstash"):
        self.dir = os.path.abspath(workdir)
        self.http_port, self.api_port, self.heap, self.bin = http_port, api_port, heap, logstash
        self.proc = None
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- process
    def _api(self, path: str) -> dict:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.api_port}{path}", timeout=5) as r:
            return json.loads(r.read())

    def _stats(self) -> dict:
        try:
            p = self._api("/_node/stats/pipelines/sandbox")["pipelines"]["sandbox"]
            return p.get("reloads") or {}
        except Exception:
            return {}

    def running(self) -> bool:
        try:
            self._api("/")
            return True
        except Exception:
            return False

    def start(self, timeout: float = 120.0) -> None:
        if self.running():
            if not self._ours():
                raise RuntimeError(f"another Logstash answers on API port {self.api_port}; stop it or use other ports")
            return
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, "lp_lib.rb"), "w") as fh:
            fh.write(RUBY_LIB)
        with open(os.path.join(self.dir, "logstash.yml"), "w") as fh:
            fh.write(f'path.data: "{self.dir}/data"\npath.logs: "{self.dir}/logs"\nconfig.reload.automatic: true\n'
                     f'config.reload.interval: 1s\napi.enabled: true\napi.http.host: "127.0.0.1"\n'
                     f'api.http.port: {self.api_port}\n')
        with open(os.path.join(self.dir, "pipelines.yml"), "w") as fh:
            fh.write(f'- pipeline.id: sandbox\n  path.config: "{self.dir}/sandbox.conf"\n  pipeline.workers: 1\n')
        self._write_conf("", "{}", "idle")
        for name in ("jvm.options", "log4j2.properties"):
            for ver in sorted(os.listdir(BREW)) if os.path.isdir(BREW) else []:
                src = os.path.join(BREW, ver, "libexec", "config", name)
                if os.path.exists(src):
                    txt = open(src).read()
                    if name == "jvm.options":
                        txt = re.sub(r"(?m)^-Xms\S+", f"-Xms{self.heap}", txt)
                        txt = re.sub(r"(?m)^-Xmx\S+", f"-Xmx{self.heap}", txt)
                    with open(os.path.join(self.dir, name), "w") as fh:
                        fh.write(txt)
        log = open(os.path.join(self.dir, "stdout.log"), "w")
        env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
        self.proc = subprocess.Popen([self.bin, "--path.settings", self.dir], stdout=log, stderr=subprocess.STDOUT,
                                     start_new_session=True, env=env)
        with open(os.path.join(self.dir, "sandbox.pid"), "w") as fh:
            fh.write(str(self.proc.pid))
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self._pipeline_up():
                return
            if self.proc.poll() is not None:
                raise RuntimeError(f"sandbox Logstash exited; see {self.dir}/stdout.log")
            time.sleep(1)
        self.stop()
        raise RuntimeError("sandbox Logstash did not start in time")

    def _ours(self) -> bool:
        """Is the Logstash on our API port the one this sandbox started (its pid file, a live process)?"""
        try:
            os.kill(int(open(os.path.join(self.dir, "sandbox.pid")).read()), 0)
            return True
        except (OSError, ValueError):
            return False

    def _pipeline_up(self) -> bool:
        try:
            return "sandbox" in self._api("/_node/pipelines").get("pipelines", {})
        except Exception:
            return False

    def stop(self) -> None:
        if self.proc is None and os.path.exists(os.path.join(self.dir, "sandbox.pid")):
            try:                                    # started by another process (e.g. an earlier run)
                os.killpg(int(open(os.path.join(self.dir, "sandbox.pid")).read()), signal.SIGTERM)
            except Exception:
                pass
        if self.proc is not None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=60)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    pass
            self.proc = None

    def _logfile(self) -> str:
        return os.path.join(self.dir, "logs", "logstash-plain.log")

    def _log_size(self) -> int:
        try:
            return os.path.getsize(self._logfile())
        except OSError:
            return 0

    def _log_error(self, since: int) -> str | None:
        """The newest pipeline or ruby error Logstash logged after `since` (the reason a reload failed or a
        line raised), e.g. 'pattern %{NOSUCHPATTERN:x} not defined'."""
        try:
            with open(self._logfile(), "rb") as fh:
                fh.seek(since)
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            return None
        found = plugin = None
        for line in text.splitlines():
            # a plugin's own complaint ("Unknown setting 'x' for csv") says more than the generic reload error
            m = re.search(r"\]\[ERROR\]\[logstash\.(?:filters|codecs|config)[^\]]*\]\s*(?:\[[^\]]*\]\s*)*(.+)$", line)
            if m and plugin is None:
                plugin = m.group(1).strip()
            if "ERROR" in line:
                m = _ERR.search(line)
                if m:
                    found = (m.group(1) or m.group(2) or "").strip()
        if plugin and (found is None or "Something is wrong" in found or "Could not execute" in found):
            return plugin
        return found

    # ---------------------------------------------------------------- one test
    def _write_conf(self, filter_text: str, tables_json: str, run_id: str, tz: str = "UTC") -> str:
        out = os.path.join(self.dir, f"out_{run_id}.jsonl")
        tables = os.path.join(self.dir, f"tables_{run_id}.json")
        with open(tables, "w") as fh:
            fh.write(tables_json)
        init = (f'require "{self.dir}/lp_lib.rb"\nLP.tz = {rb(tz)}\n'
                f'T_sb = JSON.parse(File.read("{tables}"))\n')
        conf = (f'input {{ http {{ host => "127.0.0.1" port => {self.http_port} codec => json }} }}\n'
                "filter {\n"
                f"  ruby {{ init => '{init}' code => 'nil' }}\n"
                '  mutate { rename => { "payload" => "[@metadata][s][payload]" "h" => "[@metadata][s][h]" } }\n'
                f"{filter_text}\n"
                '  mutate { copy => { "[@metadata][s][f]" => "[sb][f]" "[@metadata][s][t]" => "[sb][t]" } }\n'
                '  mutate { remove_field => ["headers", "host", "url", "user_agent", "http"] }\n'
                "}\n"
                f'output {{ file {{ path => "{out}" codec => json_lines }} }}\n'
                f"# run {run_id}\n")
        tmp = os.path.join(self.dir, ".sandbox.conf.tmp")
        with open(tmp, "w") as fh:
            fh.write(conf)
        os.replace(tmp, os.path.join(self.dir, "sandbox.conf"))
        return out

    def run(self, filter_text: str, records: list, tables: dict, tz: str = "UTC", timeout: float = 60.0) -> dict:
        """Load the filter, send the records ({id, payload, h}), return {"events": {id: event}} or
        {"error": reload error}. `tables` are the caption tables (`T_sb`)."""
        with self.lock, self._file_lock():
            run_id = uuid.uuid4().hex[:10]
            try:
                return self._run(filter_text, records, tables, tz, timeout, run_id)
            finally:
                for p in (os.path.join(self.dir, f"out_{run_id}.jsonl"), os.path.join(self.dir, f"tables_{run_id}.json")):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    @contextlib.contextmanager
    def _file_lock(self):
        """One test at a time across processes too (they share the ports and sandbox.conf)."""
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, ".lock"), "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _run(self, filter_text, records, tables, tz, timeout, run_id) -> dict:
        if True:        # (indentation kept from the locked block)
            self.start()
            before = self._stats()
            since = self._log_size()
            out = self._write_conf(filter_text, json.dumps(tables), run_id, tz)
            t0 = time.time()
            while time.time() - t0 < 40:
                now = self._stats()
                if now.get("failures", 0) > before.get("failures", 0):
                    err = (now.get("last_error") or {}).get("message", "reload failed")
                    return {"error": (self._log_error(since) or str(err))[:1500]}
                if now.get("successes", 0) > before.get("successes", 0):
                    break
                time.sleep(0.3)
            else:
                return {"error": "the sandbox did not reload the filter in time"}
            body = json.dumps(records).encode()
            for attempt in range(20):           # the input comes back up a moment after the reload
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{self.http_port}/", data=body,
                                                 headers={"Content-Type": "application/json"}, method="POST")
                    urllib.request.urlopen(req, timeout=10).read()
                    break
                except Exception:
                    time.sleep(0.3)
            else:
                return {"error": "the sandbox input did not accept the records"}
            events, last, t0 = {}, -1, time.time()
            while time.time() - t0 < timeout:
                if os.path.exists(out):
                    with open(out) as fh:
                        for line in fh:
                            try:
                                ev = json.loads(line)
                            except ValueError:
                                continue
                            if "id" in ev:
                                events[ev["id"]] = ev
                if len(events) >= len(records):
                    break
                if len(events) == last and time.time() - t0 > 8:
                    break
                last = len(events)
                time.sleep(0.3)
            if any("_rubyexception" in (e.get("tags") or []) for e in events.values()):
                err = self._log_error(since)
                if err:
                    return {"events": events, "ruby_error": err[:500]}
            return {"events": events}
