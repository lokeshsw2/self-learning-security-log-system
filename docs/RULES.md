# Rule language reference

Rules are JSON data. The engine validates every rule against a schema, compiles
patterns on RE2 and stores each save as a new version. Rules cannot contain code.

Patterns are RE2: no backreferences, no lookahead or lookbehind. Named groups are
written `(?P<name>...)`.

## Parser rule

A parser turns the **payload** of a record into a flat dict of fields. The payload
is what is left after envelopes (syslog header, Cisco tag) are stripped; the tool
`test-parser` shows `payload_of_first_sample`. Envelope fields are added
automatically with an `@` prefix: `@timestamp`, `@host`, `@app`, `@pid`, `@pri`,
`@level`, `@cisco_severity`, `@cisco_mnemonic`, `@msgid`.

```json
{"kind": "regex",
 "pattern": "^Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<src_ip>\\S+) port (?P<src_port>\\d+) ssh2$"}
```

- `regex`: must start with `^` and end with `$`. Group names are the field names:
  letters, digits, underscore, not starting with underscore. Use an optional group
  for parts that are only sometimes there. Capture the values; keep the fixed
  words as literals so the pattern stays specific to this event.
- `json`, `cef`, `leef`, `xml`: no options needed. JSON and XML are flattened to
  dotted keys (`userIdentity.arn`, `a.0.b` for arrays). CEF gives `cef.vendor`,
  `cef.product`, `cef.signature_id`, `cef.name`, `cef.severity` plus the extension
  keys; `cs1Label=Foo cs1=bar` also gives `label.Foo = bar`.
- `kv`: `{"kind": "kv", "dialect": "kv_eq"}`. Dialects: `kv_eq` (`k=v`, `k="v"`),
  `kv_colon` (`k:"v";`), `kv_pipe` (`k=v|k=v`), `kv_span` (values with spaces that
  run to the next key). Text outside the pairs is kept as `_text`.
- `delimited`: `{"kind": "delimited", "delimiter": ",", "columns": ["a", "b", ...]}`.
  The number of columns must equal the number of fields in every line. Empty
  values are dropped.
- Optional on any kind:
  - `nested`: `[{"field": "msg", "kind": "kv", "dialect": "kv_eq", "prefix": "msg."}]`
    decodes a field that itself holds JSON or key=value text.
  - `extract`: `[{"field": "msg", "pattern": "user (?P<user>\\S+) from (?P<src_ip>\\S+)"}]`
    runs a pattern on one field and adds its named groups.

Save gate: 100% of the samples must parse, at least 98% of the other stored lines
of the group must parse, and every extracted value must appear literally in the
raw line.

## Mapping rule

```json
{"class": "authentication",
 "profiles": [],
 "constants": {"activity_id": 1, "status_id": 2, "severity_id": 1,
               "service.name": "sshd", "metadata.product.name": "OpenSSH",
               "metadata.product.vendor_name": "OpenBSD"},
 "fields": [
   {"to": "user.name", "from": "user", "confidence": "high", "note": "name after 'for'"},
   {"to": "src_endpoint.ip", "from": "src_ip", "confidence": "high", "note": "address after 'from'"},
   {"to": "src_endpoint.port", "from": "src_port", "confidence": "high", "note": "client port"},
   {"to": "time", "from": "@timestamp", "transform": {"fn": "parse_timestamp"},
    "confidence": "medium", "note": "syslog header time; no year or zone in the source"},
   {"to": "status_id", "from": "result",
    "transform": {"fn": "enum_lookup", "args": {"map": {"success": 1, "failure": 2}, "default": 0}},
    "confidence": "high", "note": "vendor result word"}
 ],
 "unmapped": "rest"}
```

- `class`: an OCSF class name (`authentication`) or uid. Use `base_event` when no
  class fits.
- `constants`: fixed values by OCSF path.
- `fields`: each entry sets one OCSF path (`to`) from a parsed field (`from`, a
  name or a list of names where the first non-empty one wins) or from a fixed
  `value`. Every entry needs `confidence` (`high`, `medium`, `low`) and a short
  `note` saying why this field means that attribute.
- `join`: with a list in `from`, joins all listed fields in order with this
  separator instead of taking the first, for example
  `{"to": "time", "from": ["date", "time"], "join": " ", "transform": {"fn": "parse_timestamp"}}`.
  The entry is skipped unless every listed field is present.
- `when`: makes an entry conditional: `{"field": "action", "equals": "deny"}`,
  `{"field": "x", "in": ["a", "b"]}`, `{"field": "x", "matches": "^10\\."}`,
  `{"field": "x", "exists": true}`.
- Array positions are written `attacks[0].tactic.name`. A scalar sent to an array
  attribute is wrapped in a list automatically.
- `extends`: full id of another mapping rule to build on, for example
  `mapping:base-zeek-net` (base first, this rule overrides entries with the same
  `to`; an entry with a `when` is added beside the base entry, it does not
  replace it). `exclude`: list of `to` paths to drop from the base.
- `switch`: chooses the class per line. Each entry names a saved base mapping
  to use instead of this rule when its condition holds; the first match wins and
  lines that match none use this rule:
  `"switch": [{"when": {"field": "user", "exists": true}, "use": "mapping:base-pam-auth"}]`.
  Save the targets first with `save-mapping --base NAME`.
- `drop`: parsed field names that must not be copied to `unmapped`, for secrets
  such as a logged password.
- `profiles`: OCSF profiles this mapping uses, for example `["cloud"]` or
  `["host"]` or `["security_control"]`. An attribute that belongs to a profile is
  refused unless the profile is listed.
- `unmapped`: `rest` (default) puts every parsed field that no entry consumed
  into the OCSF `unmapped` object. Do not invent homes for fields.

Filled by code, do not map: `class_uid`, `category_uid`, `type_uid`,
`metadata.version`, the caption siblings (`activity_name`, `status`, `severity`,
`class_name`, ...). `activity_id` and `severity_id` default to 0 (Unknown).
`time` falls back to the envelope `@timestamp`, then to ingest time. Values are
cast to the schema type (string to integer and so on) when the cast is exact.

Do not set `tz` in `parse_timestamp`: a time without a zone is read in the deployment's time
zone, which the engine works out from the zoned timestamps it sees. The gate refuses a hard-coded
zone.

Meaning checks, also in the gate: the mapped `time` must be within an hour of every zoned
timestamp in the line (header or field), and must not fall back to the ingest time when the line
has a timestamp (set `"time_from_ingest_ok": true` only for sources that log no time at all). A
field such as `action`, `result` or `status` that holds a block or failure word needs an outcome in
the event (`status_id`, `action_id` or `disposition_id`) that does not say the opposite.

Save gate: the class and every `to` path must exist in OCSF 1.10.0, every entry
needs confidence and note, every sample must give a schema-valid event with no
transform errors, and at least 98% of the other stored lines must too.

### Transforms (the whole library)

A `transform` is one step or a list of steps: `{"fn": name, "args": {...}}`.

| fn | args | effect |
|---|---|---|
| `parse_timestamp` | `formats` (strptime list), `tz`, `unit` (s, ms, us, ns), `year` | any common text or epoch time to epoch milliseconds |
| `to_int` | `base` (10, 16, "auto") | integer |
| `to_float` | | number |
| `to_bool` | | true/false/yes/no/1/0 |
| `to_str` | | string |
| `enum_lookup` | `map` (optional), `default`, `patterns` (regex to value), `case_insensitive` (default true) | value lookup; no match and no default drops the field |
| `lower`, `upper` | | case |
| `trim` | `chars` | strip characters |
| `regex_extract` | `pattern`, `group` | first match of a pattern |
| `split_index` | `sep`, `index` | one part of a split |
| `split` | `sep` | list of parts |
| `null_if` | `values` | drop the field when it equals one of the values, for example `["-", "N/A"]` |
| `scale` | `factor`, `int` | multiply (seconds to milliseconds: 1000) |
| `prefix` | `prefix`, `suffix` | add fixed text |
| `windows_filetime` | | Windows FILETIME (18 digits, 100-ns ticks since 1601) to epoch milliseconds |
| `dns_name` | | Windows DNS debug-log name `(3)www(7)example(3)com(0)` to `www.example.com` |
| `syslog_severity` | `from_pri` | syslog PRI or severity 0-7 to OCSF `severity_id` |

## Mask rule (unstructured sources)

```json
{"mode": "extend",
 "patterns": [{"name": "node", "pattern": "\\bR\\d\\d-M\\d-N[0-9A-F]-[A-Z]:J\\d\\d-U\\d\\d\\b", "placeholder": "<NODE>"}]}
```

Patterns run in order before the default masks (`extend`) or instead of them
(`replace`). `placeholder` is `<UPPERCASE>`. `group` selects a capture group to
mask instead of the whole match. The tool sets the scope to the source.

## Sign rule (structured sources)

```json
{"keys": "core", "core_keys": ["src", "dst", "action"], "discriminators": ["type", "subtype"]}
```

- `discriminators`: field names whose values split a source into event types.
  For delimited data without a header use column names `c0`, `c1`, ...
- `keys`: `auto` (key set is ignored when a discriminator is present), `all`,
  `core` (only `core_keys` count), `none`.
- `depth`: how deep JSON keys count (default 1).

Save gate for both: on a quarantined source the signature count must drop to at
most half and under the cap; on a healthy source the rule must not trip the
explosion guard.

## Split rule (one group)

```json
{"presence": ["user"], "fields": ["event_type"]}
```

Splits one group into pieces by whether a parsed field is present and/or by the
value of a parsed field (at most 3 fields, 4 presence keys). Only that group
changes; every piece becomes its own group with the parent's parser and starts
with the parent's mapping.

Save gate: at least 2 and at most 30 pieces, no more than half as many pieces
as lines (otherwise the field is a variable, not an event type), the source
stays under its signature cap, and a group can be regrouped at most 3 times.

## Long-tail extraction

`{"fields": {"user": "root", "src_ip": "10.0.0.1"}, "summary": "one line"}`.
Allowed fields: `timestamp`, `host`, `user`, `src_ip`, `dst_ip`, `action`,
`outcome`, `severity`. Code drops every value that is not literally in the line.
