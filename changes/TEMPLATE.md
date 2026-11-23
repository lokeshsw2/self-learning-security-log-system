# <short title of the change>

<!-- Save as changes/<machine>-<YYYYMMDD>-<short-topic>.md, e.g. changes/gra-20261124-sasl-kafka.md.
     No secrets: passwords, keys and tokens stay in the environment and appear here only as ${NAME}. -->

- **From:** <machine: gra | dev> · commit <`git rev-parse --short HEAD` before the change>
- **Touches:** core | edge (config, adapters, scripts) | docs
- **Files:** <list>

## Why

<The problem seen. Paste the error or one example log line (shortened, no secrets or personal data).>

## What changed

<What the change does, in a few sentences. Anything the other machine must also set (config, env, version).>

## Patch

```diff
<output of: git diff   (or: git diff <base-commit>..HEAD)>
```

## Tested

<Commands run and their result, e.g. `LP_SKIP_LOGSTASH=1 pytest -q` -> 213 passed; what was checked on real data.>

## Still to check

<Anything not verified, or questions for the other side.>
