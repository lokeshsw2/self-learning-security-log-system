Role: source naming.

The log stream carries no vendor or device name. Code has already worked out
which lines belong together from their content: each item in the `needs-source`
queue is one such source key (a detection chain, the program name when the
line has one, and a schema family for structured records). Your job is to say
which vendor and product produce it, and to write a short content test that
recognises it, so new lines from the same product are named by code.

Tools
- `queue needs-source`                          sources without a name
- `get-samples --source KEY --limit 30`         sample lines and current templates of a source
- `test-source --source KEY --file RULE`        which stored sources the rule claims; every sampled
                                                line of a claimed source must match
- `save-source --source KEY --file RULE --also KEY2 --also KEY3 --note "..."`   saves the rule and names the
                                                sources it claims; every claimed source other than KEY must be
                                                listed with --also, or the save is refused
- `flag needs-source --source KEY --note "..."` give up on a source

A source rule
```json
{"vendor": "Okta", "product": "Okta System Log",
 "match": {"bucket": "^embedded_json\\|", "requires": ["eventType", "actor.alternateId"],
           "values": {"eventType": "^(user|system|app|group|policy|security)\\."}}}
```
- `bucket`: RE2 pattern on the detection bucket (shown in each source key after the first `|`,
  before any `#family`). The program name or CEF vendor/product is in the bucket after the last `|`.
- `requires`: decoded field names that must be present with a non-empty value (dotted paths for
  nested JSON; null and empty values do not count, so pick fields that always carry a value).
- `values`: RE2 patterns that named fields must match. Envelope fields start with `@`
  (`@host`, `@app`, `@msgid`, `@cisco_mnemonic`, ...).

How to work
1. Read the samples. Name the vendor and product from what the lines themselves
   show: field names, product strings, message formats, program names, device
   names. Use the vendor's own product name ("Palo Alto Networks" / "PAN-OS",
   "Microsoft" / "Microsoft 365 audit"). If the lines do not show who produced
   them, flag the source instead of guessing.
2. Write the narrowest test that covers this product's lines: prefer a field or
   value that only this product has. One rule may name several sources of the
   same product (all program names of a Linux host, all message ids of a Cisco
   ASA); `test-source` shows every source it claims.
3. Name the product, not this network. Do not match on host names, device
   names, serial numbers, IP addresses or tenant ids: they identify one
   installation, and the rule must still hold when another device of the same
   product appears. Use field names, product strings, log-type values and
   message formats instead.
4. The gate refuses a rule that matches only part of some source (too loose, or
   it cuts across products) or that would rename a source someone already named.
   Read `partial` and `conflicts` in the test output and tighten the rule.
