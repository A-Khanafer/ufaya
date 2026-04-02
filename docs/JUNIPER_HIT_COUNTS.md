# Juniper SRX Hit Counts

This note explains how UFAYA collects Juniper SRX policy hit counts, why the parser broke, and what to update if Junos changes the operational XML again.

## Important distinction

Hit counts do not come from the configuration XML.

They come from the operational command:

```text
show security policies hit-count | display xml | no-more
```

UFAYA uses the configuration XML only to build the rule list and policy contexts. The hit-count command provides the per-policy counters that are merged into those parsed rules.

## Where the live flow lives

The Juniper live hit-count path is implemented in:

- `src/ufaya/drivers/juniper/driver.py`

The main methods are:

- `_fetch_live_data()`
  - Runs the live operational hit-count command.
  - Runs the configuration command.
  - Returns config XML plus a hit-count lookup.
- `_parse_hit_count_lookup()`
  - Parses structured XML hit-count responses.
- `_extract_hit_count_entry()`
  - Maps one parsed XML entry into UFAYA's internal lookup key.
- `_parse_hit_count_text()`
  - Fallback for table-style CLI output wrapped in XML `<output>` blocks or returned as plain text.

## Root cause of the bug

The original parser only handled older tag names such as:

- `policy-information`
- `policy-name`
- `from-zone`
- `to-zone`
- `policy-count`

Your device returned a different operational XML shape, for example:

- `multi-routing-engine-results`
- `multi-routing-engine-item`
- `policy-hit-count`
- `policy-hit-count-entry`
- `policy-hit-count-policy-name`
- `policy-hit-count-from-zone`
- `policy-hit-count-to-zone`
- `policy-hit-count-count`

Because those tags were not recognized, UFAYA built an empty hit-count lookup.

That caused two visible symptoms:

- every exported rule had `hit_count: null`
- `hit_counts_collected_at` was omitted, because UFAYA only writes that timestamp when it successfully parses a live hit-count snapshot

Zero values like `0` are valid hit counts and must stay numeric. They must not be treated as missing data.

## What is supported now

The parser currently supports:

- older structured XML with `policy-information` / `policy-count`
- newer structured XML with `policy-hit-count-entry` / `policy-hit-count-count`
- multi-routing-engine wrappers around those entries
- CLI table output parsed from `<output>` blocks when structured XML is not present

Junos namespace URIs can change by release. That is not usually a problem because `xml_helpers.py` strips XML namespaces before tag comparisons.

## What to update if Junos changes again

When hit counts disappear again, start with a fresh sample of the exact live command output from the affected device:

```text
show security policies hit-count | display xml | no-more
```

Then compare that output to the parser in `src/ufaya/drivers/juniper/driver.py`.

### 1. Check the wrapper tags

Update `_parse_hit_count_lookup()` if Junos introduces a new container around entries.

Things to look for:

- a new entry element instead of `policy-hit-count-entry`
- a different top-level container instead of `policy-hit-count`
- additional cluster or logical-system wrappers

The `candidates = [...]` section is the first place to update.

### 2. Check the field names

Update `_extract_hit_count_entry()` if the policy fields are renamed.

The fields UFAYA needs are:

- policy name
- from zone
- to zone
- count

If Junos renames any of those tags, add the new names to the `_first_text(...)` calls in `_extract_hit_count_entry()`.

### 3. Check the parsed/not-parsed detection

`hit_counts_collected_at` is only written when the driver decides the hit-count snapshot was successfully parsed.

If the XML contains valid data but UFAYA still omits the timestamp, update the `parsed = bool(...)` detection in `_parse_hit_count_lookup()` so the new schema counts as a successful parse.

### 4. Check text-style output

If the device does not return structured entry XML and instead returns a table in an `<output>` element or raw text, update `_parse_hit_count_text()`.

Things to review there:

- header detection
- row parsing regex
- handling of `Logical system:` / cluster node banners
- how global policies are identified

### 5. Add a regression test

Always add the new device shape to:

- `tests/test_juniper_srx.py`

Recommended pattern:

- add a small fixture helper that contains the exact XML shape
- add one regression test that proves:
  - the live hit-count command is called
  - `hit_counts_collected_at` is present
  - a real zero count stays `0`
  - counts are assigned to the correct policy contexts

## Current regression coverage

The current tests include:

- an older `policy-information` shape
- a multi-routing-engine `policy-hit-count-entry` shape
- failure cases where the hit-count command errors or returns unusable XML

## Practical debugging checklist

If a future device shows `hit_count: null` again:

1. Confirm the driver is running in live mode, not file mode.
2. Capture the exact output of `show security policies hit-count | display xml | no-more`.
3. Compare the actual tags to `_parse_hit_count_lookup()` and `_extract_hit_count_entry()`.
4. Check whether the output is structured XML or only table text.
5. Add a regression fixture before changing the parser.

## Files most likely to change

- `src/ufaya/drivers/juniper/driver.py`
- `tests/test_juniper_srx.py`

Those are the first files to inspect when Junos changes the hit-count output format.
