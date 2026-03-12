<!--
SPDX-FileCopyrightText: 2026 Zygmunt Krynicki
SPDX-License-Identifier: LGPL-3.0-only
-->

# NSS snapd module MVP

This repository contains a minimal NSS passwd module that resolves one
synthetic identity from the `SNAP\_USER` environment variable.

## Behavior

The module exports the NSS passwd entrypoints for service name snapd.

Expected input:
- `SNAP_USER` with format `uid:name`

Optional inputs:
- `SNAP_REAL_HOME` used for `pw_dir`
- `SHELL` used for `pw_shell`

Fallbacks when optional inputs are missing:
- `pw_dir` -> `/nonexistent`
- `pw_shell` -> `/bin/false`

Lookup behavior:
- If requested name or uid matches `SNAP_USER`, return a synthetic passwd
  entry.
- If `SNAP_USER` is missing, malformed, or does not match, return `NOTFOUND` so
  the NSS chain can continue with other providers.
- Enumeration is intentionally unsupported in this MVP; `getpwent` returns
  `NOTFOUND`.

## Build

Run:

```sh
make
```

Build output:

- `libnss_snapd.so.2`

Symbol export policy:

- The linker script `nss_snapd.map` is used so only NSS entrypoints are exported.

## Test

Run all checks:

```
make check
```

This validates:
- Shared object builds
- Required exported NSS symbols
- Unit tests for success, mismatch, malformed input, missing env vars, and ERANGE

## Integration Test

Spread and image-garden integration tests are defined in:

- `spread.yaml`
- `.image-garden.mk`
- `tests/`

Run a smoke test on one Ubuntu release:

```sh
spread -v -artifacts=spread-artifacts garden:ubuntu-cloud-24.04
```

Run the full configured matrix:

```sh
spread -v -artifacts=spread-artifacts
```

This stores fetched spread logs under `spread-artifacts/` in the project
directory. 

## Integrate in a base

Typical steps when integrating into a base image:

1. Install the shared object in the base library directory, for example:
   - `/lib/x86\_64-linux-gnu/libnss\_snapd.so.2`
2. Add snapd to the passwd nsswitch line in the base configuration:
   - `passwd: files snapd`

The exact path can vary by architecture and base.
