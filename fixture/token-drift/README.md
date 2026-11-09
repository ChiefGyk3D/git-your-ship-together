Fixtures for `token-drift.yml` (called from `.github/workflows/ci.yml`).

- `ok/`: a vendored file that matches its pin. The source is not contacted.
- `live/`: a copy of this repository's `LICENSE`, pinned to a real commit; the live check fetches the source and agrees.
- `planted-pin/`: the vendored file was edited after it was pinned. Must drift.
- `planted-live/`: the vendored file matches its lock, but the lock no longer equals the source. Must drift.

The planted ones run with `advisory: true`, so their jobs are green by design, and `token-drift-control` fails unless both
reported `drifted=true`.
