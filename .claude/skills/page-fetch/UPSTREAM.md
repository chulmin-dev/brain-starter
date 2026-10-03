# PROVENANCE

- Origin: [fivetaku/insane-search](https://github.com/fivetaku/insane-search), MIT licensed; the original notice is retained in `LICENSE`.
- The engine was copied from v0.4.0 and is now a hard fork, not an automatically synchronized upstream checkout.
- Selected upstream v0.6–v0.8.2 pieces were extracted into this fork: output draining, byte-size validation, bounded retrieval, and session/cookie handling.
- The public template contains synthetic fixtures and offline regression tests, not personal crawl logs or a development journal.
- The Cloudflare active solver and its challenge-type classifier have been removed. The remaining desktop/mobile Playwright templates retain Scrapling-derived Chromium flags and staged-load waiting; their BSD-3-Clause notice is appended to `LICENSE`.
