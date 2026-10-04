# Eltanin human surface

Run `python3 tools/build_site.py` with mdBook **0.5.2** installed. The deployable
artifact is `build/site`; its docs are rendered from the existing product-owned
Markdown, not a separately maintained copy. Marketing text preserves the E1/E2/E3
security-model distinction. No analytics or executable product runtime is added.

Shared safety checker: `horonomy/.github` merge
`30c7840859dd12db752b54894451657c7d00be1f`, `scripts/public_surface.py`.
`tools/public_surface.sha256` pins its bytes; update only from an independently
reviewed upstream revision. Build checks its checksum before executing it.

## Activation gate and deployment

HORO-1702 targets `eltanin.horonom.com` with same-host `/docs/`, avoiding an
unnecessary nested docs certificate. Current preparation does not activate DNS or
publish a new host: resolve the experimental/public-preview release-reconciler
contract with the product owner first. Preserve experimental maturity and the
unearned E3 device-enforcement gate; no website can grant MVP READY.

After approval and merge, inspect real Cloudflare state, reuse the existing Pages
pattern, deploy `build/site` to a free static Pages project, then attach only the
approved marketing hostname. No SaaS/API/runtime DNS is warranted. Verify external
DNS, TLS, canonical homepage/docs, plaintext robots, XML sitemap, CSP, redirects,
links and desktop/mobile navigation before activating the canonical Registry entry.
Do not expose origin URLs in site content. Rollback to the last verified artifact;
retain the checker and intentional publication disposition.
