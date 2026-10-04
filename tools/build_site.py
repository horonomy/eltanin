#!/usr/bin/env python3
"""Render product-owned evaluation docs and check the deployable static artifact."""
from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parent.parent
BASE = 'https://eltanin.horonom.com/'
DOCS = {
    'quickstart': ('Authorization quickstart', 'docs/product/QUICKSTART.md'),
    'security-model': ('Security boundary', 'docs/product/SECURITY_MODEL.md'),
    'policy-examples': ('Policy examples', 'docs/product/POLICY_EXAMPLES.md'),
    'cli-contract': ('CLI contract', 'docs/product/CLI_CONTRACT.md'),
    'apple-fixture': ('Apple Silicon functional fixture', 'docs/product/APPLE_SILICON_FIXTURE.md'),
    'north-star': ('North Star', 'docs/product/NORTH_STAR.md'),
}


class InlineScripts(HTMLParser):
    """CSP hashes cover only generated inline script bodies, never arbitrary hosts."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.inline = False
        self.body: list[str] = []
        self.hashes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == 'script':
            self.inline = 'src' not in dict(attrs)
            self.body = []

    def handle_data(self, data: str) -> None:
        if self.inline:
            self.body.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == 'script' and self.inline:
            digest = hashlib.sha256(''.join(self.body).encode()).digest()
            self.hashes.add("'sha256-" + base64.b64encode(digest).decode() + "'")
            self.inline = False


def main() -> None:
    expected = (ROOT / 'tools/public_surface.sha256').read_text().split()[0]
    actual = hashlib.sha256((ROOT / 'tools/public_surface.py').read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError('Shared checker differs from its reviewed checksum')
    build = ROOT / 'build'
    build.mkdir(exist_ok=True)
    source = build / 'book-src'
    output = build / 'site'
    # Only these owned generated directories are replaced; product sources stay untouched.
    for target in (source, output):
        if target.exists():
            shutil.rmtree(target)
        target.mkdir()
    shutil.copyfile(ROOT / 'site/evaluation.md', source / 'index.md')
    summary = ['# Summary', '', '- [Evaluate Eltanin](index.md)']
    for slug, (title, original) in DOCS.items():
        source_url = 'https://github.com/horonomy/eltanin/blob/main/' + original
        text = (ROOT / original).read_text()
        # mdBook chapters keep the canonical source's contextual repository links.
        text = re.sub(r'(?<!!)\[([^\]]+)\]\(([^\s)]+)\)',
                      lambda match: f'[{match[1]}]({urljoin(source_url, match[2])})'
                      if not match[2].startswith('#') else match[0], text)
        (source / f'{slug}.md').write_text(text)
        summary.append(f'- [{title}]({slug}.md)')
    (source / 'SUMMARY.md').write_text('\n'.join(summary) + '\n')
    subprocess.run(['mdbook', 'build', 'site'], cwd=ROOT, check=True)
    for name in ('index.html', 'style.css'):
        shutil.copyfile(ROOT / 'site' / name, output / name)
    scripts = InlineScripts()
    locations = []
    for page in sorted(output.rglob('*.html')):
        text = page.read_text()
        if page.name == '404.html':
            text = text.replace('</head>', '<meta name="robots" content="noindex"></head>')
        else:
            relative = page.relative_to(output).as_posix()
            relative = relative[:-10] if relative.endswith('index.html') else relative
            url = BASE + relative
            if page.parent != output:
                text = text.replace('</head>', f'<link rel="canonical" href="{url}"></head>')
            locations.append(url)
        scripts.feed(text)
        page.write_text(text)
    hashes = ' '.join(sorted(scripts.hashes))
    (output / '_headers').write_text(
        "/*\n  Content-Security-Policy: default-src 'self'; script-src 'self' " + hashes +
        "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'\n"
        "  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n"
    )
    (output / 'robots.txt').write_text('User-agent: *\nAllow: /\nSitemap: ' + BASE + 'sitemap.xml\n')
    (output / 'sitemap.xml').write_text(
        '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
        ''.join(f'<url><loc>{url}</loc></url>' for url in locations) + '</urlset>\n'
    )
    subprocess.run(['python3', 'tools/public_surface.py', 'public-surface.json', str(output)],
                   cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
