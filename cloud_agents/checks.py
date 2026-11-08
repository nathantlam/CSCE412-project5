"""Deterministic evidence. An LLM's conclusions never determine the pass flag."""
from __future__ import annotations
import hashlib
import socket
import ssl
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
import dns.resolver
import requests
from .core import ROOT, now

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.assets, self.nav_links = [], [], []
        self.nav_depth = 0
        self.has_viewport = False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'nav':
            self.nav_depth += 1
        if tag == 'a' and 'href' in attrs:
            self.links.append(attrs['href'])
            if self.nav_depth:
                self.nav_links.append(attrs['href'])
        if tag in ('img', 'script') and 'src' in attrs:
            self.assets.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.assets.append(attrs.get('href', ''))
        if tag == 'meta' and attrs.get('name') == 'viewport':
            self.has_viewport = True
    def handle_endtag(self, tag):
        if tag == 'nav':
            self.nav_depth = max(0, self.nav_depth-1)

def inspect_website(config):
    site = (ROOT/config['website_directory']).resolve()
    files = []
    problems = []
    for path in sorted(site.rglob('*')):
        if not path.is_file():
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(site):
            raise ValueError('Symlinks and escaped website paths are forbidden')
        relative = path.relative_to(site).as_posix()
        if path.suffix.lower() not in {'.html', '.css', '.js', '.svg', '.png', '.jpg', '.jpeg', '.webp', '.ico', '.txt'}:
            raise ValueError('Unsupported website file: '+relative)
        if path.stat().st_size > 10_000_000:
            raise ValueError('Website file exceeds 10 MB limit')
        files.append({'key': relative, 'bytes': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    if not files or len(files) > 200:
        raise ValueError('Website inventory must contain 1 to 200 files')
    names = {row['key'] for row in files}
    for name in config['pages']+['404.html']:
        if name not in names:
            problems.append('Missing '+name)
            continue
        parser = Links()
        parser.feed((site/name).read_text(encoding='utf-8'))
        if not parser.has_viewport:
            problems.append(name+': viewport metadata missing')
        if not set(config['pages']).issubset(set(parser.nav_links)):
            problems.append(name+': navigation must link all five pages')
        for link in parser.links+parser.assets:
            parsed = urlparse(link)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (site/name).parent / parsed.path
            if not destination.resolve().is_relative_to(site) or not destination.is_file():
                problems.append(name+': unresolved local reference '+link)
    return {'time': now(), 'passed': not problems, 'files': files, 'problems': problems,
            'note': 'Static checks do not establish visual quality or JavaScript behavior.'}

def verify_public(config):
    base = 'https://'+config['domain']
    checks = []
    def add(name, passed, **evidence):
        checks.append({'name': name, 'passed': passed, 'evidence': evidence})
    session = requests.Session()
    def get(url):
        # Redirects are inspected rather than followed to avoid an unexpected destination.
        return session.get(url, timeout=(10, 20), allow_redirects=False)
    try:
        response = get('http://'+config['domain']+'/')
        location = response.headers.get('Location', '')
        add('http_redirect', response.status_code in (301,302,307,308) and location == base+'/',
            status=response.status_code, location=location)
    except requests.RequestException as exc:
        add('http_redirect', False, error=type(exc).__name__)
    remote_assets = set()
    for name in ['']+config['pages']:
        try:
            response = get(base+'/'+name)
            parser = Links()
            if response.status_code == 200:
                parser.feed(response.text)
                remote_assets.update(parser.assets)
            cloudfront = 'cloudfront' in response.headers.get('Via', '').lower()
            html = 'text/html' in response.headers.get('Content-Type', '')
            navigation = set(config['pages']).issubset(set(parser.nav_links))
            add('page:'+(name or '/'), response.status_code == 200 and cloudfront and html and navigation and parser.has_viewport,
                status=response.status_code, cloudfront=cloudfront, content_type=response.headers.get('Content-Type'),
                navigation_links=parser.nav_links, responsive_metadata=parser.has_viewport,
                sha256=hashlib.sha256(response.content).hexdigest())
        except requests.RequestException as exc:
            add('page:'+(name or '/'), False, error=type(exc).__name__)
    for asset in sorted(remote_assets):
        target = urljoin(base+'/', asset)
        if urlparse(target).netloc != config['domain'] or not target.startswith(base+'/'):
            add('asset:'+asset, False, error='Asset is outside the configured HTTPS origin')
            continue
        try:
            response = get(target)
            add('asset:'+asset, response.status_code == 200, status=response.status_code)
        except requests.RequestException as exc:
            add('asset:'+asset, False, error=type(exc).__name__)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((config['domain'],443), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=config['domain']) as connection:
                cert = connection.getpeercert()
                add('tls_certificate', True, protocol=connection.version(), expires=cert.get('notAfter'),
                    subject_alt_names=cert.get('subjectAltName'), hostname_verified=True)
    except (OSError, ssl.SSLError) as exc:
        add('tls_certificate', False, error=type(exc).__name__)
    direct = f"https://{config['bucket']}.s3.{config['region']}.amazonaws.com/index.html"
    try:
        response = get(direct)
        add('private_s3_object', response.status_code == 403, url=direct, status=response.status_code,
            note='Runtime denial for index.html; full bucket security requires authenticated inspection.')
    except requests.RequestException as exc:
        add('private_s3_object', False, error=type(exc).__name__)
    try:
        nameservers = sorted(str(row.target).rstrip('.') for row in dns.resolver.resolve(config['domain'],'NS', lifetime=15))
        add('route53_delegation', len(nameservers)==4 and all('.awsdns-' in name for name in nameservers),
            nameservers=nameservers)
    except Exception as exc:
        add('route53_delegation', False, error=type(exc).__name__)
    try:
        response = get(base+'/__project5_nonexistent_resource__.html')
        add('custom_error_page', response.status_code == 404 and 'That page' in response.text,
            status=response.status_code)
    except requests.RequestException as exc:
        add('custom_error_page', False, error=type(exc).__name__)
    return {'time': now(), 'domain': config['domain'], 'passed': all(c['passed'] for c in checks),
            'checks': checks, 'limitations': ['Browser interaction and visual responsiveness require a manual browser check.']}
