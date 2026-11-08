"""Validated configuration, durable JSON communication, and approval boundaries."""
from __future__ import annotations
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]

def now():
    return datetime.now(timezone.utc).isoformat()

def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    temp.replace(path)

def load_config(path=None):
    data = json.loads(Path(path or ROOT/'config.json').read_text(encoding='utf-8'))
    patterns = {'domain': r'[a-z0-9][a-z0-9.-]+\.[a-z]{2,}',
                'bucket': r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',
                'region': r'[a-z]{2}-[a-z]+-\d', 'distribution_id': r'E[A-Z0-9]+',
                'account_id': r'\d{12}',
                'distribution_domain': r'[a-z0-9]+\.cloudfront\.net'}
    for key, pattern in patterns.items():
        if not re.fullmatch(pattern, data.get(key, '')):
            raise ValueError(f'Invalid configuration field: {key}')
    if not data['certificate_arn'].startswith(f"arn:aws:acm:us-east-1:{data['account_id']}:certificate/"):
        raise ValueError('Certificate must belong to configured account in us-east-1')
    site = (ROOT/data['website_directory']).resolve()
    if not site.is_relative_to(ROOT) or site == ROOT:
        raise ValueError('Website directory must be a project subdirectory')
    if len(data['pages']) < 5 or len(set(data['pages'])) != len(data['pages']):
        raise ValueError('At least five distinct pages are required')
    for page in data['pages']:
        if not re.fullmatch(r'[a-zA-Z0-9_-]+\.html', page):
            raise ValueError('Page names must be flat HTML filenames')
    return data

def redact(value):
    text = json.dumps(value, ensure_ascii=False)
    for name in ('OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_ACCESS_KEY_ID'):
        secret = os.getenv(name)
        if secret:
            text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'sk-[A-Za-z0-9_-]{12,}', '[REDACTED]', text)
    text = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED]', text)
    return json.loads(text)

class Run:
    def __init__(self, label='run', parent=None):
        self.id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid4().hex[:8]
        self.path = Path(parent or ROOT/'outputs')/self.id
        self.path.mkdir(parents=True)
        self.event('run_started', {'label': label, 'run_id': self.id})

    def event(self, kind, data):
        row = redact({'time': now(), 'kind': kind, 'data': data})
        with (self.path/'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=False)+'\n')
        print(f'[{kind}] '+json.dumps(row['data'], ensure_ascii=True)[:450], flush=True)

    def artifact(self, name, value):
        if not re.fullmatch(r'[a-zA-Z0-9_-]+\.json', name):
            raise ValueError('Invalid artifact name')
        save_json(self.path/name, redact(value))
        self.event('artifact_saved', {'file': name})
        return name

class ApprovalRequired(RuntimeError):
    pass

class Approvals:
    """Every mutation needs a fresh, exact typed approval; no auto-yes switch."""
    def __init__(self, run):
        self.run = run

    def require(self, action, details):
        self.run.event('approval_requested', {'action': action, 'details': details})
        print('\nReview this exact change:\n'+json.dumps(details, indent=2))
        phrase = f'APPROVE {action}'
        try:
            answer = input(f'Type {phrase!r} to apply, or press Enter to cancel: ')
        except (EOFError, OSError):
            answer = ''
        accepted = answer == phrase
        self.run.event('approval_result', {'action': action, 'approved': accepted})
        if not accepted:
            raise ApprovalRequired(f'{action} was not approved; no change applied')
