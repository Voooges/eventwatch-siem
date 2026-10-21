"""Event normalization, persistent storage, and deterministic batch detection."""
import hashlib
import json
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

MAX_EVENTS = 20000

def normalize(row):
    if not isinstance(row, dict):
        raise ValueError('Each event must be an object')
    try:
        stamp = datetime.fromisoformat(str(row['timestamp']).replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('Timestamp must include a timezone')
        eid = int(row['event_id'])
        host = str(row['host']).strip()
        if not host or not 0 < eid < 65536:
            raise ValueError('Invalid host or event ID')
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'Invalid event: {exc}') from exc
    fields = ('user', 'domain', 'source_ip', 'group_sid', 'member', 'actor', 'record_id')
    result = {k: str(row.get(k, '') or '')[:2048] for k in fields}
    result.update(timestamp=stamp.astimezone(timezone.utc).isoformat(), event_id=eid, host=host[:256])
    return result

def parse_events(raw, kind='json'):
    if kind == 'xml':
        # Reject DTD/entity definitions; Windows event exports do not need them.
        if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
            raise ValueError('XML DTDs and entities are not supported')
        root = ET.fromstring(raw)
        rows = []
        for e in root.iter():
            if e.tag.split('}')[-1] != 'Event':
                continue
            def node(name):
                return next((n for n in e.iter() if n.tag.split('}')[-1] == name), None)
            data = {n.attrib.get('Name'): n.text or '' for n in e.iter() if n.tag.split('}')[-1] == 'Data'}
            # Event 1102 uses UserData rather than EventData.
            for n in e.iter():
                if n.tag.split('}')[-1] in ('SubjectUserName', 'SubjectDomainName'):
                    data[n.tag.split('}')[-1]] = n.text or ''
            ts, eid, host = node('TimeCreated'), node('EventID'), node('Computer')
            if ts is None or eid is None or host is None:
                raise ValueError('XML event is missing System fields')
            rows.append(dict(timestamp=ts.attrib.get('SystemTime'), event_id=eid.text,
                host=host.text, user=data.get('TargetUserName', data.get('SubjectUserName', '')),
                domain=data.get('TargetDomainName', data.get('SubjectDomainName', '')),
                source_ip=data.get('IpAddress', ''), group_sid=data.get('TargetSid', ''),
                member=data.get('MemberName', data.get('MemberSid', '')),
                actor=data.get('SubjectUserName', ''), record_id=node('EventRecordID').text if node('EventRecordID') is not None else ''))
    else:
        rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > MAX_EVENTS:
        raise ValueError(f'Expected an array of at most {MAX_EVENTS} events')
    return [normalize(row) for row in rows]

def connect(path):
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE IF NOT EXISTS events (fingerprint TEXT PRIMARY KEY, payload TEXT NOT NULL)')
    return db

def ingest(db, events):
    events = [normalize(e) for e in events]
    before = db.total_changes
    with db:
        for event in events:
            payload = json.dumps(event, sort_keys=True)
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?)',
                       (hashlib.sha256(payload.encode()).hexdigest(), payload))
    return db.total_changes - before

def read_events(db):
    return sorted((json.loads(r[0]) for r in db.execute('SELECT payload FROM events')), key=lambda e:e['timestamp'])

def detect(events, threshold=5, window_seconds=300):
    """Recompute across all stored events so import order does not affect results."""
    failures = defaultdict(deque)
    alerts = []
    def emit(rule, severity, title, event, evidence, guidance):
        evidence = list(evidence)
        identity = json.dumps([rule, evidence], sort_keys=True)
        alerts.append(dict(id=hashlib.sha256(identity.encode()).hexdigest()[:16], rule=rule,
            severity=severity, title=title, timestamp=event['timestamp'], host=event['host'],
            user=event['user'], evidence=list(evidence), guidance=guidance))
    for e in sorted(events, key=lambda x:x['timestamp']):
        t = datetime.fromisoformat(e['timestamp'])
        key = tuple(e.get(k, '').casefold() for k in ('host','domain','user','source_ip'))
        queue = failures[key]
        while queue and (t-datetime.fromisoformat(queue[0]['timestamp'])).total_seconds() > window_seconds:
            queue.popleft()
        valid_identity = e.get('user') not in ('', '-') and e.get('source_ip') not in ('', '-')
        if e['event_id'] == 4625 and valid_identity:
            queue.append(e)
            if len(queue) == threshold:
                emit('EW001','medium','Repeated failed logins',e,queue,
                     'Check the source and account. Mistyped or cached passwords can cause this pattern.')
        elif e['event_id'] == 4624 and valid_identity:
            if len(queue) >= threshold:
                emit('EW002','high','Successful login after repeated failures',e,[*queue,e],
                     'Verify the login with the account owner. This pattern alone does not prove compromise.')
            queue.clear()
        elif e['event_id'] == 4720:
            emit('EW003','medium','User account created',e,[e], 'Confirm the actor and account match an approved change.')
        elif e['event_id'] == 4732 and e.get('group_sid') == 'S-1-5-32-544':
            emit('EW004','high','Member added to local Administrators',e,[e], 'Review the member, actor, and approved access request.')
        elif e['event_id'] == 1102:
            emit('EW005','high','Security audit log cleared',e,[e], 'Confirm authorized maintenance and review upstream retained logs.')
    return sorted(alerts, key=lambda a:a['timestamp'], reverse=True)
