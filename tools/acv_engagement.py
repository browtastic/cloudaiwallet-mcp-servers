#!/usr/bin/env python3
"""
AICryptoVault engagement metrics.

Run on Box A:   python3 acv_engagement.py /var/log/cloudaiwallet
Reads current + rotated .gz logs together.

Core idea: almost everything in these logs is self-traffic. The numbers only
mean something after the operator's own plumbing is classified out.
"""
import json, glob, gzip, sys, collections, ipaddress
from datetime import datetime

LOGDIR = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---------------------------------------------------------------- classification
ANTHROPIC_PREFIXES = ('160.79.106.',)          # claude.ai MCP connector egress
REGISTRY_CLIENTS = {'smithery-probe', 'agent-tools.cloud',
                    'Smithery Connect', 'smithery-validation-test'}
SELF_CLIENTS = {'openclaw-bundle-mcp', 'aicryptovault-bridge'}

def first_ip(v):
    """source_ip may be an XFF chain 'client, proxy, proxy' — client is first."""
    if not v: return None
    return str(v).split(',')[0].strip()

def klass(ip, client=None):
    """Return one of: SELF, SYNTHETIC, OPERATOR_CLAUDE, REGISTRY, ORGANIC."""
    if client in SELF_CLIENTS: return 'SELF'
    if client in REGISTRY_CLIENTS: return 'REGISTRY'
    ip = first_ip(ip)
    if not ip: return 'UNKNOWN'
    if ip.startswith(ANTHROPIC_PREFIXES): return 'OPERATOR_CLAUDE'
    try: a = ipaddress.ip_address(ip)
    except ValueError: return 'UNKNOWN'
    if a.is_loopback: return 'SELF'
    # RFC 5737 documentation ranges cannot route on the public internet.
    # Python's is_private covers them, so test these BEFORE is_private.
    if ip.startswith(('203.0.113.', '198.51.100.', '192.0.2.')): return 'SYNTHETIC'
    if a.is_private: return 'SELF'
    return 'ORGANIC'

CAPTURE_FIELDS = ['reasoning', 'model_info', 'referral_source', 'context',
                  'operator_instructions', 'session_objective', 'feedback',
                  'client_application', 'agent_framework']

# ---------------------------------------------------------------- io
def read(pattern):
    for f in sorted(glob.glob(f'{LOGDIR}/{pattern}')):
        op = gzip.open if f.endswith('.gz') else open
        try:
            for line in op(f, 'rt', errors='replace'):
                line = line.strip()
                if not line: continue
                try: yield json.loads(line)
                except ValueError: pass
        except OSError: pass

def ts_of(d):
    return d.get('_ts') or d.get('ts') or ''

# ---------------------------------------------------------------- funnel
funnel = collections.defaultdict(collections.Counter)
for d in read('*-api-requests.jsonl*'):
    ev = d.get('event')
    k = klass(d.get('source_ip'), (d.get('mcp_client_name') or
                                   (d.get('body', {}) or {}).get('params', {})
                                   .get('clientInfo', {}).get('name')))
    if ev == 'sse_connect': funnel[k]['1_connect'] += 1
    elif ev == 'mcp_message':
        m = d.get('method') or (d.get('body') or {}).get('method')
        if m == 'initialize': funnel[k]['2_initialize'] += 1
        elif m == 'tools/list': funnel[k]['3_tools_list'] += 1
        elif m == 'tools/call': funnel[k]['4_tools_call'] += 1
    elif ev == 'tool_call': funnel[k]['5_tool_executed'] += 1

print('=' * 78)
print('FUNNEL  (rows = source class, cols = how deep they got)')
print('=' * 78)
stages = ['1_connect', '2_initialize', '3_tools_list', '4_tools_call', '5_tool_executed']
print(f"{'class':18s}" + ''.join(f'{s:>16s}' for s in stages))
for k in sorted(funnel, key=lambda x: -funnel[x]['1_connect']):
    print(f'{k:18s}' + ''.join(f"{funnel[k][s]:>16d}" for s in stages))

# ---------------------------------------------------------------- tool calls
print()
print('=' * 78)
print('TOOL CALLS — every one, classified')
print('=' * 78)
calls = []
for d in read('*-api-requests.jsonl*'):
    if d.get('event') != 'tool_call': continue
    args = d.get('arguments') or {}
    filled = [f for f in CAPTURE_FIELDS if args.get(f) not in (None, '', [])]
    calls.append({'ts': ts_of(d), 'ip': first_ip(d.get('source_ip')),
                  'class': klass(d.get('source_ip')), 'server': d.get('_server'),
                  'tool': d.get('tool'), 'tag': d.get('tag'),
                  'model_info': args.get('model_info'), 'filled': filled})
calls.sort(key=lambda c: c['ts'])
for c in calls:
    print(f"{c['ts'][:19]:20s} {c['class']:16s} {str(c['ip']):16s} "
          f"{str(c['tool']):22s} tag={c['tag']} "
          f"capture={len(c['filled'])}/9 model={str(c['model_info'])[:38]}")

by_class = collections.Counter(c['class'] for c in calls)
print(f'\ntool_call totals by class: {dict(by_class)}')
print(f"ORGANIC tool calls: {by_class.get('ORGANIC', 0)}")

# ---------------------------------------------------------------- tag sanity
tags = collections.Counter(c['tag'] for c in calls)
print(f'\ntag field distribution across ALL tool_calls: {dict(tags)}')
if len(tags) == 1:
    print('  !! tag is a CONSTANT, not a classifier — it labels operator traffic')
    print('     identically to attacker traffic. Anything keyed on it is 100% FP.')

# ---------------------------------------------------------------- capture fill
print()
print('=' * 78)
print('CAPTURE FIELD FILL RATE  (per field, per source class)')
print('=' * 78)
fill = collections.defaultdict(collections.Counter)
tot = collections.Counter()
for c in calls:
    tot[c['class']] += 1
    for f in c['filled']: fill[c['class']][f] += 1
for k in sorted(tot):
    print(f'\n{k}  (n={tot[k]})')
    for f in CAPTURE_FIELDS:
        n = fill[k][f]
        if n: print(f'   {f:24s} {n:3d}/{tot[k]:<3d}  {100*n/tot[k]:5.1f}%')

# ---------------------------------------------------------------- dwell
# session_id is unreliable (null on bridge handshakes; nova ids are cookie-derived
# and survive server-side session resets). Construct sessions from (ip, gap).
print()
print('=' * 78)
print('DWELL  (sessions constructed from source_ip + idle gap; not session_id)')
print('=' * 78)

def parse(t):
    try: return datetime.fromisoformat(t.replace('Z', '+00:00'))
    except Exception: return None

for GAP in (300, 900, 1800):     # sensitivity — the window moves the answer
    ev = collections.defaultdict(list)
    for d in read('*-api-requests.jsonl*'):
        t = parse(ts_of(d))
        if t: ev[(klass(d.get('source_ip')), first_ip(d.get('source_ip')))].append(t)
    sess, dur = 0, []
    for (k, ip), times in ev.items():
        if k != 'ORGANIC': continue
        times.sort()
        start = prev = times[0]
        for t in times[1:]:
            if (t - prev).total_seconds() > GAP:
                sess += 1; dur.append((prev - start).total_seconds()); start = t
            prev = t
        sess += 1; dur.append((prev - start).total_seconds())
    avg = sum(dur) / len(dur) if dur else 0
    print(f'  gap={GAP:4d}s -> ORGANIC sessions={sess:3d}  '
          f'mean dwell={avg:7.1f}s  max={max(dur) if dur else 0:.1f}s')

# ---------------------------------------------------------------- doors
print()
print('=' * 78)
print('DOORS (provenance.jsonl) — where traffic actually lands')
print('=' * 78)
doors = collections.Counter()
for d in read('provenance.jsonl*'):
    doors[(d.get('door'), klass(d.get('ip'), d.get('client_name')))] += 1
for (dr, k), n in doors.most_common(12):
    print(f'{n:6d}  door={str(dr):16s} {k}')
