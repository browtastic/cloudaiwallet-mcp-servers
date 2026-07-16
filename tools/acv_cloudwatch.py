#!/usr/bin/env python3
"""
acv_cloudwatch.py — ship EVERYTHING to CloudWatch.

Box A  (engagement):  python3 acv_cloudwatch.py --engagement --logdir /var/log/cloudaiwallet
LLM3   (tokens/cost): python3 acv_cloudwatch.py --llm --langfuse-host http://127.0.0.1:3000
Admin  (verify):      python3 acv_cloudwatch.py --verify

Emits BOTH:
  * CloudWatch Logs  -> group acv-research, one stream per feed (the durable record)
  * CloudWatch Metrics -> namespace ACV/* (queryable, alarmable)

WHY BOTH: Logs are the archive — full fidelity, replayable, survives the box.
Metrics are for alarms; they cannot be reconstructed into records. Shipping only
metrics would throw away the data. Shipping only logs means no tripwire.

DELIVERY IS NOT ASSUMED. Every push is followed by a nextSequenceToken check,
and --verify does the only trustworthy test (get-log-events read-back) from
admin credentials. storedBytes and lastEventTimestamp lie; this project learned
that the hard way.

NOTE ON IAM: Box A's role is deliberately write-only. It can PutLogEvents but
not GetLogEvents. That is correct — Box A is the honeypot; an attacker who owns
it must not be able to read back the research data. So --verify runs from admin,
off-box. Do not "fix" this by granting Box A read access.
"""
import argparse, json, glob, gzip, sys, time, collections, ipaddress
from datetime import datetime, timezone

try:
    import boto3
except ImportError:
    sys.exit("pip install boto3 --break-system-packages")

GROUP = 'acv-research'
REGION = 'us-east-1'

# ---------------------------------------------------------------- classification
# Mirrors acv_engagement.py. Keep in sync — or better, import it.
ANTHROPIC = ('160.79.106.',)
REGISTRY = {'smithery-probe', 'agent-tools.cloud', 'Smithery Connect', 'smithery-validation-test'}
SELF_CLIENTS = {'openclaw-bundle-mcp', 'aicryptovault-bridge'}

def first_ip(v):
    return str(v).split(',')[0].strip() if v else None

def klass(ip, client=None):
    if client in SELF_CLIENTS: return 'SELF'
    if client in REGISTRY: return 'REGISTRY'
    ip = first_ip(ip)
    if not ip: return 'UNKNOWN'
    if ip.startswith(ANTHROPIC): return 'OPERATOR_CLAUDE'
    try: a = ipaddress.ip_address(ip)
    except ValueError: return 'UNKNOWN'
    if a.is_loopback: return 'SELF'
    if ip.startswith(('203.0.113.', '198.51.100.', '192.0.2.')): return 'SYNTHETIC'
    if a.is_private: return 'SELF'
    return 'ORGANIC'

def read_logs(logdir, pattern):
    for f in sorted(glob.glob(f'{logdir}/{pattern}')):
        op = gzip.open if f.endswith('.gz') else open
        try:
            for line in op(f, 'rt', errors='replace'):
                line = line.strip()
                if not line: continue
                try: yield json.loads(line)
                except ValueError: pass
        except OSError: pass

# ---------------------------------------------------------------- cw plumbing
class CW:
    def __init__(self, region=REGION):
        self.logs = boto3.client('logs', region_name=region)
        self.cw = boto3.client('cloudwatch', region_name=region)

    def ensure(self, stream):
        for fn, kw in ((self.logs.create_log_group, {'logGroupName': GROUP}),
                       (self.logs.create_log_stream, {'logGroupName': GROUP, 'logStreamName': stream})):
            try: fn(**kw)
            except self.logs.exceptions.ResourceAlreadyExistsException: pass
            except Exception as e: print(f'  ! {e}', file=sys.stderr)
        # retention: explicit. The old group shipped with -1 (forever) by accident.
        try: self.logs.put_retention_policy(logGroupName=GROUP, retentionInDays=90)
        except Exception: pass

    def put_logs(self, stream, records):
        if not records: return 0
        self.ensure(stream)
        now = int(time.time() * 1000)
        events = [{'timestamp': now, 'message': json.dumps(r)[:250000]} for r in records]
        events.sort(key=lambda e: e['timestamp'])
        sent = 0
        for i in range(0, len(events), 1000):          # API caps at 1000/call
            r = self.logs.put_log_events(logGroupName=GROUP, logStreamName=stream,
                                         logEvents=events[i:i + 1000])
            if 'nextSequenceToken' not in r and 'rejectedLogEventsInfo' in r:
                print(f'  ! rejected: {r["rejectedLogEventsInfo"]}', file=sys.stderr)
            sent += len(events[i:i + 1000])
        return sent

    def put_metrics(self, namespace, data):
        for i in range(0, len(data), 20):              # API caps at 20/call
            self.cw.put_metric_data(Namespace=namespace, MetricData=data[i:i + 20])
        return len(data)

def metric(name, value, unit='Count', **dims):
    d = {'MetricName': name, 'Value': float(value), 'Unit': unit,
         'Timestamp': datetime.now(timezone.utc)}
    if dims:
        d['Dimensions'] = [{'Name': k, 'Value': str(v)} for k, v in dims.items()]
    return d

# ---------------------------------------------------------------- engagement
def ship_engagement(cw, logdir):
    funnel = collections.defaultdict(collections.Counter)
    calls, raw = [], []

    for d in read_logs(logdir, '*-api-requests.jsonl*'):
        ev = d.get('event')
        k = klass(d.get('source_ip'), d.get('mcp_client_name'))
        if ev == 'sse_connect': funnel[k]['connect'] += 1
        elif ev == 'mcp_message':
            m = d.get('method') or (d.get('body') or {}).get('method')
            if m in ('initialize', 'tools/list', 'tools/call'):
                funnel[k][m.replace('/', '_')] += 1
        elif ev == 'tool_call':
            funnel[k]['tool_executed'] += 1
            args = d.get('arguments') or {}
            calls.append({'ts': d.get('_ts'), 'source_class': k, 'ip': first_ip(d.get('source_ip')),
                          'server': d.get('_server'), 'tool': d.get('tool'),
                          'tag_raw': d.get('tag'),
                          'model_info': args.get('model_info'),
                          'capture_filled': [f for f in
                              ('reasoning','model_info','referral_source','context',
                               'operator_instructions','session_objective','feedback',
                               'client_application','agent_framework')
                              if args.get(f) not in (None, '', [])]})
            raw.append(d)

    # metrics
    md = []
    for k, c in funnel.items():
        for stage in ('connect', 'initialize', 'tools_list', 'tools_call', 'tool_executed'):
            md.append(metric(f'Funnel_{stage}', c[stage], SourceClass=k))
    fill = collections.Counter()
    tot = collections.Counter()
    for c in calls:
        tot[c['source_class']] += 1
        for f in c['capture_filled']: fill[(c['source_class'], f)] += 1
    for (k, f), n in fill.items():
        md.append(metric('CaptureFillRate', 100.0 * n / tot[k], 'Percent', SourceClass=k, Field=f))

    n_m = cw.put_metrics('ACV/Engagement', md)
    n_l = cw.put_logs('engagement-toolcalls', calls)
    n_r = cw.put_logs('engagement-raw', raw)

    organic = funnel['ORGANIC']['tool_executed']
    print(f'engagement: {n_m} metrics, {n_l} tool-call records, {n_r} raw records')
    print(f'  ORGANIC tool calls = {organic}   <-- the tripwire')
    for k in sorted(funnel, key=lambda x: -funnel[x]['connect']):
        c = funnel[k]
        print(f'  {k:16s} connect={c["connect"]:5d} init={c["initialize"]:5d} '
              f'list={c["tools_list"]:5d} call={c["tools_call"]:3d}')
    return organic

# ---------------------------------------------------------------- llm cost
# Prices are the OPERATOR'S OWN inference cost. Vela runs on a self-hosted
# g4dn.xlarge, so per-token price is 0 and the real cost is instance-hours.
# Emitting a fake per-token dollar figure would render an estimate as a
# measurement. Instance cost is emitted separately and honestly.
G4DN_USD_PER_HOUR = 0.526      # us-east-1 on-demand, verify against your billing

def ship_llm(cw, host, pk, sk):
    import base64, urllib.request
    auth = base64.b64encode(f'{pk}:{sk}'.encode()).decode()
    url = f'{host}/api/public/traces?limit=100'
    req = urllib.request.Request(url, headers={'Authorization': f'Basic {auth}'})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            traces = json.loads(r.read()).get('data', [])
    except Exception as e:
        print(f'  ! langfuse fetch failed: {e}', file=sys.stderr)
        print('    (check LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY and that '
              'langfuse-web is up on the given host)', file=sys.stderr)
        return 0

    recs, md = [], []
    tot_in = tot_out = 0
    for t in traces:
        u = t.get('usage') or {}
        pin, pout = u.get('input') or 0, u.get('output') or 0
        tot_in += pin; tot_out += pout
        recs.append({'trace_id': t.get('id'), 'ts': t.get('timestamp'),
                     'name': t.get('name'), 'input_tokens': pin, 'output_tokens': pout,
                     'latency_ms': t.get('latency'), 'model': t.get('model')})
    if recs:
        md += [metric('PromptTokens', tot_in), metric('CompletionTokens', tot_out),
               metric('Traces', len(recs))]
        lat = [r['latency_ms'] for r in recs if r.get('latency_ms')]
        if lat: md.append(metric('MeanLatencyMs', sum(lat) / len(lat), 'Milliseconds'))
    md.append(metric('InferenceCostUSDPerHour', G4DN_USD_PER_HOUR, 'None'))

    n_m = cw.put_metrics('ACV/LLM', md)
    n_l = cw.put_logs('llm-traces', recs)
    print(f'llm: {n_m} metrics, {n_l} trace records  (in={tot_in} out={tot_out} tokens)')
    return len(recs)

# ---------------------------------------------------------------- verify
def verify(cw):
    """The ONLY trustworthy delivery check. Needs admin creds — Box A cannot do this."""
    marker = f'ACV-VERIFY-{int(time.time())}'
    cw.put_logs('verify', [{'marker': marker}])
    print(f'wrote marker {marker}; waiting 30s for delivery...')
    time.sleep(30)
    try:
        r = cw.logs.get_log_events(logGroupName=GROUP, logStreamName='verify', limit=20)
        hit = any(marker in e['message'] for e in r.get('events', []))
        print('READ-BACK CONFIRMED' if hit else 'READ-BACK FAILED — marker not found')
        return hit
    except Exception as e:
        print(f'READ-BACK FAILED — {e}')
        print('  If this is AccessDenied, you are on a write-only role. Run from admin.')
        return False

# ---------------------------------------------------------------- main
if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--engagement', action='store_true')
    ap.add_argument('--llm', action='store_true')
    ap.add_argument('--verify', action='store_true')
    ap.add_argument('--logdir', default='/var/log/cloudaiwallet')
    ap.add_argument('--langfuse-host', default='http://127.0.0.1:3000')
    ap.add_argument('--langfuse-pk', default=None)
    ap.add_argument('--langfuse-sk', default=None)
    a = ap.parse_args()

    cw = CW()
    if a.verify: sys.exit(0 if verify(cw) else 1)
    if a.engagement: ship_engagement(cw, a.logdir)
    if a.llm:
        import os
        pk = a.langfuse_pk or os.environ.get('LANGFUSE_PUBLIC_KEY')
        sk = a.langfuse_sk or os.environ.get('LANGFUSE_SECRET_KEY')
        if not (pk and sk): sys.exit('need --langfuse-pk/--langfuse-sk or env vars')
        ship_llm(cw, a.langfuse_host, pk, sk)
    if not (a.engagement or a.llm or a.verify): ap.print_help()
