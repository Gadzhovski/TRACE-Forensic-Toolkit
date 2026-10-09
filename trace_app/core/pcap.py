"""Network captures (PCAP / PCAPNG) found on evidence, summarised (no Qt;
dpkt -- BSD, pure Python, no dependencies).

What an examiner asks of a capture first: when it ran, who talked to
whom and how much, which names were looked up, which web pages were asked
for and which TLS servers were contacted (the ClientHello's server name,
readable even though the session is encrypted). `summarise(data)` reads
every packet (up to MAX_PACKETS) of classic pcap (microsecond and
nanosecond, either byte order) or pcapng; `page(summary)` is that as an
escaped, static HTML page for the viewer; `text(summary)` the same for the
search index (so hosts, names and URLs are found by keyword and listed as
indicators).

Link types: Ethernet, Linux cooked (SLL, SLL2), raw IP, BSD loopback.
VLAN-tagged Ethernet is unwrapped by dpkt. Nothing is reassembled: an HTTP
request is read from the segment that starts it, as tcpdump shows it.
"""

import datetime
import html
import io
import ipaddress
import struct

MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',      # microseconds
          b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',      # nanoseconds
          b'\x0a\x0d\x0d\x0a')                            # pcapng
MAX_PACKETS = 2_000_000
MAX_LISTED = 2000
_HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ',
                 b'OPTIONS ', b'PATCH ', b'CONNECT ', b'TRACE ')


class PcapError(ValueError):
    pass


def is_capture(head):
    return bytes(head[:4]) in MAGICS


def _utc(seconds):
    try:
        return datetime.datetime.fromtimestamp(
            float(seconds), datetime.timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S.%f')[:-3]
    except (OverflowError, OSError, ValueError):
        return ''


def _address(raw):
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return raw.hex()


def _reader(data):
    import dpkt
    stream = io.BytesIO(bytes(data))
    try:
        if bytes(data[:4]) == MAGICS[-1]:
            return dpkt.pcapng.Reader(stream)
        return dpkt.pcap.Reader(stream)
    except (ValueError, dpkt.dpkt.Error) as exc:
        raise PcapError(f"Not a readable capture: {exc}") from exc


def _network_layer(linktype, frame):
    """The IP / IPv6 packet inside a frame, or None."""
    import dpkt
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            return dpkt.ethernet.Ethernet(frame).data
        if linktype == dpkt.pcap.DLT_LINUX_SLL:
            return dpkt.sll.SLL(frame).data
        if linktype == 276:                                 # LINUX_SLL2
            return dpkt.sll2.SLL2(frame).data
        if linktype in (dpkt.pcap.DLT_RAW, 12, 14, 101):    # raw IP
            version = frame[0] >> 4 if frame else 0
            return dpkt.ip6.IP6(frame) if version == 6 else \
                dpkt.ip.IP(frame)
        if linktype in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
            return dpkt.loopback.Loopback(frame).data
    except (dpkt.dpkt.Error, IndexError, struct.error, ValueError):
        return None
    return None


def server_name(payload):
    """The SNI of a TLS ClientHello at the start of `payload`, or ''."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return ''
    try:
        position = 9 + 2 + 32                    # record, handshake, version,
        session = payload[position]              # random
        position += 1 + session
        suites = struct.unpack_from('>H', payload, position)[0]
        position += 2 + suites
        methods = payload[position]
        position += 1 + methods
        end = position + 2 + struct.unpack_from('>H', payload, position)[0]
        position += 2
        while position + 4 <= min(end, len(payload)):
            kind, length = struct.unpack_from('>HH', payload, position)
            position += 4
            if kind == 0 and length >= 5:            # server_name
                name_length = struct.unpack_from('>H', payload,
                                                 position + 3)[0]
                return payload[position + 5:position + 5 + name_length] \
                    .decode('ascii', 'replace')
            position += length
    except (IndexError, struct.error):
        return ''
    return ''


def summarise(data, max_packets=MAX_PACKETS):
    """{'format', 'link', 'packets', 'bytes', 'first', 'last', 'hosts',
    'conversations', 'dns', 'http', 'tls', 'truncated', 'undecoded'}."""
    import dpkt
    reader = _reader(data)
    linktype = reader.datalink()
    out = {'format': 'pcapng' if bytes(data[:4]) == MAGICS[-1] else 'pcap',
           'link': linktype, 'packets': 0, 'bytes': 0, 'first': None,
           'last': None, 'hosts': {}, 'conversations': {}, 'dns': [],
           'http': [], 'tls': [], 'truncated': False, 'undecoded': 0}
    try:
        for stamp, frame in reader:
            out['packets'] += 1
            out['bytes'] += len(frame)
            if out['first'] is None or stamp < out['first']:
                out['first'] = stamp
            if out['last'] is None or stamp > out['last']:
                out['last'] = stamp
            if out['packets'] > max_packets:
                out['truncated'] = True
                break
            packet = _network_layer(linktype, frame)
            if not isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
                out['undecoded'] += 1
                continue
            _packet(out, stamp, packet, len(frame))
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError,
            struct.error):
        out['damaged'] = (f"the capture ends inside a record after "
                          f"{out['packets']:,} packets")
    return out


def _packet(out, stamp, packet, size):
    import dpkt
    source, target = _address(packet.src), _address(packet.dst)
    for host in (source, target):
        entry = out['hosts'].setdefault(host, [0, 0])
        entry[0] += 1
        entry[1] += size
    transport = packet.data
    if isinstance(transport, dpkt.tcp.TCP):
        protocol = 'TCP'
    elif isinstance(transport, dpkt.udp.UDP):
        protocol = 'UDP'
    else:
        protocol = {1: 'ICMP', 58: 'ICMPv6'}.get(
            getattr(packet, 'p', getattr(packet, 'nxt', 0)), 'other')
        transport = None
    ports = (transport.sport, transport.dport) if transport is not None \
        else (0, 0)
    key = (protocol,) + tuple(sorted(((source, ports[0]),
                                      (target, ports[1]))))
    row = out['conversations'].setdefault(key, [0, 0, stamp, stamp])
    row[0] += 1
    row[1] += size
    row[3] = stamp
    if transport is None:
        return
    payload = bytes(transport.data)
    if 53 in ports and payload:
        _dns(out, stamp, payload, protocol, source, target)
    if protocol == 'TCP' and payload.startswith(_HTTP_METHODS):
        _http(out, stamp, payload, source, target, ports[1])
    if protocol == 'TCP' and payload[:1] == b'\x16':
        name = server_name(payload)
        if name and len(out['tls']) < MAX_LISTED:
            out['tls'].append({'time': _utc(stamp), 'client': source,
                               'server': target, 'port': ports[1],
                               'name': name})


def _dns(out, stamp, payload, protocol, source, target):
    import dpkt
    if protocol == 'TCP':
        payload = payload[2:]                    # length prefix
    try:
        message = dpkt.dns.DNS(payload)
    except (dpkt.dpkt.Error, IndexError, struct.error, ValueError):
        return
    answers = []
    for answer in message.an:
        if answer.type == dpkt.dns.DNS_A:
            answers.append(_address(answer.rdata))
        elif answer.type == dpkt.dns.DNS_AAAA:
            answers.append(_address(answer.rdata))
        elif answer.type in (dpkt.dns.DNS_CNAME, dpkt.dns.DNS_PTR,
                             dpkt.dns.DNS_NS):
            answers.append(getattr(answer, 'cname', '') or
                           getattr(answer, 'ptrname', '') or
                           getattr(answer, 'nsname', ''))
    for question in message.qd:
        if len(out['dns']) >= MAX_LISTED:
            return
        out['dns'].append({
            'time': _utc(stamp), 'client': target if message.qr else source,
            'server': source if message.qr else target,
            'name': question.name,
            'type': _QTYPES.get(question.type, str(question.type)),
            'response': bool(message.qr),
            'answers': answers if message.qr else []})


_QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
           16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY'}


def _http(out, stamp, payload, source, target, port):
    if len(out['http']) >= MAX_LISTED:
        return
    head = payload.split(b'\r\n\r\n', 1)[0].decode('latin-1')
    lines = head.split('\r\n')
    parts = lines[0].split(' ')
    if len(parts) < 2:
        return
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(':')
        headers[name.strip().lower()] = value.strip()
    host = headers.get('host', target)
    out['http'].append({'time': _utc(stamp), 'client': source,
                        'server': target, 'port': port, 'method': parts[0],
                        'host': host, 'uri': parts[1],
                        'url': f"http://{host}{parts[1]}" if
                        parts[1].startswith('/') else parts[1],
                        'agent': headers.get('user-agent', '')})


# --- what an examiner reads -----------------------------------------------------

_LINKS = {1: 'Ethernet', 113: 'Linux cooked', 276: 'Linux cooked v2',
          101: 'raw IP', 12: 'raw IP', 14: 'raw IP', 0: 'BSD loopback',
          108: 'loopback'}


def page(summary):
    """The summary as an escaped static HTML page."""
    e = html.escape
    rows = [('Format', summary['format']),
            ('Link type', _LINKS.get(summary['link'],
                                     str(summary['link']))),
            ('Packets', f"{summary['packets']:,}"
                        + (' (stopped at the limit)' if summary['truncated']
                           else '')),
            ('Bytes captured', f"{summary['bytes']:,}"),
            ('First packet (UTC)', _utc(summary['first'])
             if summary['first'] is not None else ''),
            ('Last packet (UTC)', _utc(summary['last'])
             if summary['last'] is not None else '')]
    if summary.get('damaged'):
        rows.append(('Damage', summary['damaged']))
    if summary['undecoded']:
        rows.append(('Not IP', f"{summary['undecoded']:,} packets"))
    out = ['<h2>Network capture</h2><table>'] + [
        f'<tr><th align="left">{e(k)}</th><td>{e(v)}</td></tr>'
        for k, v in rows] + ['</table>']

    def table(title, headers, values):
        if not values:
            return
        out.append(f'<h3>{e(title)} ({len(values):,})</h3><table border="1" '
                   f'cellspacing="0" cellpadding="3"><tr>' + ''.join(
                       f'<th>{e(h)}</th>' for h in headers) + '</tr>')
        for row in values:
            out.append('<tr>' + ''.join(f'<td>{e(str(c))}</td>'
                                        for c in row) + '</tr>')
        out.append('</table>')

    table('TLS server names (from ClientHello)',
          ['Time (UTC)', 'Client', 'Server', 'Port', 'Server name'],
          [(t['time'], t['client'], t['server'], t['port'], t['name'])
           for t in summary['tls']])
    table('HTTP requests', ['Time (UTC)', 'Client', 'Method', 'URL',
                            'User-Agent'],
          [(h['time'], h['client'], h['method'], h['url'], h['agent'])
           for h in summary['http']])
    table('DNS', ['Time (UTC)', 'Client', 'Server', 'Name', 'Type',
                  'Answers'],
          [(d['time'], d['client'], d['server'], d['name'], d['type'],
            ', '.join(d['answers']) if d['response'] else '(query)')
           for d in summary['dns']])
    conversations = sorted(summary['conversations'].items(),
                           key=lambda item: -item[1][1])[:MAX_LISTED]
    table('Conversations, by bytes', ['Protocol', 'A', 'B', 'Packets',
                                      'Bytes', 'First (UTC)', 'Last (UTC)'],
          [(key[0], f"{key[1][0]}:{key[1][1]}" if key[1][1] else key[1][0],
            f"{key[2][0]}:{key[2][1]}" if key[2][1] else key[2][0],
            f"{v[0]:,}", f"{v[1]:,}", _utc(v[2]), _utc(v[3]))
           for key, v in conversations])
    hosts = sorted(summary['hosts'].items(), key=lambda item: -item[1][1])
    table('Hosts, by bytes', ['Address', 'Packets', 'Bytes'],
          [(h, f"{v[0]:,}", f"{v[1]:,}") for h, v in hosts[:MAX_LISTED]])
    return ''.join(out)


def text(summary):
    """Hosts, names and URLs, one per line, for the search index."""
    lines = list(summary['hosts'])
    lines += [d['name'] for d in summary['dns']]
    lines += [a for d in summary['dns'] for a in d['answers']]
    lines += [h['url'] for h in summary['http']]
    lines += [h['agent'] for h in summary['http'] if h['agent']]
    lines += [t['name'] for t in summary['tls']]
    return '\n'.join(dict.fromkeys(line for line in lines if line))
