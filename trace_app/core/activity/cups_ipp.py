"""CUPS IPP control files (no Qt).

A macOS/Linux print spooler keeps a c##### control file per print job under
/var/spool/cups, in the IPP binary format (RFC 8010): a 2-byte version, a
2-byte operation/status, a 4-byte request id, then attribute groups. Each
attribute is a 1-byte value tag, a 2-byte name length and name, a 2-byte
value length and value; a 0-length name continues the previous attribute
(a set). Groups end at tag 0x03.

`records(data, path, ref)` returns one `activity.record` for the job: who
printed, what, on which printer, and when it was created, started and
finished. Checked against plaso's mac_cups_ipp and its expected values
(tests/test_cups_ipp.py).
"""

import logging
import struct

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.CUPS')

_INTEGER_TAGS = {0x21, 0x23}            # integer, enum
_END_OF_ATTRIBUTES = 0x03


def _attributes(data):
    """{name: value} for the file's attributes; an integer value is an int,
    everything else the text. The last value wins (as CUPS rewrites)."""
    out = {}
    offset = 8                          # version, operation, request id
    size = len(data)
    name = None
    while offset < size:
        tag = data[offset]
        offset += 1
        if tag <= _END_OF_ATTRIBUTES or tag == 0x00:
            name = None
            continue
        if offset + 2 > size:
            break
        name_length = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        this_name = data[offset:offset + name_length].decode('utf-8',
                                                             'replace')
        offset += name_length
        if offset + 2 > size:
            break
        value_length = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        raw = data[offset:offset + value_length]
        offset += value_length
        key = this_name or name         # a 0-length name is a set member
        if not key:
            continue
        name = key
        if tag in _INTEGER_TAGS and value_length == 4:
            value = struct.unpack('>i', raw)[0]
        else:
            value = raw.decode('utf-8', 'replace')
        out.setdefault(key, value)      # the first value of a set
    return out


def records(data, path, ref):
    if data[:2] not in (b'\x02\x00', b'\x02\x01', b'\x01\x01'):
        return []
    attributes = _attributes(data)
    if not attributes:
        return []
    created = times.unix(attributes.get('time-at-creation'))
    detail = {
        'user': attributes.get('job-originating-user-name'),
        'owner': attributes.get('com.apple.print.JobInfo.PMJobOwner'),
        'job name': attributes.get('job-name'),
        'application': attributes.get(
            'com.apple.print.JobInfo.PMApplicationName'),
        'printer': attributes.get('DestinationPrinterID'),
        'printer uri': attributes.get('printer-uri') or
        attributes.get('job-printer-uri'),
        'document type': attributes.get('document-format'),
        'copies': attributes.get('copies'),
        'job id': attributes.get('job-uuid'),
        'host': attributes.get('job-originating-host-name'),
        'started': times.iso(times.unix(attributes.get('time-at-processing'))),
        'finished': times.iso(times.unix(attributes.get('time-at-completed'))),
        'basis': 'when the print job was created',
    }
    subject = detail['job name'] or detail['application'] or \
        detail['printer'] or 'print job'
    return [record('system', 'CUPS print job', created, 'Printed', subject,
                   detail, user=detail['user'] or '', path=path, ref=ref)]
