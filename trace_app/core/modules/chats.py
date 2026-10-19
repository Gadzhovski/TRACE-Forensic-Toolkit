"""Chats a LEAPP read, as conversation rows (no Qt).

A LEAPP artifact that holds messages says so in its LAVA entry:
`data_views.conversation` names the columns -- the thread
(`conversationDiscriminatorColumn`) and its label
(`conversationLabelColumn`), the text, the sender, the direction and the
value of it that means sent (`directionSentValue`), the time, an
attachment (`mediaColumn`), and how the device owner is called on a sent
message (`sentMessageStaticLabel`). iLEAPP has two dozen such artifacts
(Discord, Instagram, Kik, Line, Burner, IMO...), aLEAPP, VLEAPP and DLEAPP
their own.

`_artifact_rows()` turns one such artifact's rows into the 'communication'
rows core/conversations groups into threads; core/modules/bridge stores
them as activity rows (reader = the tool), so Triage ▸ Conversations shows
them beside TRACE's own WhatsApp, iMessage and Skype, as bubbles, with
export and the report. Each row points at its LAVA row (`make_module_ref`):
a click shows the file the tool read it from, a double-click the row in
the Modules tab. The tool's database is only read.
"""

import logging
import os
import re

from trace_app.core.case import make_module_ref
from trace_app.core.modules import lava

logger = logging.getLogger('TRACE.Modules')

#: Rows read from one artifact, at most (a chat table is rarely large; the
#: cap keeps a pathological one from filling the window's memory).
MAX_ROWS_PER_ARTIFACT = 200_000
#: What a sent message's sender is called when the tool gives no label.
DEVICE_OWNER = 'Device owner'
_TRAILING = re.compile(r'\s*(-\s*)?(direct messages|messages|message|chats|'
                       r'chat|threads|conversations|conversation)\s*$', re.I)


def app_name(artifact_name):
    """'Discord - Chats' -> 'Discord', 'Kik Messages' -> 'Kik',
    'Instagram Threads' -> 'Instagram'."""
    name = (artifact_name or '').strip()
    if ' - ' in name:
        name = name.split(' - ', 1)[0]
    stripped = _TRAILING.sub('', name).strip()
    return stripped or name or 'Messages'


def _value(values, column):
    if not column:
        return None
    value = values.get(column)
    return None if value in (None, '') else value


_LATITUDE = ('latitude', 'lat')
_LONGITUDE = ('longitude', 'lon', 'lng', 'long')


def _location(values):
    """(latitude, longitude) when the row has both and they are a place
    (not 0, 0), else None."""
    found = {}
    for name, value in values.items():
        key = name.lower()
        for which, names in (('lat', _LATITUDE), ('lon', _LONGITUDE)):
            if key in names and value not in (None, ''):
                try:
                    found[which] = float(value)
                except (TypeError, ValueError):
                    pass
    if len(found) < 2 or (found['lat'] == 0 and found['lon'] == 0):
        return None
    if not (-90 <= found['lat'] <= 90 and -180 <= found['lon'] <= 180):
        return None
    return found['lat'], found['lon']


def _artifact_rows(database, media, artifact, view, report, run_id,
                   evidence_id, tool, name):
    app = app_name(name)
    types = {c['name']: c.get('type') for c in artifact['columns']}
    text_column = view.get('textColumn')
    sent_value = view.get('directionSentValue')
    owner = view.get('sentMessageStaticLabel') or DEVICE_OWNER
    out = []
    for count, (rowid, values) in enumerate(lava.iter_rows(database,
                                                           artifact)):
        if count >= MAX_ROWS_PER_ARTIFACT:
            logger.info("%s: chats past %d rows not read", name,
                        MAX_ROWS_PER_ARTIFACT)
            break
        direction = _value(values, view.get('directionColumn'))
        sent = direction is not None and sent_value is not None and \
            str(direction).strip().lower() == str(sent_value).strip().lower()
        sender = _value(values, view.get('senderColumn'))
        time_column = view.get('timeColumn')
        moment = _value(values, time_column)
        if moment is not None and types.get(time_column) == 'datetime':
            moment = lava.utc_text(moment)
        moment = str(moment).replace(' ', 'T') if moment is not None \
            else None
        thread = _value(values, view.get('conversationDiscriminatorColumn'))
        label = _value(values, view.get('conversationLabelColumn'))
        detail = {'direction': 'sent' if sent else 'received',
                  'chat id': str(thread if thread is not None else
                                 '(no thread)'),
                  'chat': str(label if label is not None else
                              thread if thread is not None else name),
                  'from': owner if sent else str(sender or ''),
                  'module': f"{tool} · {name}"}
        if direction is not None:
            detail['tool direction'] = str(direction)
        attachment = _value(values, view.get('mediaColumn'))
        if attachment is not None:
            item = media.get(attachment)
            if item is not None:
                detail['attachment'] = item['name'] or os.path.basename(
                    item['source_path'])
                if item.get('extraction_path'):
                    detail['attachment_file'] = os.path.normpath(
                        os.path.join(report, item['extraction_path']))
                detail['attachment_type'] = item.get('type') or ''
            else:
                detail['attachment'] = str(attachment)
        place = _location(values)
        if place is not None:
            detail['latitude'], detail['longitude'] = place
        text = _value(values, text_column)
        text = '' if text is None else str(text)
        # A message with no text is an attachment or a shared location:
        # say which (exports and Search read the text).
        if not text and 'attachment' in detail:
            text = f"[{detail['attachment']}]"
        elif not text and place is not None:
            text = f"[Location {place[0]:.6f}, {place[1]:.6f}]"
        out.append({
            'id': rowid, 'evidence_id': evidence_id,
            'category': 'communication', 'source': app,
            'time_utc': moment, 'local': 0,
            'what': 'Message sent' if sent else 'Message received',
            'subject': text, 'user': '', 'detail': detail,
            'source_path': lava.source_path(artifact, values, media),
            'source_ref': make_module_ref(run_id, artifact['tablename'],
                                          rowid),
            'artifact_ref': make_module_ref(run_id, artifact['tablename'],
                                            rowid)})
    return out
