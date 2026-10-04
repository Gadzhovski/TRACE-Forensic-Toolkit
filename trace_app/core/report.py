"""The case report: what was examined, how, and what was found.

One HTML generator serves both formats:

* **HTML** -- one self-contained file: styles inline, pictures as data: URIs,
  no scripts, nothing fetched. Opens in any browser, prints cleanly;
* **PDF** -- the same HTML laid out by PyMuPDF's Story on A4, with running
  header and footer ("Page n of m"), a table of contents with page numbers,
  clickable cross-references and a PDF outline.

Every value that came from evidence is HTML-escaped: a file named
``<script>`` is text in a report, never markup.

The examiner picks the sections and their options; ``default_options`` is
where a new report starts. Pictures (bookmarked files, carved photos) are
read from the images themselves through the ImageHandlers the caller opens,
scaled to fit -- never cropped -- and embedded. Nothing is written to disk
but the report, in the case's ``exports/`` folder, and its SHA-256 goes into
the audit trail.

No Qt here; it runs in the background job process (core/background.py).
"""

import base64
import datetime
import html
import io
import json
import logging
import os
import platform

from trace_app.core.case import (REPORTED_FINDING_GRADES, REPORTED_MISMATCHES,
                                 parse_artifact_ref)

logger = logging.getLogger('TRACE.Report')

#: (key, title, what it holds) in the default order.
SECTIONS = (
    ('summary', 'Case summary',
     "Case details, the examiner's summary and conclusions, and the counts "
     "of everything examined and found."),
    ('evidence', 'Evidence and verification',
     "Each image: its file, size and hashes, and every verification run "
     "against it."),
    ('bookmarks', 'Bookmarks and notes',
     "What the examiner marked, with notes and a picture of each "
     "bookmarked image."),
    ('findings', 'Findings',
     "Type mismatches, high entropy, hidden data, located photos, "
     "document authors, YARA matches and thumbnails of files gone."),
    ('hashes', 'Hash set matches',
     "Files matching known-bad and notable hash sets."),
    ('ntfs', 'NTFS: timestomping, downloads and streams',
     "Times set by hand, Mark of the Web, alternate data streams."),
    ('persistence', 'Persistence (autoruns)',
     "Everything set to start by itself, the suspicious and notable first, "
     "with the reasons."),
    ('keywords', 'Keyword hits',
     "Each keyword list's terms, how many files hold each, and the files "
     "with the first hit in context."),
    ('activity', 'User activity',
     "Programs run, files opened, USB devices, logons, web history -- the "
     "newest of each kind."),
    ('timeline', 'Timeline',
     "Events added to the report from the Timeline, and/or every event in "
     "a time range."),
    ('carved', 'Carved files', "Files recovered from unallocated space."),
    ('indicators', 'Indicators',
     "E-mail addresses, URLs, IPs and the rest, most widespread first."),
    ('virustotal', 'VirusTotal', "Every lookup and upload, as answered."),
    ('methods', 'Methods and tools',
     "TRACE and library versions, and which modules ran on each image."),
    ('audit', 'Appendix: audit trail',
     "Every action recorded in the case, in order."),
)
SECTION_TITLES = {key: title for key, title, _note in SECTIONS}

FORMATS = ('html', 'pdf')

_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'jpe', 'png', 'gif', 'bmp', 'tif',
                     'tiff', 'webp', 'heic', 'heif', 'avif'}
#: Largest picture read for a thumbnail.
MAX_PICTURE_BYTES = 40 * 1024 * 1024


class ReportCancelled(Exception):
    """The examiner stopped it."""


def default_options(case=None):
    """Where the report dialog starts."""
    return {
        'title': 'Forensic Examination Report',
        'case_name': case.name if case is not None else '',
        'case_number': case.number if case is not None else '',
        'examiner': case.examiner if case is not None else '',
        'organisation': '',
        'classification': '',
        'summary': '',
        'conclusions': '',
        'logo_path': '',
        'sections': [{'key': key, 'enabled': key not in (
            'indicators', 'virustotal', 'carved')} for key, _t, _n in
            SECTIONS],
        'formats': ['html', 'pdf'],
        'thumbnails': True,
        'thumbnail_size': 180,
        'findings_grade': 'notable',        # suspicious | notable | all
        'findings_limit': 200,
        'activity_limit': 50,
        'activity_categories': [],          # empty: every category
        'timeline_items': True,
        'timeline_range': False,
        'timeline_start': '',
        'timeline_end': '',
        'timeline_limit': 500,
        'timeline_sources': [],             # empty: the timeline's default
        'carved_limit': 200,
        'indicator_limit': 25,
        'audit_limit': 5000,
        'evidence_ids': None,               # None: every image
    }


# --- small builders ---------------------------------------------------------------

def e(value):
    return html.escape('' if value is None else str(value), quote=True)


def _size(value):
    value = value or 0
    for unit in ('bytes', 'KB', 'MB', 'GB', 'TB'):
        if value < 1024 or unit == 'TB':
            return f"{value:,.0f} {unit}" if unit == 'bytes' else \
                f"{value:,.1f} {unit}"
        value /= 1024
    return str(value)


def _table(headers, rows, widths=None, css=''):
    """An HTML table; `rows` are lists of already-escaped cell HTML."""
    if not rows:
        return "<p class='none'>None.</p>"
    # A column nothing in it fills (no referrer on any download) is left
    # out rather than printed empty down every page.
    keep = [0] + [i for i in range(1, len(headers))
                  if any(i < len(row) and row[i] not in ('', None)
                         for row in rows)]
    if len(keep) < len(headers):
        headers = [headers[i] for i in keep]
        rows = [[row[i] for i in keep] for row in rows]
    head = ''.join(f"<th>{e(h)}</th>" for h in headers)
    body = ''.join('<tr>' + ''.join(f"<td>{cell}</td>" for cell in row)
                   + '</tr>' for row in rows)
    return (f"<table class='data {css}'><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table>")


def _facts(pairs):
    rows = ''.join(f"<tr><th>{e(k)}</th><td>{v}</td></tr>"
                   for k, v in pairs if v not in (None, ''))
    return f"<table class='facts'>{rows}</table>"


def _badge(grade):
    grade = grade or ''
    return f"<span class='badge {e(grade)}'>{e(grade.capitalize())}</span>"


def _mono(value):
    return f"<span class='mono'>{e(value)}</span>"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# --- the report --------------------------------------------------------------------

class _Builder:
    def __init__(self, case, options, images, progress, should_stop):
        self.case = case
        self.options = options
        self.images = images or {}
        self.progress = progress
        self.should_stop = should_stop
        self.generated = _now()
        evidence = case.evidence()
        chosen = options.get('evidence_ids')
        self.evidence = [r for r in evidence
                         if chosen is None or r['id'] in chosen]
        self.names = {r['id']: r.get('display_name')
                      or os.path.basename(r['path']) for r in evidence}
        self.toc = []                  # (level, id, title)
        self.pictures = 0

    def scope(self, rows):
        ids = {r['id'] for r in self.evidence}
        return [r for r in rows if r.get('evidence_id') in ids
                or r.get('evidence_id') is None]

    def check(self):
        if self.should_stop and self.should_stop():
            raise ReportCancelled()

    def heading(self, level, anchor, title):
        self.toc.append((level, anchor, title))
        return f"<h{level} id='{e(anchor)}'>{e(title)}</h{level}>"

    def evidence_name(self, evidence_id):
        return self.names.get(evidence_id, '') if evidence_id is not None \
            else ''

    # --- pictures -------------------------------------------------------------

    def picture(self, evidence_id, ref, name, size=None, carved=None):
        """A data: URI thumbnail of a picture on an image, or ''."""
        if not self.options.get('thumbnails'):
            return ''
        handler = self.images.get(evidence_id)
        if handler is None:
            return ''
        try:
            if carved is not None:
                from trace_app.core.carving import read_carved
                if carved['size'] > MAX_PICTURE_BYTES:
                    return ''
                data = read_carved(handler.read, carved['offset'],
                                   carved['size'], carved.get('fragments'))
            else:
                parsed = parse_artifact_ref(ref)
                if parsed['kind'] != 'file':
                    return ''
                fs = handler.get_fs_info(parsed['start_offset'])
                entry = fs.open_meta(inode=parsed['inode'])
                length = int(entry.info.meta.size)
                # By content, not name: a browser cache keeps its pictures
                # with no extension at all.
                if not length or length > MAX_PICTURE_BYTES or \
                        not is_picture(entry.read_random(0, min(64, length))):
                    return ''
                data = entry.read_random(0, length)
        except Exception as exc:
            logger.debug("No picture for %s: %s", name, exc)
            return ''
        return thumbnail_uri(data, int(self.options.get('thumbnail_size')
                                       or 180))

    # --- sections ---------------------------------------------------------------

    def cover(self):
        o = self.options
        logo = ''
        logo_path = o.get('logo_path')
        if logo_path and os.path.exists(logo_path):
            try:
                with open(logo_path, 'rb') as handle:
                    logo = thumbnail_uri(handle.read(), 160, keep_format=True)
            except OSError:
                logo = ''
        parts = ["<div class='cover'>"]
        if o.get('classification'):
            parts.append(f"<p class='classification'>"
                         f"{e(o['classification'])}</p>")
        if logo:
            parts.append(f"<p class='logo'><img src='{logo}' "
                         f"alt='logo'/></p>")
        parts.append(f"<p class='report-title'>{e(o.get('title'))}</p>")
        parts.append(f"<p class='report-case'>{e(o.get('case_name'))}</p>")
        parts.append(_facts([
            ("Case number", e(o.get('case_number'))),
            ("Examiner", e(o.get('examiner'))),
            ("Organisation", e(o.get('organisation'))),
            ("Report generated", e(self.generated.strftime(
                '%Y-%m-%d %H:%M:%S UTC'))),
            ("Evidence", e(', '.join(self.names[r['id']]
                                     for r in self.evidence))),
            ("Produced with", e(f"TRACE {_trace_version()}")),
        ]))
        parts.append("</div>")
        return ''.join(parts)

    def section_summary(self):
        case = self.case
        out = [self.heading(1, 'summary', SECTION_TITLES['summary'])]
        if case.description:
            out.append(f"<p>{e(case.description)}</p>")
        if self.options.get('summary'):
            out.append(self.heading(2, 'summary-text', "Summary"))
            out.append(_paragraphs(self.options['summary']))
        if self.options.get('conclusions'):
            out.append(self.heading(2, 'conclusions', "Conclusions"))
            out.append(_paragraphs(self.options['conclusions']))
        out.append(self.heading(2, 'counts', "At a glance"))
        rows = []
        for row in self.evidence:
            evidence_id = row['id']
            summary = case.analysis_summary(evidence_id)
            ntfs = case.ntfs_counts(evidence_id)
            hashes = case.hash_match_counts(evidence_id)
            activity = sum(case.user_activity_summary(evidence_id).values())
            rows.append([
                e(self.names[evidence_id]),
                f"{summary['analysed']:,}",
                f"{summary['mismatches'] + summary['hidden']:,}",
                f"{ntfs['timestomp']:,}",
                f"{hashes.get('known-bad', 0):,}",
                f"{activity:,}",
                f"{summary['carved']:,}",
                f"{len(case.bookmarks(evidence_id)):,}",
            ])
        out.append(_table(['Evidence', 'Files analysed', 'Flagged files',
                           'Timestomped', 'Known bad', 'Activity records',
                           'Carved', 'Bookmarks'], rows, css='numbers'))
        return ''.join(out)

    def section_evidence(self):
        out = [self.heading(1, 'evidence', SECTION_TITLES['evidence'])]
        for row in self.evidence:
            self.check()
            anchor = f"evidence-{row['id']}"
            out.append(self.heading(2, anchor, self.names[row['id']]))
            out.append(_facts([
                ("File", _mono(row['path'])),
                ("Size", e(_size(row.get('size')))),
                ("Added to the case", e(row.get('added_utc'))),
                ("MD5", _mono(row.get('md5'))),
                ("SHA-1", _mono(row.get('sha1'))),
                ("SHA-256", _mono(row.get('sha256'))),
                ("MD5 stored in the image", _mono(row.get('stored_md5'))),
                ("SHA-1 stored in the image", _mono(row.get('stored_sha1'))),
                ("Last verification", e(row.get('last_status'))),
            ]))
            checks = list(reversed(self.case.verifications(row['id'],
                                                           limit=1000)))
            out.append("<p class='caption'>Verification history</p>")
            out.append(_table(
                ['When (UTC)', 'Algorithm', 'Result', 'Expected',
                 'Computed'],
                [[e(c.get('utc')), e(c.get('algorithm')),
                  _badge('clean' if c.get('status') == 'verified'
                         else 'suspicious') + ' ' + e(c.get('status')),
                  _mono(c.get('expected')), _mono(c.get('computed'))]
                 for c in checks], css='small'))
        return ''.join(out)

    def section_bookmarks(self):
        out = [self.heading(1, 'bookmarks', SECTION_TITLES['bookmarks'])]
        bookmarks = self.scope(self.case.bookmarks())
        notes = self.case.notes()
        by_bookmark, by_ref, loose = {}, {}, []
        for note in notes:
            if note.get('bookmark_id'):
                by_bookmark.setdefault(note['bookmark_id'], []).append(note)
            elif note.get('artifact_ref'):
                by_ref.setdefault((note.get('evidence_id'),
                                   note['artifact_ref']), []).append(note)
            else:
                loose.append(note)
        if not bookmarks:
            out.append("<p class='none'>No bookmarks.</p>")
        for evidence in self.evidence:
            mine = [b for b in reversed(bookmarks)
                    if b.get('evidence_id') == evidence['id']]
            if not mine:
                continue
            out.append(self.heading(2, f"bookmarks-{evidence['id']}",
                                    self.names[evidence['id']]))
            for number, bookmark in enumerate(mine, start=1):
                self.check()
                attached = by_bookmark.get(bookmark['id'], []) + by_ref.get(
                    (bookmark.get('evidence_id'), bookmark.get(
                        'artifact_ref')), [])
                picture = self.picture(bookmark.get('evidence_id'),
                                       bookmark.get('artifact_ref'),
                                       bookmark.get('artifact_name'))
                if picture:
                    self.pictures += 1
                body = [f"<p class='item-title'>{number}. "
                        f"{e(bookmark.get('label') or bookmark.get('artifact_name'))}"
                        "</p>"]
                body.append(_facts([
                    ("File", e(bookmark.get('artifact_name'))),
                    ("Path", _mono(bookmark.get('artifact_path'))),
                    ("Reference", _mono(bookmark.get('artifact_ref'))),
                    ("Bookmarked", e(bookmark.get('created_utc'))),
                ]))
                for note in attached:
                    body.append(f"<div class='note'><p class='note-meta'>"
                                f"Note, {e(note.get('created_utc'))}</p>"
                                f"{_paragraphs(note.get('body'))}</div>")
                if picture:
                    out.append(
                        "<table class='bookmark'><tr><td class='thumb'>"
                        f"<img src='{picture}' alt=''/></td><td>"
                        + ''.join(body) + "</td></tr></table>")
                else:
                    out.append("<div class='bookmark'>" + ''.join(body)
                               + "</div>")
        if loose:
            out.append(self.heading(2, 'notes', "Case notes"))
            for note in reversed(loose):
                out.append(f"<div class='note'><p class='note-meta'>"
                           f"{e(note.get('created_utc'))}</p>"
                           f"{_paragraphs(note.get('body'))}</div>")
        return ''.join(out)

    def _grades(self):
        threshold = self.options.get('findings_grade') or 'notable'
        if threshold == 'suspicious':
            return ('suspicious',)
        if threshold == 'all':
            return None
        return REPORTED_FINDING_GRADES

    def section_findings(self):
        out = [self.heading(1, 'findings', SECTION_TITLES['findings'])]
        limit = int(self.options.get('findings_limit') or 200)
        grades = self._grades()
        mismatch_grades = ('suspicious',) if grades == ('suspicious',) \
            else REPORTED_MISMATCHES
        groups = []
        mismatches = []
        for grade in mismatch_grades:
            mismatches += self.scope(self.case.type_mismatches(None,
                                                               grade=grade))
        groups.append(('findings-mismatch', 'Type mismatches',
                       ['File', 'Evidence', 'Claims', 'Content', 'Grade',
                        'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         e('.' + (r.get('extension') or '')),
                         e(r.get('mime')), _badge(r.get('mismatch')),
                         _mono(r.get('path'))] for r in mismatches]))
        entropy = self.scope(self.case.high_entropy_files(None))
        groups.append(('findings-entropy', 'High entropy',
                       ['File', 'Evidence', 'Entropy', 'Peak', 'Type',
                        'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         f"{r.get('entropy') or 0:.2f}",
                         f"{r.get('entropy_peak') or 0:.2f}",
                         e(r.get('mime')), _mono(r.get('path'))]
                        for r in entropy]))
        hidden = self.scope(self.case.findings(None, 'hidden', grades=grades,
                                               limit=limit + 1))
        groups.append(('findings-hidden', 'Hidden data',
                       ['File', 'Evidence', 'Grade', 'Finding', 'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         _badge(r.get('grade')), e(r.get('summary')),
                         _mono(r.get('path'))] for r in hidden]))
        photos = [r for r in self.scope(self.case.findings(
            None, 'photo', limit=100000)) if 'latitude' in (r.get('detail')
                                                            or {})]
        groups.append(('findings-photos', 'Photos with a location',
                       ['Photo', 'Evidence', 'Taken', 'Camera', 'Latitude',
                        'Longitude', 'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         e(r['detail'].get('taken')),
                         e(' '.join(p for p in (r['detail'].get('make'),
                                                r['detail'].get('model'))
                                    if p)),
                         f"{r['detail']['latitude']:.6f}",
                         f"{r['detail']['longitude']:.6f}",
                         _mono(r.get('path'))] for r in photos]))
        authors = self.scope(self.case.findings(None, 'authors',
                                                limit=limit + 1))
        groups.append(('findings-authors', 'Document authors',
                       ['Document', 'Evidence', 'Author', 'Last saved by',
                        'Application', 'Created', 'Modified'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         e((r.get('detail') or {}).get('author')),
                         e((r.get('detail') or {}).get('last_saved_by')),
                         e((r.get('detail') or {}).get('application')
                           or (r.get('detail') or {}).get('producer')),
                         e((r.get('detail') or {}).get('created')),
                         e((r.get('detail') or {}).get('modified'))]
                        for r in authors]))
        yara = self.scope(self.case.findings(None, 'yara', grades=grades,
                                             limit=limit + 1))
        groups.append(('findings-yara', 'YARA matches',
                       ['File', 'Evidence', 'Grade', 'Rule', 'Rule set',
                        'Matched', 'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         _badge(r.get('grade')),
                         e((r.get('detail') or {}).get('rule')),
                         e((r.get('detail') or {}).get('set')),
                         _mono('; '.join(
                             f"{s['identifier']}@{s['offset']}: {s['data']}"
                             for s in ((r.get('detail') or {}).get('strings')
                                       or [])[:5])),
                         _mono(r.get('path'))] for r in yara]))
        programs = self.scope(self.case.findings(
            None, 'executables', grades=grades, limit=limit + 1))
        groups.append(('findings-executables', 'Executables',
                       ['File', 'Evidence', 'Grade', 'Kind', 'Linked',
                        'Indicators', 'Path'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         _badge(r.get('grade')),
                         e(' '.join(p for p in (
                             (r.get('detail') or {}).get('format'),
                             (r.get('detail') or {}).get('architecture'),
                             (r.get('detail') or {}).get('kind')) if p)),
                         e((r.get('detail') or {}).get('compiled')),
                         e('; '.join(i['text'] for i in (
                             (r.get('detail') or {}).get('indicators')
                             or []))),
                         _mono(r.get('path'))] for r in programs]))
        detections = self.scope(self.case.findings(
            None, 'sigma', grades=grades, limit=limit + 1))
        groups.append(('findings-sigma', 'Event log detections (Sigma)',
                       ['Log', 'Evidence', 'Level', 'Rule', 'Time (UTC)',
                        'Event', 'Computer', 'ATT&CK'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         _badge(r.get('grade')),
                         e((r.get('detail') or {}).get('rule')),
                         e(((r.get('detail') or {}).get('time') or '')[:19]),
                         e(str((r.get('detail') or {}).get('event_id')
                               or '')),
                         e((r.get('detail') or {}).get('computer')),
                         e(', '.join((r.get('detail') or {}).get('attack')
                                     or []))] for r in detections]))
        gone = self.scope(self.case.findings(None, 'thumbnails',
                                             limit=limit + 1))
        groups.append(('findings-thumbnails',
                       'Thumbnails of files no longer in their folder',
                       ['File pictured', 'Evidence', 'Modified (catalog)',
                        'Finding', 'Thumbs.db'],
                       [[e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         e((r.get('detail') or {}).get('modified')),
                         e(r.get('summary')), _mono(r.get('path'))]
                        for r in gone]))
        for anchor, title, headers, rows in groups:
            self.check()
            out.append(self.heading(2, anchor, f"{title} ({len(rows):,})"))
            out.append(_limited(_table(headers, rows[:limit], css='small'),
                                len(rows), limit))
        return ''.join(out)

    def section_hashes(self):
        out = [self.heading(1, 'hashes', SECTION_TITLES['hashes'])]
        from trace_app.core.hashsets import CATEGORIES, case_options
        options = case_options(self.case)
        if not options.get('enabled'):
            out.append("<p class='none'>Hash sets were not used in this "
                       "case.</p>")
            return ''.join(out)
        rows = self.scope(self.case.hash_matches(None, ['known-bad',
                                                        'notable']))
        out.append(_table(
            ['File', 'Evidence', 'Category', 'Hash set', 'Matched by',
             'Digest', 'Path'],
            [[e(r.get('name')), e(self.evidence_name(r.get('evidence_id'))),
              _badge('suspicious' if r['category'] == 'known-bad'
                     else 'notable') + ' ' + e(CATEGORIES.get(
                         r['category'])),
              e(r.get('set_name')), e((r.get('algorithm') or '').upper()),
              _mono(r.get('digest')), _mono(r.get('path'))] for r in rows],
            css='small'))
        good = self.case.hash_match_counts().get('known-good', 0)
        if good:
            out.append(f"<p class='caption'>{good:,} file(s) matched "
                       f"known-good sets and are not listed.</p>")
        return ''.join(out)

    def section_ntfs(self):
        out = [self.heading(1, 'ntfs', SECTION_TITLES['ntfs'])]
        limit = int(self.options.get('findings_limit') or 200)
        stomped = self.scope(self.case.ntfs_rows('timestomp'))
        out.append(self.heading(2, 'ntfs-timestomp',
                                f"Timestomping ({len(stomped):,})"))
        out.append("<p class='caption'>$STANDARD_INFORMATION times can be "
                   "set by any program; $FILE_NAME times only by the file "
                   "system. Routine cases (installers) are left out.</p>")
        rows = []
        for r in stomped[:limit]:
            detail = r.get('detail') or {}
            si = detail.get('standard_information') or {}
            fn = detail.get('file_name') or {}
            rows.append([e(r.get('name')),
                         e(self.evidence_name(r.get('evidence_id'))),
                         _badge(r.get('grade')), e(r.get('summary')),
                         _mono(si.get('created')), _mono(fn.get('created')),
                         _mono(r.get('path'))])
        out.append(_limited(_table(['File', 'Evidence', 'Grade', 'Why',
                                    '$SI created', '$FN created', 'Path'],
                                   rows, css='small'), len(stomped), limit))
        streams = self.scope(self.case.ntfs_rows('streams',
                                                 include_routine=True))
        downloads = [r for r in streams if r.get('kind') == 'motw']
        hidden = [r for r in streams if r.get('kind') == 'ads'
                  and r.get('grade') != 'benign']
        out.append(self.heading(2, 'ntfs-downloads',
                                f"Downloaded files ({len(downloads):,})"))
        out.append(_limited(_table(
            ['File', 'Evidence', 'Zone', 'From', 'Referrer', 'Path'],
            [[e(r.get('name')), e(self.evidence_name(r.get('evidence_id'))),
              e((r.get('detail') or {}).get('zone')),
              _mono((r.get('detail') or {}).get('HostUrl')),
              _mono((r.get('detail') or {}).get('ReferrerUrl')),
              _mono(r.get('path'))] for r in downloads[:limit]],
            css='small'), len(downloads), limit))
        out.append(self.heading(2, 'ntfs-streams',
                                f"Alternate data streams ({len(hidden):,})"))
        out.append(_limited(_table(
            ['File', 'Evidence', 'Grade', 'Stream', 'Path'],
            [[e(r.get('name')), e(self.evidence_name(r.get('evidence_id'))),
              _badge(r.get('grade')), e(r.get('summary')),
              _mono(r.get('path'))] for r in hidden[:limit]], css='small'),
            len(hidden), limit))
        return ''.join(out)

    def section_persistence(self):
        out = [self.heading(1, 'persistence',
                            SECTION_TITLES['persistence'])]
        rows = self.scope(self.case.persistence(None, include_benign=False))
        routine = sum(self.case.persistence_counts(e['id']).get('benign', 0)
                      for e in self.evidence)
        out.append(_table(
            ['Grade', 'Where', 'Name', 'Starts', 'Why', 'File', 'User',
             'Evidence'],
            [[_badge(r.get('grade')), e(r.get('location')), e(r.get('name')),
              _mono(r.get('command')), e('; '.join(r.get('reasons') or [])),
              e({1: 'present', 0: 'missing'}.get(r.get('target_exists'),
                                                 '')),
              e(r.get('user')), e(self.evidence_name(r.get('evidence_id')))]
             for r in rows], css='small'))
        if routine:
            out.append(f"<p class='caption'>{routine:,} routine autostart(s) "
                       f"-- Windows' own services and drivers, signed "
                       f"updaters -- are not listed.</p>")
        return ''.join(out)

    def section_keywords(self):
        from trace_app.core.keywords import KIND_LABELS, term_summary
        out = [self.heading(1, 'keywords', SECTION_TITLES['keywords'])]
        findings = self.scope(self.case.findings(None, 'keywords',
                                                 limit=500000))
        if not findings:
            out.append("<p class='none'>No keyword list found anything, or "
                       "none was searched for.</p>")
            return ''.join(out)
        limit = int(self.options.get('findings_limit') or 200)
        terms = term_summary(findings)
        out.append(_table(
            ['Term', 'List', 'Type', 'Grade', 'Files', 'Hits', 'Note'],
            [[_mono(t['term']), e(t['list']),
              e(KIND_LABELS.get(t['term_kind'], t['term_kind'])),
              _badge(t['grade']),
              f"{t['files']:,}{'+' if t['truncated'] else ''}",
              f"{t['hits']:,}", e(t['note'])] for t in terms], css='small'))
        for number, term in enumerate(terms, 1):
            self.check()
            rows = sorted(
                (f for f in findings
                 if (f.get('detail') or {}).get('list_id') == term['list_id']
                 and (f.get('detail') or {}).get('term') == term['term']),
                key=lambda f: -int((f.get('detail') or {}).get('hits') or 0))
            out.append(self.heading(
                2, f"keywords-{number}",
                f"\u201c{term['term']}\u201d \u2014 {term['list']} "
                f"({len(rows):,} file(s))"))
            out.append(_limited(_table(
                ['File', 'Evidence', 'Hits', 'Context', 'Path'],
                [[e(r.get('name')),
                  e(self.evidence_name(r.get('evidence_id'))),
                  f"{int((r.get('detail') or {}).get('hits') or 0):,}",
                  e((r.get('detail') or {}).get('excerpt')),
                  _mono(r.get('path'))] for r in rows[:limit]],
                css='small'), len(rows), limit))
        return ''.join(out)

    def section_activity(self):
        from trace_app.core.activity import CATEGORIES
        out = [self.heading(1, 'activity', SECTION_TITLES['activity'])]
        limit = int(self.options.get('activity_limit') or 50)
        chosen = self.options.get('activity_categories') or [
            key for key, _label in CATEGORIES]
        any_rows = False
        for key, label in CATEGORIES:
            if key not in chosen:
                continue
            self.check()
            rows = self.scope(self.case.user_activity(None, key))
            if not rows:
                continue
            any_rows = True
            out.append(self.heading(2, f"activity-{key}",
                                    f"{label} ({len(rows):,})"))
            out.append(_limited(_table(
                ['Time (UTC)', 'What', 'Subject', 'User', 'Source',
                 'Evidence'],
                [[e(f"{r.get('time_utc') or ''}"
                    + (' (local)' if r.get('time_local') else '')),
                  e(r.get('what')), _mono(r.get('subject')),
                  e(r.get('user')), e(r.get('source')),
                  e(self.evidence_name(r.get('evidence_id')))]
                 for r in rows[:limit]], css='small'), len(rows), limit))
        if not any_rows:
            out.append("<p class='none'>No activity was read.</p>")
        return ''.join(out)

    def section_timeline(self):
        from trace_app.core import timeline
        out = [self.heading(1, 'timeline', SECTION_TITLES['timeline'])]
        if self.options.get('timeline_items', True):
            items = self.scope(self.case.report_items('timeline'))
            out.append(self.heading(2, 'timeline-picked',
                                    f"Events selected by the examiner "
                                    f"({len(items):,})"))
            out.append(_table(
                ['Time', 'Source', 'Event', 'Path / subject', 'User',
                 'Evidence'],
                [[e(i.get('time_utc') or '')
                  + (' (local)' if (i.get('detail') or {}).get('local')
                     else ''),
                  e(timeline.SOURCE_LABELS.get((i.get('detail') or {})
                                               .get('source'), '')),
                  e(i.get('title')),
                  _mono((i.get('detail') or {}).get('subject')),
                  e((i.get('detail') or {}).get('user')),
                  e(self.evidence_name(i.get('evidence_id')))]
                 for i in items], css='small'))
        if self.options.get('timeline_range'):
            filters = timeline.default_filters()
            if self.options.get('timeline_sources'):
                filters['sources'] = list(self.options['timeline_sources'])
            filters['start'] = self.options.get('timeline_start') or None
            filters['end'] = self.options.get('timeline_end') or None
            if len(self.evidence) == 1:
                filters['evidence_id'] = self.evidence[0]['id']
            limit = int(self.options.get('timeline_limit') or 500)
            connection = self.case._db
            total = timeline.count(connection, filters)
            rows = timeline.events(connection, filters, limit)
            span = ' to '.join(v for v in (filters['start'],
                                           filters['end']) if v)
            out.append(self.heading(2, 'timeline-range',
                                    f"Every event {('from ' + span) if span else ''}"
                                    f" ({total:,})"))
            out.append(_limited(_table(
                ['Time', 'Source', 'Type', 'Description', 'Path / subject',
                 'Evidence'],
                [["<span class='dot' style='color:"
                  f"{timeline.SOURCE_COLOURS.get(r['source'])}'>&#9679;"
                  f"</span> {e(r['time'])}"
                  + (' (local)' if r['local'] else ''),
                  e(timeline.SOURCE_LABELS.get(r['source'])),
                  e(timeline.describe_kind(r)), e(r['title'] or ''),
                  _mono(r['subject']),
                  e(self.evidence_name(r['evidence_id']))] for r in rows],
                css='small'), total, limit))
        return ''.join(out)

    def section_carved(self):
        out = [self.heading(1, 'carved', SECTION_TITLES['carved'])]
        limit = int(self.options.get('carved_limit') or 200)
        from trace_app.core.carve_verify import STATUS_LABELS
        rows = self.scope(self.case.carved_files(None))
        states = {}
        for row in rows:
            states[row.get('status')] = states.get(row.get('status'), 0) + 1
        named = sum(1 for row in rows if row.get('origin'))
        counts = {}
        for row in rows:
            if row.get('sha256'):
                counts[row['sha256']] = counts.get(row['sha256'], 0) + 1
        copies = sum(n - 1 for n in counts.values() if n > 1)
        summary = ', '.join(f"{states[k]:,} {STATUS_LABELS[k].lower()}"
                            for k in ('complete', 'valid', 'reconstructed',
                                      'partial')
                            if states.get(k))
        out.append(f"<p class='caption'>{len(rows):,} file(s) carved"
                   + (f": {summary}" if summary else '')
                   + (f"; {named:,} named from the deleted file-system "
                      f"entry they began at" if named else '')
                   + (f"; {copies:,} identical copies" if copies else '')
                   + ". Complete: every check passed and the format's own "
                     "checksums prove the file whole. Valid: every check "
                     "passed; the format has nothing that could prove no "
                     "foreign data is inside. Reconstructed: rebuilt from "
                     "fragments a checksum proved. Partial: a check failed."
                     "</p>")
        for run in self.case.carving_runs(None, limit=20):
            if self.evidence and run['evidence_id'] not in \
                    {e_['id'] for e_ in self.evidence}:
                continue
            stats = run.get('stats') or {}
            candidates = sum((stats.get('candidates') or {}).values())
            rejected = sum((stats.get('rejected') or {}).values())
            out.append(
                f"<p class='caption'>Run {run['id']} on "
                f"{e(self.evidence_name(run['evidence_id']))} "
                f"({e(run['status'])}, {e(run.get('started_utc'))} UTC): "
                f"{e((run.get('settings') or {}).get('source'))}, "
                f"{candidates:,} signature hits checked, {run['found']:,} "
                f"kept, {rejected:,} rejected. {e(run.get('engine'))}.</p>")
        table = []
        for row in rows[:limit]:
            self.check()
            picture = ''
            if (row.get('type') or '').lower() in _IMAGE_EXTENSIONS:
                picture = self.picture(row.get('evidence_id'), None,
                                       row.get('name'), carved=row)
                if picture:
                    self.pictures += 1
            failed = [text for ok, text in row.get('checks') or []
                      if ok is False]
            status = STATUS_LABELS.get(row.get('status'), 'Not checked')
            if failed:
                status += ': ' + '; '.join(failed)
            table.append([
                f"<img class='small-thumb' src='{picture}' alt=''/>"
                if picture else '',
                e(row.get('name')), e(self.evidence_name(row.get(
                    'evidence_id'))), e((row.get('type') or '').upper()),
                e(status), e((row.get('origin') or {}).get('path')),
                f"{row.get('offset') or 0:,}", e(_size(row.get('size'))),
                e(row.get('embedded_date')), _mono(row.get('sha256'))])
        out.append(_limited(_table(['', 'File', 'Evidence', 'Type', 'Status',
                                    'Was', 'Offset', 'Size', 'Date inside',
                                    'SHA-256'],
                                   table, css='small'), len(rows), limit))
        return ''.join(out)

    def section_indicators(self):
        out = [self.heading(1, 'indicators', SECTION_TITLES['indicators'])]
        try:
            from trace_app.core.search_index import SearchIndex
            index = SearchIndex(self.case.folder)
        except Exception as exc:
            out.append(f"<p class='none'>No search index ({e(exc)}).</p>")
            return ''.join(out)
        try:
            from trace_app.core.search_index import INDICATOR_KINDS
            summary = index.indicator_summary(None)
            limit = int(self.options.get('indicator_limit') or 25)
            if not summary:
                out.append("<p class='none'>No indicators were extracted "
                           "(the search index was not built).</p>")
            for kind in INDICATOR_KINDS:
                if not summary.get(kind):
                    continue
                values = index.indicators(kind, limit=limit)
                out.append(self.heading(
                    2, f"indicators-{kind}",
                    f"{kind.replace('_', ' ').capitalize()} "
                    f"({summary[kind]:,})"))
                out.append(_limited(_table(
                    ['Value', 'Items holding it'],
                    [[_mono(v['value']), f"{v['files']:,}"]
                     for v in values], css='small'), summary[kind], limit))
        finally:
            index.close()
        return ''.join(out)

    def section_virustotal(self):
        out = [self.heading(1, 'virustotal', SECTION_TITLES['virustotal'])]
        rows = self.scope(self.case.vt_results(None, limit=5000))
        out.append(_table(
            ['File', 'Evidence', 'Method', 'Result', 'Detections',
             'Scanned', 'Asked (UTC)', 'SHA-256'],
            [[e(r.get('name')), e(self.evidence_name(r.get('evidence_id'))),
              e(r.get('method')), e(r.get('status')),
              e(f"{r.get('positives')}/{r.get('total')}"
                if r.get('total') else ''), e(r.get('scan_date')),
              e(r.get('queried_utc')), _mono(r.get('sha256'))]
             for r in rows], css='small'))
        return ''.join(out)

    def section_methods(self):
        out = [self.heading(1, 'methods', SECTION_TITLES['methods'])]
        out.append("<p>The evidence was opened read-only; nothing was "
                   "written to it. Files were read in place from the images "
                   "and nothing was extracted to disk to be examined. Times "
                   "are UTC unless marked local (the source stored no time "
                   "zone).</p>")
        out.append(self.heading(2, 'methods-tools', "Software"))
        out.append(_table(['Component', 'Version'],
                          [[e(name), _mono(version)]
                           for name, version in tool_versions()]))
        out.append(self.heading(2, 'methods-runs', "What ran on each image"))
        rows = []
        for evidence in self.evidence:
            evidence_id = evidence['id']
            name = e(self.names[evidence_id])
            state = self.case.analysis_state(evidence_id)
            if state:
                rows.append([name, "File analysis (" + e(
                    state.get('modules') or '') + ")",
                    e(state.get('status')),
                    e(f"{state.get('files_done') or 0:,} files"),
                    e(state.get('updated_utc'))])
            state = self.case.ntfs_state(evidence_id)
            if state:
                rows.append([name, "NTFS $MFT and change journal",
                             e(state.get('status')),
                             e(f"{state.get('entries') or 0:,} entries, "
                               f"{state.get('journal') or 0:,} journal "
                               "records"), e(state.get('updated_utc'))])
            state = self.case.user_activity_state(evidence_id)
            if state:
                rows.append([name, "Windows activity and browser history",
                             e(state.get('status')),
                             e(f"{state.get('records') or 0:,} records"),
                             e(state.get('updated_utc'))])
            state = self.case.carving_state(evidence_id) \
                if hasattr(self.case, 'carving_state') else None
            if state:
                rows.append([name, "File carving", e(state.get('status')),
                             e(f"{state.get('found') or 0:,} files"),
                             e(state.get('updated_utc'))])
        out.append(_table(['Evidence', 'Module', 'Status', 'Result',
                           'Finished (UTC)'], rows, css='small'))
        return ''.join(out)

    def section_audit(self):
        out = [self.heading(1, 'audit', SECTION_TITLES['audit'])]
        limit = int(self.options.get('audit_limit') or 5000)
        rows = list(reversed(self.case.activity(limit=limit)))
        out.append(_table(['When (UTC)', 'Action', 'Detail'],
                          [[e(r.get('utc')), e(r.get('action')),
                            e(r.get('detail'))] for r in rows],
                          css='small audit'))
        return ''.join(out)

    # --- the whole -----------------------------------------------------------------

    def body(self):
        sections = [s for s in self.options.get('sections') or []
                    if s.get('enabled')]
        parts = [self.cover(), "<div class='toc-holder'>{{TOC}}</div>"]
        for done, section in enumerate(sections):
            self.check()
            key = section['key']
            builder = getattr(self, f"section_{key}", None)
            if builder is None:
                continue
            if self.progress:
                self.progress(done, len(sections),
                              SECTION_TITLES.get(key, key))
            parts.append(f"<div class='section'>{builder()}</div>")
        return ''.join(parts)


def _paragraphs(text):
    return ''.join(f"<p>{e(line)}</p>" for line in (text or '').split('\n')
                   if line.strip())


def _limited(table, total, limit):
    if total > limit:
        return table + (f"<p class='caption'>The first {limit:,} of "
                        f"{total:,} are listed.</p>")
    return table


def _toc(entries, pages=None):
    items = []
    for level, anchor, title in entries:
        if level > 2:
            continue
        page = ''
        if pages is not None:
            number = pages.get(anchor)
            page = f"<span class='toc-page'>{number}</span>" \
                if number else ''
        items.append(f"<tr class='toc{level}'><td><a href='#{e(anchor)}'>"
                     f"{e(title)}</a></td><td class='toc-num'>{page}</td>"
                     f"</tr>")
    return ("<p class='toc-title'>Contents</p><table class='toc'>"
            + ''.join(items) + "</table>")


def is_picture(head):
    """Does a file start the way a picture Pillow reads does?"""
    head = head or b''
    return (head[:3] == b'\xff\xd8\xff' or head[:8] == b'\x89PNG\r\n\x1a\n'
            or head[:6] in (b'GIF87a', b'GIF89a') or head[:2] == b'BM'
            or head[:4] in (b'II*\x00', b'MM\x00*')
            or (head[:4] == b'RIFF' and head[8:12] == b'WEBP')
            or (head[4:8] == b'ftyp' and head[8:12] in (
                b'heic', b'heix', b'mif1', b'msf1', b'avif', b'heim')))


def thumbnail_uri(data, size, keep_format=False):
    """A picture scaled to fit `size` pixels (never cropped), as a data:
    URI; '' if it is not a picture Pillow can read."""
    try:
        from PIL import Image, ImageOps
        image = Image.open(io.BytesIO(data))
        image.load()
        image = ImageOps.exif_transpose(image)
        image.thumbnail((size, size))
        out = io.BytesIO()
        if keep_format and image.mode in ('RGBA', 'LA', 'P'):
            image.save(out, 'PNG')
            kind = 'png'
        else:
            image.convert('RGB').save(out, 'JPEG', quality=82)
            kind = 'jpeg'
    except Exception:
        return ''
    return f"data:image/{kind};base64," + base64.b64encode(
        out.getvalue()).decode('ascii')


def _trace_version():
    try:
        from trace_app import __version__
        return __version__
    except ImportError:
        return 'unknown'


def tool_versions():
    """[(component, version)] of what read the evidence."""
    out = [('TRACE', _trace_version()),
           ('Python', platform.python_version()),
           ('Operating system', f"{platform.system()} {platform.release()} "
                                f"({platform.machine()})")]
    probes = (
        ('The Sleuth Kit (pytsk3)', lambda: __import__('pytsk3')
         .TSK_VERSION_STR),
        ('libewf', lambda: __import__('pyewf').get_version()),
        ('libvmdk', lambda: __import__('pyvmdk').get_version()),
        ('libvhdi', lambda: __import__('pyvhdi').get_version()),
        ('libqcow', lambda: __import__('pyqcow').get_version()),
        ('libbde', lambda: __import__('pybde').get_version()),
        ('libvshadow', lambda: __import__('pyvshadow').get_version()),
        ('libpff', lambda: __import__('pypff').get_version()),
        ('PyMuPDF', lambda: __import__('pymupdf').VersionBind),
        ('Pillow', lambda: __import__('PIL').__version__),
    )
    for name, probe in probes:
        try:
            out.append((name, str(probe())))
        except Exception:
            continue
    try:
        from trace_app.infra.preflight import libmagic_identity
        identity = libmagic_identity()
        if identity:
            out.append(('libmagic', str(identity.get('version')
                                        if isinstance(identity, dict)
                                        else identity)))
    except Exception:
        pass
    return out


# --- styles -----------------------------------------------------------------------

_CSS_COMMON = """
body { font-family: "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
       color: #1f2328; font-size: 10pt; line-height: 1.4; }
h1 { font-size: 17pt; color: #0b3d63; border-bottom: 2px solid #0b3d63;
     padding-bottom: 3px; margin: 22pt 0 8pt 0; }
h2 { font-size: 12.5pt; color: #0b3d63; margin: 14pt 0 5pt 0; }
p { margin: 3pt 0 6pt 0; }
table { border-collapse: collapse; }
table.data { width: 100%; margin: 4pt 0 10pt 0; }
table.data th { background-color: #e9eef4; color: #0b3d63; text-align: left;
                font-weight: bold; padding: 3pt 5pt;
                border-bottom: 1px solid #b8c4d1; }
table.data td { padding: 2.5pt 5pt; border-bottom: 1px solid #e3e7ec;
                vertical-align: top; }
table.small td, table.small th { font-size: 8.5pt; }
table.facts th { text-align: left; color: #57606a; font-weight: normal;
                 padding: 1.5pt 12pt 1.5pt 0; vertical-align: top; }
table.facts td { padding: 1.5pt 0; }
.mono { font-family: Consolas, "DejaVu Sans Mono", monospace;
        font-size: 8.5pt; }
.badge { font-weight: bold; }
.badge.suspicious { color: #b42318; }
.badge.notable { color: #b45309; }
.badge.benign, .badge.clean { color: #1a7f37; }
.caption { color: #57606a; font-size: 8.5pt; }
.none { color: #57606a; font-style: italic; }
.cover { margin-bottom: 18pt; }
.report-title { font-size: 24pt; font-weight: bold; color: #0b3d63;
                margin: 10pt 0 2pt 0; }
.report-case { font-size: 15pt; color: #1f2328; margin: 0 0 12pt 0; }
.classification { color: #b42318; font-weight: bold; font-size: 11pt;
                  border: 1.5px solid #b42318; padding: 3pt 6pt;
                  text-align: center; }
.toc-title { font-size: 14pt; font-weight: bold; color: #0b3d63;
             margin-top: 14pt; }
table.toc { width: 100%; }
table.toc td { padding: 1.5pt 0; }
tr.toc2 td { padding-left: 14pt; font-size: 9pt; color: #57606a; }
td.toc-num { text-align: right; width: 40pt; }
.item-title { font-weight: bold; font-size: 10.5pt; margin-top: 6pt; }
.note { border-left: 3px solid #b8c4d1; padding: 2pt 0 2pt 8pt;
        margin: 4pt 0 6pt 0; }
.note-meta { color: #57606a; font-size: 8.5pt; margin: 0; }
table.bookmark { width: 100%; margin: 6pt 0 10pt 0;
                 border-bottom: 1px solid #e3e7ec; }
table.bookmark td { vertical-align: top; padding: 2pt 8pt 6pt 0; }
td.thumb { width: 150pt; }
td.thumb img { max-width: 140pt; }
img.small-thumb { max-width: 64px; max-height: 64px; }
a { color: #0b3d63; text-decoration: none; }
"""

_CSS_SCREEN = """
body { max-width: 1100px; margin: 0 auto; padding: 28px 36px 60px 36px;
       background: #ffffff; }
.cover { border-bottom: 3px solid #0b3d63; padding-bottom: 14px; }
.logo img { max-height: 90px; }
.section { page-break-before: always; }
table.data tbody tr:nth-child(even) td { background-color: #f6f8fa; }
@media print {
  body { max-width: none; padding: 0; }
  a { color: inherit; }
  tr { page-break-inside: avoid; }
  thead { display: table-header-group; }
}
@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
"""

#: MuPDF's layout engine reads a subset of CSS; keep to it.
_CSS_PDF = """
.section { page-break-before: always; }
.logo img { height: 70px; }
table.data th { background-color: transparent;
                border-bottom: 1.5px solid #0b3d63; }
"""


def build_html(case, options, images=None, progress=None,
               should_stop=None):
    """(html text, builder) -- the screen/print HTML report."""
    builder = _Builder(case, options, images, progress, should_stop)
    body = builder.body()
    title = e(f"{options.get('title')} — {options.get('case_name')}")
    page = (f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='generator' content='TRACE {e(_trace_version())}'>"
            f"<title>{title}</title><style>{_CSS_COMMON}{_CSS_SCREEN}"
            f"</style></head><body>"
            f"{body.replace('{{TOC}}', _toc(builder.toc))}"
            f"<p class='caption'>Generated by TRACE {e(_trace_version())} "
            f"on {e(builder.generated.strftime('%Y-%m-%d %H:%M:%S UTC'))}."
            f"</p></body></html>")
    return page, builder, body


def write_pdf(builder, body, path):
    """The PDF: two layout passes, so the contents carry page numbers."""
    import pymupdf
    css = _CSS_COMMON + _CSS_PDF

    def lay_out(content, output):
        story = pymupdf.Story(html=content, user_css=css)
        writer = pymupdf.DocumentWriter(output)
        mediabox = pymupdf.paper_rect('a4')
        where = mediabox + (42, 58, -42, -58)
        positions = []
        page = 0
        more = True
        while more:
            device = writer.begin_page(mediabox)
            more, _ = story.place(where)
            # add_pdf_links reads `page_num`, counted from 1.
            story.element_positions(lambda p: positions.append(p),
                                    {'page_num': page + 1})
            story.draw(device)
            writer.end_page()
            page += 1
        writer.close()
        return story, positions

    def heading_pages(positions):
        pages = {}
        for position in positions:
            if position.heading and position.id and position.open_close & 1:
                pages.setdefault(position.id, position.page_num)
        return pages

    # Pass one: where does each heading land? Pass two: the same layout
    # with those numbers in the contents (same length, same pages).
    first = io.BytesIO()
    _story, positions = lay_out(body.replace('{{TOC}}', _toc(
        builder.toc, {anchor: 999 for _l, anchor, _t in builder.toc})),
        first)
    pages = heading_pages(positions)
    second = io.BytesIO()
    story, positions = lay_out(body.replace('{{TOC}}', _toc(builder.toc,
                                                            pages)), second)
    document = pymupdf.open('pdf', second.getvalue())
    try:
        story.add_pdf_links(document, positions)
    except Exception as exc:
        logger.debug("Contents links not added: %s", exc)
    pages = heading_pages(positions)
    titles = {anchor: (level, title) for level, anchor, title in builder.toc}
    outline = [[titles[a][0], titles[a][1], pages[a]]
               for _l, a, _t in builder.toc if a in pages]
    # A PDF outline cannot jump from level 1 to 3; ours never does.
    document.set_toc(outline)
    options = builder.options
    total = document.page_count
    left = ' - '.join(p for p in (options.get('case_name'),
                                  options.get('case_number')) if p)
    stamp = builder.generated.strftime('%Y-%m-%d %H:%M UTC')
    classification = options.get('classification') or ''
    for number, page in enumerate(document, start=1):
        width = page.rect.width
        grey = (0.35, 0.38, 0.42)
        page.insert_text((42, 34), _pdf_text(options.get('title') or ''),
                         fontsize=8, color=grey)
        if classification:
            label = _pdf_text(classification)
            text_width = pymupdf.get_text_length(label, fontsize=8)
            page.insert_text((width - 42 - text_width, 34), label,
                             fontsize=8, color=(0.7, 0.14, 0.1))
        page.draw_line((42, 40), (width - 42, 40), color=(0.72, 0.77, 0.82),
                       width=0.6)
        bottom = page.rect.height - 30
        page.draw_line((42, bottom - 10), (width - 42, bottom - 10),
                       color=(0.72, 0.77, 0.82), width=0.6)
        page.insert_text((42, bottom), _pdf_text(left), fontsize=8,
                         color=grey)
        right = f"Page {number} of {total}  -  {stamp}"
        text_width = pymupdf.get_text_length(right, fontsize=8)
        page.insert_text((width - 42 - text_width, bottom), right,
                         fontsize=8, color=grey)
    document.set_metadata({
        'title': f"{options.get('title')} - {options.get('case_name')}",
        'author': options.get('examiner') or '',
        'subject': options.get('case_number') or '',
        'creator': f"TRACE {_trace_version()}",
        'producer': f"TRACE {_trace_version()} / PyMuPDF",
    })
    document.save(path, garbage=3, deflate=True)
    document.close()
    return total


_PLAIN = str.maketrans({'\u2014': '-', '\u2013': '-', '\u2018': "'",
                        '\u2019': "'", '\u201c': '"', '\u201d': '"',
                        '\u2026': '...', '\u00b7': '-', '\u25b8': '>'})


def _pdf_text(text):
    """Base-14 Helvetica covers Latin-1: dashes and quotes become their
    plain forms, anything else past it a '?' rather than nothing."""
    return (text or '').translate(_PLAIN).encode(
        'latin-1', 'replace').decode('latin-1')


# --- writing --------------------------------------------------------------------

def write_report(case, options, images=None, progress=None,
                 should_stop=None, folder=None):
    """Write the report in each chosen format. Returns
    [{'format', 'path', 'sha256', 'pages'}] and records each in the audit
    trail."""
    import hashlib
    folder = folder or os.path.join(case.folder, 'exports')
    os.makedirs(folder, exist_ok=True)
    stamp = _now().strftime('%Y%m%d-%H%M%S')
    base = os.path.join(folder, f"report-{stamp}")
    page, builder, body = build_html(case, options, images, progress,
                                     should_stop)
    written = []
    formats = [f for f in options.get('formats') or FORMATS if f in FORMATS]
    if 'html' in formats:
        path = base + '.html'
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(page)
        written.append({'format': 'html', 'path': path, 'pages': None})
    if 'pdf' in formats:
        if should_stop and should_stop():
            raise ReportCancelled()
        if progress:
            progress(1, 1, 'Laying out the PDF')
        path = base + '.pdf'
        pages = write_pdf(builder, body, path)
        written.append({'format': 'pdf', 'path': path, 'pages': pages})
    for item in written:
        digest = hashlib.sha256()
        with open(item['path'], 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        item['sha256'] = digest.hexdigest()
        sections = ','.join(s['key'] for s in options.get('sections') or []
                            if s.get('enabled'))
        case.record_event(
            'report created',
            f"{os.path.basename(item['path'])} sha256={item['sha256']} "
            f"sections={sections}" + (f" pages={item['pages']}"
                                      if item['pages'] else ''))
    logger.info("Report written: %s", ', '.join(i['path'] for i in written))
    return written


def save_template(options, path):
    """The examiner's choices (not the case's text) for another case."""
    keep = {k: v for k, v in options.items()
            if k not in ('case_name', 'case_number', 'summary',
                         'conclusions', 'evidence_ids', 'timeline_start',
                         'timeline_end')}
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(keep, handle, indent=2)


def load_template(path, case=None):
    options = default_options(case)
    with open(path, encoding='utf-8') as handle:
        stored = json.load(handle)
    known = {s['key'] for s in options['sections']}
    options.update({k: v for k, v in stored.items() if k in options})
    sections = [s for s in options['sections'] if s.get('key') in known]
    missing = [{'key': k, 'enabled': False} for k in
               (key for key, _t, _n in SECTIONS)
               if k not in {s['key'] for s in sections}]
    options['sections'] = sections + missing
    return options

