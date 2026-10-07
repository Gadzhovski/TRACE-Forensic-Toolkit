import datetime

import pytsk3
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (QLabel, QPlainTextEdit, QScrollArea, QSizePolicy,
                               QVBoxLayout, QWidget)

from trace_app.infra.constants import UNKNOWN_DATE
from trace_app.core import content_checks
from trace_app.ui.widgets.property_table import PropertyTable
import hashlib
from magic import Magic


class MetadataViewer(QWidget):
    def __init__(self, image_handler):
        super(MetadataViewer, self).__init__()
        self.image_handler = image_handler
        self.init_ui()

    def set_image_handler(self, image_handler):
        """Point this viewer at a newly loaded image."""
        self.image_handler = image_handler

    def init_ui(self):
        """One scrolling surface, not two.

        This pane used to stack a property table above a text view inside a
        splitter. In a dock only ~160px tall that gave each of them its own
        cramped scroll area -- 13 rows of properties squeezed into three rows
        of visible space, with the low-level dump scrolling separately below.

        Both now sit inside a single scroll area and grow to their full
        content height, so there is one scrollbar for the whole pane and
        everything reads top to bottom.
        """
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.scroll = QScrollArea(self)
        self.scroll.setObjectName("metadataScroll")
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        content = QWidget()
        content.setObjectName("metadataContent")
        inner = QVBoxLayout(content)
        inner.setContentsMargins(12, 10, 12, 12)
        inner.setSpacing(0)

        # Properties. A real table rather than generated HTML, so it follows
        # the theme and an examiner can select and copy a hash.
        self.property_table = PropertyTable("Property", "Value", content)
        # Not AdjustToContents: that sizes the table to its content width, so
        # the value column stayed about 100px and elided almost every value
        # while the rest of the pane sat empty. The table fills the pane and
        # the stretching value column takes whatever the labels do not.
        self.property_table.setSizePolicy(QSizePolicy.Expanding,
                                          QSizePolicy.Fixed)
        self.property_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.property_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner.addWidget(self.property_table)

        self.details_heading = QLabel("Filesystem detail", content)
        self.details_heading.setObjectName("detailHeading")
        inner.addWidget(self.details_heading)

        # Low-level output is preformatted text, so it stays a text view -- but
        # a themed, monospaced one rather than an HTML <pre>.
        self.details_view = QPlainTextEdit(content)
        self.details_view.setObjectName("monoDetailView")
        self.details_view.setReadOnly(True)
        self.details_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.details_view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.details_view.setFrameShape(QPlainTextEdit.NoFrame)
        inner.addWidget(self.details_view)

        inner.addStretch(1)
        self.scroll.setWidget(content)
        layout.addWidget(self.scroll)

    def _fit_to_contents(self):
        """Size the table and text view to their content.

        Both are inside the shared scroll area, so they must report their full
        height rather than provide their own scrollbars.
        """
        table = self.property_table
        height = sum(table.rowHeight(r) for r in range(table.rowCount()))
        table.setFixedHeight(height + 2 * table.frameWidth())

        if not self.details_view.isVisible():
            # A hidden view still reports a line of text, so sizing it left a
            # block of empty space below the properties for every file with no
            # low-level detail.
            self.details_view.setFixedHeight(0)
            return

        document = self.details_view.document()
        document.setTextWidth(-1)
        lines = max(1, document.blockCount())
        line_height = QFontMetrics(self.details_view.font()).lineSpacing()
        self.details_view.setFixedHeight(lines * line_height + 12)

    def display_metadata(self, data):
        """Populate the pane for the selected file."""
        is_carved = data.get('is_carved', False)
        file_content = data.get('file_content')

        if is_carved and file_content:
            # Carved file: no filesystem metadata is available for it.
            metadata = None
        else:
            inode_number = data.get('inode_number')
            offset = data.get('start_offset')
            file_content, metadata = self.image_handler.get_file_content(inode_number, offset)

            if metadata is None:
                self.property_table.set_rows([("Status", "No metadata available.")])
                self.details_view.clear()
                self.details_view.setVisible(False)
                self.details_heading.setVisible(False)
                self._fit_to_contents()
                return

        if is_carved:
            # A carved file was recovered from unallocated space with no
            # directory entry, so it has no filesystem timestamps at all. The
            # only date available is one the format stored inside itself, and
            # it is not a substitute for any of the four.
            carved_timestamp = data.get('carved_timestamp') or UNKNOWN_DATE
            carved_source = data.get('carved_timestamp_source') or ''
            created_time = modified_time = accessed_time = changed_time = None
        else:
            created_time = self._format_timestamp(getattr(metadata, 'crtime', None))
            modified_time = self._format_timestamp(getattr(metadata, 'mtime', None))
            accessed_time = self._format_timestamp(getattr(metadata, 'atime', None))
            changed_time = self._format_timestamp(getattr(metadata, 'ctime', None))

        md5_hash = hashlib.md5(file_content).hexdigest() if file_content else "N/A"
        sha256_hash = hashlib.sha256(file_content).hexdigest() if file_content else "N/A"
        mime_type = Magic().from_buffer(file_content) if file_content else "N/A"

        if is_carved:
            size = self.image_handler.get_readable_size(data.get('size', 0))
        else:
            size = metadata.size if metadata.size else 'N/A'
            if isinstance(size, str):
                try:
                    size = int(size)
                except ValueError:
                    size = 'N/A'
            else:
                size = self.image_handler.get_readable_size(size)

        # Grouped into sections so the pane reads as three short lists rather
        # than one long undifferentiated column.
        rows = []
        if is_carved:
            rows.append(("Carved File", "Recovered from unallocated space", "warning"))

        rows += [
            (None, "File"),
            ("Name", data.get('name', 'N/A')),
            ("Type", data.get('type')),
            ("MIME Type", mime_type),
            ("Size", size),
        ]

        if is_carved:
            offset_value = data.get('offset', 0)
            rows.append(("Disk Offset", f"{hex(offset_value)} ({offset_value} bytes)"))

        if is_carved:
            rows.append((None, "Timestamps"))
            rows.append(("Embedded Date", carved_timestamp))
            if carved_source:
                rows.append(("Date Source", carved_source))
            rows.append(("Filesystem Times",
                         "None -- carved from unallocated space"))
        else:
            rows += [
                (None, "Timestamps"),
                ("Modified", modified_time),
                ("Accessed", accessed_time),
                ("Created", created_time),
                ("Changed", changed_time),
            ]

        rows += [
            (None, "Hashes"),
            ("MD5", md5_hash),
            ("SHA-256", sha256_hash),
        ]
        rows += self._content_rows(data.get('name') or '', file_content)
        self.property_table.set_rows(rows)

        # Carved files have no inode, so there is nothing low-level to show.
        details = None
        if not is_carved:
            details = self.get_inode_details(data.get('start_offset'), data.get('inode_number'))
        self.details_view.setPlainText(details or "")
        self.details_view.setVisible(bool(details))
        self.details_heading.setVisible(bool(details))
        self._fit_to_contents()

    @staticmethod
    def _content_rows(name, content):
        """Photo, document and hidden-data sections, when the file has them.

        The same checks the analysis pass runs over every file, applied to
        the one on screen -- which is where the old EXIF tab's information now
        lives, shown only for files that carry it.
        """
        if not content or len(content) > content_checks.MAX_INSPECT_BYTES:
            return []
        rows = []

        photo = content_checks.photo_metadata(content)
        if photo:
            rows.append((None, "Photo"))
            camera = ' '.join(p for p in (photo.get('make'),
                                          photo.get('model')) if p)
            for label, value in (("Camera", camera),
                                 ("Lens", photo.get('lens')),
                                 ("Serial number", photo.get('serial')),
                                 ("Taken", photo.get('taken')),
                                 ("Digitised", photo.get('digitized')),
                                 ("Modified", photo.get('modified')),
                                 ("Software", photo.get('software')),
                                 ("Artist", photo.get('artist')),
                                 ("Copyright", photo.get('copyright'))):
                if value:
                    rows.append((label, value))
            if 'latitude' in photo:
                rows.append(("Location", f"{photo['latitude']:.6f}, "
                                         f"{photo['longitude']:.6f}",
                             "warning"))
                if photo.get('altitude') is not None:
                    rows.append(("Altitude", f"{photo['altitude']} m"))
                if photo.get('gps_date'):
                    rows.append(("GPS date", photo['gps_date']))

        authors = content_checks.document_authors(content)
        if authors:
            rows.append((None, "Document"))
            for label, key in (("Title", 'title'), ("Author", 'author'),
                               ("Last saved by", 'last_saved_by'),
                               ("Company", 'company'),
                               ("Application", 'application'),
                               ("Producer", 'producer'),
                               ("Template", 'template'),
                               ("Created", 'created'),
                               ("Modified", 'modified'),
                               ("Last printed", 'last_printed'),
                               ("Revision", 'revision'),
                               ("Editing time (min)", 'editing_minutes')):
                if authors.get(key):
                    rows.append((label, authors[key]))

        rows += _executable_rows(name, content)

        hidden = [f for f in content_checks.inspect(
                      name, content, (content_checks.MODULE_HIDDEN,))
                  if f.grade in content_checks.REPORTED_GRADES]
        if hidden:
            rows.append((None, "Hidden data"))
            for finding in hidden:
                rows.append((finding.grade.capitalize(), finding.summary,
                             "warning"))
        return rows

    def get_inode_details(self, offset, inode_number):
        """Render low-level filesystem details for an inode.

        This reads the same metadata The Sleuth Kit's `istat` reports, but
        through pytsk3 directly. The previous implementation shelled out to a
        bundled tools/sleuthkit-4.12.1-win32/bin/istat.exe behind an
        `os.name == 'nt'` guard, so macOS and Linux silently got a reduced
        Metadata tab with no explanation -- and a packaged build got a
        FileNotFoundError, since tools/ was never bundled.

        Returns a plain-text block, or None when the data is unavailable.
        """
        if offset is None or inode_number is None:
            return None

        try:
            fs_info = self.image_handler.get_fs_info(offset)
            if fs_info is None:
                return None
            file_obj = fs_info.open_meta(inode=inode_number)
        except Exception as e:
            return f"Filesystem details unavailable: {e}"

        meta = getattr(file_obj.info, 'meta', None)
        if meta is None:
            return None

        lines = []

        def add(label, value):
            lines.append(f"{label}: {value}")

        add("Entry", meta.addr)
        if getattr(meta, 'seq', None) is not None:
            add("Sequence", meta.seq)

        alloc = "Allocated" if int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC else "Deleted"
        meta_type = self._META_TYPES.get(int(meta.type), str(meta.type))
        add("Status", f"{alloc} {meta_type}")

        if getattr(meta, 'nlink', None) is not None:
            add("Links", meta.nlink)
        add("Size", meta.size)
        add("UID / GID", f"{meta.uid} / {meta.gid}")
        if getattr(meta, 'mode', None) is not None:
            add("Mode", oct(int(meta.mode)))

        lines.append("")
        lines.append("Timestamps:")
        for label, attr in (("Created ", 'crtime'), ("File Modified", 'mtime'),
                            ("MFT Modified", 'ctime'), ("Accessed", 'atime')):
            ts = getattr(meta, attr, None)
            # NTFS records these to 100-nanosecond precision and TSK hands the
            # fraction back separately. Truncating to whole seconds throws away
            # the detail that orders events within the same second, which is
            # exactly what a timeline is built from.
            nanoseconds = getattr(meta, f'{attr}_nano', None)
            lines.append(f"  {label}\t{self._format_timestamp(ts, nanoseconds)}")

        # Attribute list -- the resident/non-resident breakdown istat prints.
        try:
            attrs = list(file_obj)
        except Exception:
            attrs = []

        if attrs:
            lines.append("")
            lines.append("Attributes:")
            for attr in attrs:
                info = attr.info
                try:
                    non_res = bool(int(info.flags) & pytsk3.TSK_FS_ATTR_NONRES)
                except Exception:
                    non_res = False
                name = info.name
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                type_name = self._ATTR_TYPES.get(int(info.type), str(info.type))
                lines.append(
                    f"  Type: {type_name} ({int(info.type)}-{info.id})   "
                    f"Name: {name or 'N/A'}   "
                    f"{'Non-Resident' if non_res else 'Resident'}   "
                    f"size: {info.size}")

        return "\n".join(lines)

    @staticmethod
    def _format_timestamp(ts, nanoseconds=None):
        """Format a filesystem timestamp, with its fraction when there is one.

        `nanoseconds` is the sub-second part TSK reports alongside the whole
        seconds. It is shown only when non-zero, so a filesystem that does not
        record it (or a file where it happens to be zero) reads the same as
        before rather than gaining a misleading '.000000000'.
        """
        if not ts:
            return "N/A"
        try:
            formatted = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        except (OSError, OverflowError, ValueError):
            return "N/A"

        try:
            if nanoseconds:
                formatted += f".{int(nanoseconds):09d}"
        except (TypeError, ValueError):
            pass
        return formatted + " UTC"

    # NTFS attribute type identifiers, as istat labels them.
    _ATTR_TYPES = {
        16: "$STANDARD_INFORMATION", 32: "$ATTRIBUTE_LIST", 48: "$FILE_NAME",
        64: "$OBJECT_ID", 80: "$SECURITY_DESCRIPTOR", 96: "$VOLUME_NAME",
        112: "$VOLUME_INFORMATION", 128: "$DATA", 144: "$INDEX_ROOT",
        160: "$INDEX_ALLOCATION", 176: "$BITMAP", 192: "$REPARSE_POINT",
        256: "$LOGGED_UTILITY_STREAM",
    }

    # Built from the pytsk3 constants rather than hardcoded numbers, so the
    # labels cannot drift from the enum.
    _META_TYPES = {
        int(pytsk3.TSK_FS_META_TYPE_REG): "File",
        int(pytsk3.TSK_FS_META_TYPE_DIR): "Directory",
        int(pytsk3.TSK_FS_META_TYPE_FIFO): "Named Pipe",
        int(pytsk3.TSK_FS_META_TYPE_CHR): "Character Device",
        int(pytsk3.TSK_FS_META_TYPE_BLK): "Block Device",
        int(pytsk3.TSK_FS_META_TYPE_LNK): "Symbolic Link",
        int(pytsk3.TSK_FS_META_TYPE_SHAD): "Shadow",
        int(pytsk3.TSK_FS_META_TYPE_SOCK): "Socket",
        int(pytsk3.TSK_FS_META_TYPE_WHT): "Whiteout",
        int(pytsk3.TSK_FS_META_TYPE_VIRT): "Virtual",
        int(pytsk3.TSK_FS_META_TYPE_VIRT_DIR): "Virtual Directory",
        int(pytsk3.TSK_FS_META_TYPE_UNDEF): "Unknown",
    }

    def clear(self):
        self.property_table.clear_rows()
        self.details_view.clear()
        self.details_view.setVisible(False)
        self.details_heading.setVisible(False)
        self._fit_to_contents()


def _executable_rows(name, content):
    """The Executable section: what core/executables.py reads from a PE,
    ELF or Mach-O file's headers, its indicators first."""
    from trace_app.core import executables
    facts = executables.analyse(content)
    if facts is None:
        return []
    rows = [(None, "Executable")]
    for grade, text in executables.indicators(facts, name):
        rows.append((grade.capitalize(), text, "warning"))
    rows.append(("Format", f"{facts.get('format', '')}, "
                           f"{facts.get('architecture', '')}"))
    rows.append(("Kind", facts.get('kind', '')
                 + (f" ({facts['subsystem']})" if facts.get('subsystem')
                    else '')))
    if facts.get('compiled') or facts.get('compiled_note'):
        rows.append(("Linked", facts.get('compiled')
                     or facts['compiled_note']))
    version = facts.get('version') or {}
    for label, key in (("Original name", 'OriginalFilename'),
                       ("Description", 'FileDescription'),
                       ("Company", 'CompanyName'),
                       ("Product", 'ProductName'),
                       ("File version", 'FileVersion')):
        if version.get(key):
            rows.append((label, version[key]))
    signature = facts.get('signature')
    if signature:
        signer = executables.signed_by(facts)
        text = f"{signature['type']}, {signer or 'signer not read'}"
        if signature.get('issuer'):
            text += f", issued by {signature['issuer']}"
        if signature.get('valid_from'):
            text += (f", certificate valid {signature['valid_from']} to "
                     f"{signature.get('valid_to', '')}")
        if signature.get('identifier'):
            text += f", identifier {signature['identifier']}"
        rows.append(("Signature", text + " (present; not verified)"))
    elif not facts.get('format', '').startswith('ELF'):
        rows.append(("Signature", "None"))
    for label, key in (("PDB", 'pdb'), ("Build ID", 'build_id'),
                       ("UUID", 'uuid'), ("Interpreter", 'interpreter'),
                       ("Install name", 'install_name'),
                       ("Platform", 'platform'),
                       ("Minimum OS", 'minimum_os'),
                       ("Entry point", 'entry_point')):
        if facts.get(key):
            rows.append((label, facts[key]))
    if facts.get('compiler'):
        rows.append(("Compiler", '; '.join(facts['compiler'])))
    if facts.get('protections'):
        rows.append(("Protections", ', '.join(facts['protections'])))
    checksum = facts.get('checksum')
    if checksum:
        rows.append(("PE checksum", f"{checksum['stored']} "
                     + ("(matches)" if checksum['matches'] else
                        f"(computed {checksum['computed']})")))
    sections = facts.get('sections') or []
    if sections:
        rows.append(("Sections", '; '.join(
            f"{s['name'] or '(unnamed)'} {s['flags']} "
            f"{s['raw_size']:,} B, entropy {s['entropy']:.2f}"
            for s in sections[:24])))
    imports = facts.get('imports') or []
    libraries = [i['library'] for i in imports
                 if i['library'] != '(dynamic symbols)']
    if libraries:
        rows.append(("Libraries", ', '.join(libraries[:60])))
    count = len(executables.all_functions(facts))
    if count:
        rows.append(("Imported functions", f"{count:,}"))
    exports = facts.get('exports')
    if exports:
        rows.append(("Exports", f"{exports.get('functions', 0):,}"
                     + (f" ({exports['name']})" if exports.get('name')
                        else '')))
    overlay = facts.get('overlay')
    if overlay:
        rows.append(("Appended data", f"{overlay['size']:,} bytes at "
                     f"{overlay['offset']:,}"
                     + (f", {overlay['starts']}" if overlay['starts'] else '')
                     + f", entropy {overlay['entropy']:.2f}"))
    return rows
