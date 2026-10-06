"""Adapters that give the viewer tabs one common interface.

Each viewer widget grew its own vocabulary: `display_hex_content`,
`display_text_content`, `display_application_content`, `display_metadata`,
`load_and_display_exif_data`, and VirusTotal's `set_file_hash` /
`set_file_content` pair (both since retired). Clearing was split between `clear_content()` and
`clear()`.

MainWindow therefore dispatched on the tab's *integer index*::

    if index == 0:   self.hex_viewer.display_hex_content(...)
    elif index == 1: self.text_viewer.display_text_content(...)
    ...

which is tied to the order of the `addTab()` calls -- reordering a tab silently
routed content to the wrong viewer -- and repeated the same coupling in
`clear_viewers()` and in the media-streaming check (`current_tab_index == 2`).

A ViewerAdapter wraps each widget so MainWindow can just say `display(...)` or
`clear()`, and asks the adapter itself whether it wants a stream instead of
hardcoding an index. Adapting rather than renaming the widgets' own methods
keeps their existing call sites (toolbars, paging, context menus) untouched.
"""

from trace_app.core.filetypes import VIEW_AUDIO, VIEW_VIDEO, plan_from_name

# Audio and video are streamed from the image rather than read into memory.
# Which extensions count comes from core/filetypes, the same table that
# decides how every other file is shown, so the two cannot disagree.


class ViewerAdapter:
    """Common interface over one viewer widget.

    Subclasses implement `display`; `clear` defaults to whichever clear method
    the wrapped widget happens to provide.
    """

    #: Tab label, used when registering with the QTabWidget.
    label = None

    def __init__(self, widget):
        self.widget = widget

    def display(self, content, data):
        """Show `content` (bytes) for the entry described by `data` (dict)."""
        raise NotImplementedError

    def clear(self):
        for name in ('clear_content', 'clear'):
            method = getattr(self.widget, name, None)
            if callable(method):
                method()
                return

    def wants_stream(self, data):
        """True if this viewer prefers a streamed handle over loaded bytes."""
        return False

    def needs_content(self):
        """False if `display` works from `data` alone and needs no file read."""
        return True


class HexAdapter(ViewerAdapter):
    label = 'Hex'

    def display(self, content, data):
        self.widget.display_hex_content(content, data)

    def reads_itself(self, data):
        """A file on the image is read by the hex view a page at a time
        (core/hex_source.ImageFileSource), never loaded whole."""
        return bool(data) and data.get('type') == 'file' and \
            data.get('inode_number') is not None and \
            data.get('start_offset') is not None and \
            not data.get('archive_member')


class TextAdapter(ViewerAdapter):
    label = 'Text'

    def display(self, content, data):
        self.widget.display_text_content(content)


class ApplicationAdapter(ViewerAdapter):
    label = 'Application'

    def display(self, content, data):
        self.widget.display_application_content(content, data.get('name', ''),
                                                data)

    def wants_stream(self, data):
        plan = plan_from_name(data.get('name', ''))
        return plan is not None and plan.kind in (VIEW_AUDIO, VIEW_VIDEO)

    def display_stream(self, file_obj, file_size, data):
        """Hand the viewer a streaming handle instead of loaded bytes."""
        path = data.get('name', '')
        self.widget.load(
            mime_type=self.mime_type_for(path),
            path=path,
            file_obj=file_obj,
            file_size=file_size,
        )

    @staticmethod
    def mime_type_for(path):
        """Best-effort MIME type from the file extension."""
        plan = plan_from_name(path)
        if plan is not None and plan.mime:
            return plan.mime
        return 'application/octet-stream'


class MetadataAdapter(ViewerAdapter):
    label = 'File Metadata'

    def display(self, content, data):
        self.widget.display_metadata(data)

    def needs_content(self):
        # display_metadata() reads the file itself via the image handler.
        return False


class CaseAdapter(ViewerAdapter):
    label = 'Case'

    def display(self, content, data):
        self.widget.display_case(data)

    def needs_content(self):
        # A case is a property of the session, not of whichever file happens
        # to be selected, so there is no file to read.
        return False

    def clear(self):
        # The case outlives any one selection.
        pass


class NotesAdapter(ViewerAdapter):
    label = 'Notes'

    def display(self, content, data):
        self.widget.display_for(data)

    def needs_content(self):
        # A note is about a file, not made from it: the data dict names the
        # artifact, and nothing has to be read off disk to write one.
        return False


#: Adapter classes in tab order. Adding a viewer means adding one entry here
#: and constructing the widget in MainWindow -- no index arithmetic anywhere.
VIEWER_ADAPTERS = (
    HexAdapter,
    TextAdapter,
    ApplicationAdapter,
    MetadataAdapter,
    CaseAdapter,
    NotesAdapter,
)
