"""What a run covers (core/scope.py): rules, presets on every system's
path shapes, and the walks that honour them."""

import pytest

from trace_app.core import scope
from trace_app.core.scope import Scope


def _match(rules, roots=('/',), **extra):
    return Scope(preset='custom', **rules, **extra).matcher(roots=list(roots))


def test_everything_leaves_nothing_out():
    assert Scope().everything
    assert Scope().matcher(roots=['/']) is None
    assert Scope.preset_scope('everything').everything
    assert Scope().covers_free_space
    assert 'no files left out' in Scope().describe()


def test_rule_forms():
    m = _match({'exclude': ['~/usr', '/home/alex/cache', 'node_modules',
                            '~/Users/*/AppData/Local/Temp']})
    assert m.skips_folder('/usr') and m.skips_folder('/usr/lib/x')
    assert not m.skips_folder('/usrlocal')
    assert m.skips_folder('/home/alex/cache/a')
    assert not m.skips_folder('/home/bob/cache')
    assert m.skips_folder('/srv/app/node_modules')         # anywhere
    assert m.skips_folder('/Users/Bob/AppData/Local/Temp')  # wildcard
    assert not m.skips_folder('/Users/Bob/AppData/Local')
    # Case does not matter: Windows names ignore it, examiners type it.
    assert m.skips_folder('/USR/bin')


def test_include_prunes_everything_else_but_the_way_in():
    m = _match({'include': ['~/home']})
    assert not m.skips_folder('/')            # on the way
    assert not m.skips_folder('/home')
    assert not m.skips_folder('/home/alex/Documents')
    assert m.skips_folder('/usr')
    assert m.skips_file('/etc/passwd')
    assert not m.skips_file('/home/alex/notes.txt')
    m = _match({'include': ['/data/projects/x']})
    assert not m.skips_folder('/data') and not m.skips_folder('/data/projects')
    assert m.skips_folder('/data/other')


def test_fedora_btrfs_layout():
    """Fedora's Btrfs root holds the system in subvolume 'root' and people
    in 'home', both seen at the top: '~/usr' is /root/usr, '~/home' is the
    'home' subvolume as well as /root/home -- and '~/root' (root's own
    home) never takes in the whole 'root' subvolume."""
    roots = ['/', '/root']           # the volume root looks like one too
    user = Scope.preset_scope('user').matcher(roots=roots)
    assert not user.skips_file('/home/user/Documents/a.docx')
    assert not user.skips_file('/root/home/user/a.txt')
    assert not user.skips_file('/root/root/.bash_history')
    assert user.skips_file('/root/usr/lib64/libxul.so')
    assert user.skips_folder('/root/usr')
    no_system = Scope.preset_scope('no_system').matcher(roots=roots)
    assert no_system.skips_folder('/root/usr')
    assert no_system.skips_folder('/root/var/cache/dnf')
    assert not no_system.skips_folder('/root/etc')
    assert not no_system.skips_file('/home/user/a.txt')


@pytest.mark.parametrize('roots,user_file,system_file', [
    (['/'], '/Users/Alex/Desktop/plan.docx', '/Windows/WinSxS/x/y.dll'),
    (['/'], '/Documents and Settings/bob/My Documents/a.doc',
     '/Windows/Installer/1.msi'),
    (['/'], '/Users/alex/Pictures/a.jpg', '/System/Library/x.plist'),
    (['/C'], '/C/Users/alex/a.txt', '/C/Windows/WinSxS/a.dll'),   # KAPE
    (['/'], '/home/alex/a.txt', '/usr/lib/libc.so.6'),
    (['/'], '/private/var/mobile/Library/SMS/sms.db', '/System/x'),
    (['/'], '/data/data/com.whatsapp/databases/msgstore.db', '/usr/x'),
])
def test_presets_on_every_system(roots, user_file, system_file):
    user = Scope.preset_scope('user').matcher(roots=roots)
    no_system = Scope.preset_scope('no_system').matcher(roots=roots)
    assert not user.skips_file(user_file)
    assert user.skips_file(system_file)
    assert not no_system.skips_file(user_file)
    assert no_system.skips_file(system_file)


def test_windows_system32_is_kept_by_no_system():
    m = Scope.preset_scope('no_system').matcher(roots=['/'])
    assert not m.skips_file('/Windows/System32/config/SOFTWARE')
    assert not m.skips_file('/Windows/System32/winevt/Logs/Security.evtx')


def test_types_sizes_dates_names_and_deleted():
    m = _match({'types': ['documents', 'pictures']})
    assert not m.skips_file('/a/b.DOCX') and not m.skips_file('/a/c.jpg')
    assert m.skips_file('/a/d.exe')
    m = _match({'exclude_names': ['*.so', '*.ko.xz']})
    assert m.skips_file('/usr/lib/libz.so') and m.skips_file('/m/a.ko.xz')
    assert not m.skips_file('/usr/lib/libz.so.1')
    m = _match({}, min_size=10, max_size=100)
    assert m.skips_file('/a', size=5) and m.skips_file('/a', size=101)
    assert not m.skips_file('/a', size=50)
    m = _match({}, modified_after='2024-01-01', modified_before='2024-01-31')
    jan = 1704067200                                   # 2024-01-01 00:00 UTC
    assert not m.skips_file('/a', mtime=jan)
    assert not m.skips_file('/a', mtime=jan + 30 * 86400 + 3600)  # the 31st
    assert m.skips_file('/a', mtime=jan - 1)
    assert m.skips_file('/a', mtime=jan + 31 * 86400)
    assert not m.skips_file('/a', mtime=None)        # unknown: not ruled out
    m = _match({}, deleted=scope.DELETED_ONLY)
    assert m.skips_file('/a', deleted=False) and not m.skips_file('/a',
                                                                  deleted=True)
    m = _match({}, deleted=scope.DELETED_EXCLUDE)
    assert m.skips_file('/a', deleted=True)


def test_kept_and_stated():
    s = Scope.preset_scope('documents')
    again = Scope.from_dict(s.to_dict())
    assert again.to_dict() == s.to_dict()
    assert again.label == 'Documents and pictures'
    text = s.describe()
    assert 'only in' in text and 'documents' in text
    assert 'unallocated space and file slack not searched' in text
    assert not s.covers_free_space
    assert Scope.preset_scope('no_system').covers_free_space
    assert Scope.from_dict(None).everything
    assert Scope.from_dict('garbage').everything
    assert Scope.from_dict({'types': ['nonsense']}).everything


def test_system_roots_of_a_real_volume():
    """A plain NTFS volume is its own system root."""
    from tests.conftest import image_path
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('ntfs1-gen2.E01'))
    try:
        assert handler.load_image()
        offset = handler.volume_offsets()[0]
        roots = scope.system_roots(handler.get_fs_info(offset))
        assert roots and all(r.startswith('/') for r in roots)
    finally:
        handler.close_resources()


def test_walks_honour_the_scope():
    """The shared walk, analysis's count and the index's count all leave
    the same files out."""
    from tests.conftest import image_path
    from trace_app.core import analysis, indexer, walk
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('8-jpeg-search.dd'))
    try:
        assert handler.load_image()
        every = list(walk.iter_files(handler))
        assert every
        only = Scope(preset='custom', types=['pictures'])
        kept = list(walk.iter_files(handler, scope=only))
        assert kept and len(kept) < len(every)
        assert all(e.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif',
                                            '.bmp', '.tif', '.tiff'))
                   for e in kept)
        offsets = handler.volume_offsets()
        counted = sum(analysis._count_files(
            handler, o, None, only.matcher(handler.get_fs_info(o)))
            for o in offsets)
        indexed = sum(indexer._count_files(
            handler, o, None, only.matcher(handler.get_fs_info(o)))
            for o in offsets)
        assert counted == indexed == len(kept)
    finally:
        handler.close_resources()


# --- the dialogs -----------------------------------------------------------

def test_the_editor_round_trips_and_turns_custom_when_edited(qapp):
    from trace_app.ui.dialogs.scope_editor import ScopeEditor
    start = Scope.preset_scope('user')
    editor = ScopeEditor(start)
    try:
        assert editor.scope().to_dict() == start.to_dict()
        assert editor.preset_combo.currentData() == 'user'
        # Any change makes it the examiner's own.
        editor.names_edit.setText('*.so, *.ko.xz')
        assert editor.preset_combo.currentData() == scope.CUSTOM
        edited = editor.scope()
        assert edited.exclude_names == ['*.so', '*.ko.xz']
        assert edited.include == start.include
        editor.type_boxes['pictures'].setChecked(True)
        editor.min_box.setChecked(True)
        editor.min_spin.setValue(2)
        editor.after_box.setChecked(True)
        edited = editor.scope()
        assert edited.types == ['pictures'] and edited.min_size == 2 * 1024 * 1024
        assert edited.modified_after
        assert 'only pictures' in editor.summary.text()
        # Choosing a preset loads its rules.
        editor.preset_combo.setCurrentIndex(
            editor.preset_combo.findData('no_system'))
        assert editor.scope().to_dict() == \
            Scope.preset_scope('no_system').to_dict()
    finally:
        editor.deleteLater()


def test_the_module_selector_carries_the_scope(qapp):
    from trace_app.ui.dialogs.analysis_modules import ModuleSelector
    selector = ModuleSelector()
    try:
        assert Scope.from_dict(selector.choice()['scope']).everything
        selector.scope_combo.setCurrentIndex(
            selector.scope_combo.findData('no_system'))
        assert selector.choice()['scope']['preset'] == 'no_system'
        assert 'Skip operating-system files' in selector.scope_note.toolTip()
        mine = Scope(preset='custom', include=['~/srv']).to_dict()
        selector.set_choice({'modules': [], 'carve_types': [],
                             'scope': mine})
        assert selector.choice()['scope'] == mine
        assert selector.scope_combo.currentData() == scope.CUSTOM
    finally:
        selector.deleteLater()


def test_an_index_run_covers_only_its_scope(tmp_path):
    from tests.conftest import image_path
    from trace_app.core import indexer
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.search_index import SearchIndex
    handler = ImageHandler(image_path('8-jpeg-search.dd'))
    index = SearchIndex(str(tmp_path))
    try:
        assert handler.load_image()
        only = Scope(preset='custom', types=['pictures'])
        indexer.index_evidence(handler, index, 1, scope=only)
        rows = index._db.execute(
            "SELECT kind, name FROM indexed_items").fetchall()
        files = [name for kind, name in rows if kind == 'file']
        assert files and all(name.lower().endswith(('.jpg', '.jpeg'))
                             for name in files)
        # Free space and slack belong to no type: left out.
        assert not [k for k, _n in rows if k in ('unallocated', 'slack')]
    finally:
        index.close()
        handler.close_resources()
