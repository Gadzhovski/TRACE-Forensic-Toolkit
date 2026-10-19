"""One ref per file, whichever view made it (core/ref_repair.py).

The Listing used to make a deleted NTFS file's ref from its MFT entry --
no sequence at all for a name TSK gives no metadata, the advanced one for a
freed entry -- while the walk, the analysis and core/deleted.py use the
name entry's. A tag, bookmark or Project VIC category put on a deleted file
in the Listing then named nothing the Deleted Files tab or the VICS export
knew. The Listing reads the name's sequence now; marks an older Listing
stored are repaired when the image opens.
"""

import pytest

from tests.conftest import image_path


def _listed(handler):
    """{(volume, path lower-cased): {refs the Listing makes there}}."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.core.walk import volume_offsets
    listed = {}

    def visit(offset, inode, path, depth=0):
        for entry in handler.get_directory_contents(offset, inode):
            child = f"{path}/{entry['name']}"
            if entry.get('is_directory'):
                if depth < 10:
                    visit(offset, entry['inode_number'], child, depth + 1)
                continue
            if entry['inode_number'] is None:
                continue
            listed.setdefault((offset, child.lower()), set()).add(
                make_artifact_ref(offset, entry['inode_number'],
                                  entry.get('sequence')))
    for offset in volume_offsets(handler):
        visit(offset, None, '')
    return listed


@pytest.mark.parametrize('name, expected', [('7-ntfs-undel.dd', 7),
                                            ('dfr-01-recycle-ntfs.dd', 2)])
def test_the_listing_names_deleted_files_as_deleted_py_does(name, expected):
    """Every deleted file the Listing shows has the ref core/deleted.py
    gives it. (A file deleted.py knows only from $LogFile -- its entry
    reused, no name left in any folder -- is not in the Listing.)"""
    from trace_app.core import deleted
    from trace_app.core.carving import allocation_map
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.load_image()
    try:
        listed = _listed(handler)
        compared = 0
        for record in deleted.deleted_files(handler,
                                            allocation_map(handler)):
            key = (record['volume'], record['path'].lower())
            if record.get('is_dir') or key not in listed or \
                    not record.get('inode') or \
                    record.get('source') == '$LogFile':
                continue
            compared += 1
            assert record['ref'] in listed[key], (record['path'],
                                                  listed[key])
        assert compared == expected
    finally:
        handler.close_resources()


def test_marks_an_older_listing_stored_are_given_the_name_entrys_ref(
        tmp_path):
    """DFTT #7's deleted frag1.dat (MFT entry 29, its name records
    sequence 1): an older Listing stored 'p0:i29'. Opening the image
    repairs the bookmark, tag, category and note on it; a live file's mark
    and a path that no longer resolves are left alone; it is audited."""
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.ref_repair import Resolver
    path = image_path('7-ntfs-undel.dd')
    case = Case.create(str(tmp_path / 'case'), 'Repair')
    try:
        evidence_id = case.add_evidence(path)
        old = {'evidence_id': evidence_id, 'artifact_ref': 'p0:i29',
               'name': 'frag1.dat', 'path': '/frag1.dat'}
        missing = {'evidence_id': evidence_id, 'artifact_ref': 'p0:i30',
                   'name': 'gone.dat', 'path': '/no/such/gone.dat'}
        case.add_bookmark(evidence_id, 'p0:i29', 'fragment', 'frag1.dat',
                          '/frag1.dat')
        relevant = case.tags()[0]['id']
        case.tag_artifacts(relevant, [old, missing])
        case.set_vic_category(4, [old])
        case.add_note('first fragment', evidence_id, 'p0:i29', 'frag1.dat',
                      '/frag1.dat')
        # The same tag already on the repaired ref (put there since): the
        # old row goes rather than doubling it.
        case.tag_artifacts(relevant, [dict(old, artifact_ref='p0:i29:s1')])
        handler = ImageHandler(path)
        assert handler.load_image()
        try:
            changed = case.repair_file_refs(evidence_id, Resolver(handler))
        finally:
            handler.close_resources()
        assert changed == 4
        assert [b['artifact_ref'] for b in case.bookmarks()] == \
            ['p0:i29:s1']
        assert sorted(r['artifact_ref'] for r in case.tagged()) == \
            ['p0:i29:s1', 'p0:i30']
        assert case.vic_categories_for(evidence_id) == {'p0:i29:s1': 4}
        assert [n['artifact_ref'] for n in case.notes()] == ['p0:i29:s1']
        entry = next(e for e in case.activity()
                     if e['action'] == 'file references updated')
        assert 'p0:i29 -> p0:i29:s1' in entry['detail']
        # A second pass finds nothing left to do.
        handler = ImageHandler(path)
        assert handler.load_image()
        try:
            assert case.repair_file_refs(evidence_id,
                                         Resolver(handler)) == 0
        finally:
            handler.close_resources()
    finally:
        case.close()


def test_a_live_files_ref_is_never_changed():
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.ref_repair import Resolver
    from trace_app.core.walk import iter_files
    handler = ImageHandler(image_path('7-ntfs-undel.dd'))
    assert handler.load_image()
    try:
        resolve = Resolver(handler)
        live = [entry for entry in iter_files(handler) if not entry.deleted]
        assert live
        for entry in live:
            assert resolve(entry.ref, entry.path) is None, entry.path
    finally:
        handler.close_resources()
