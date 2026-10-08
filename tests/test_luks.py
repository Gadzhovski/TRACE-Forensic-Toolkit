"""Encrypted Linux disks as installers lay them out: GPT -> LUKS -> LVM ->
ext4 (tools/make_luks_lvm.py, made by cryptsetup and lvm2 themselves).

LUKS1 is unlocked by libluksde; LUKS2 -- cryptsetup's default, which
libluksde cannot read -- by core/luks2.py, here with argon2id and 4 KiB
sectors as current installs write it. Once unlocked, the LVM inside is
found (it used to be looked for on the encrypted bytes), its logical
volumes read file for file as the kernel wrote them, and carving reaches
inside: the PNG deleted in the home volume comes back byte for byte.

The disks need root and loop devices to build, so Linux CI builds them
and these tests skip elsewhere.
"""

import hashlib
import json

import pytest

from tests.conftest import image_path

KEY = 'luks-lvm.json'
DISKS = ['luks1-lvm.raw', 'luks2-lvm.raw']
START = 2048


def disk_key(name):
    with open(image_path(KEY), encoding='utf-8') as source:
        return next(d for d in json.load(source)['disks']
                    if d['image'] == name)


def unlocked(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.loaded
    handler.unlock_volume(START, 'luks', password=disk_key(name)['password'])
    return handler


@pytest.mark.parametrize('name', DISKS)
def test_lvm_inside_luks_reads_as_the_kernel_wrote_it(name):
    key = disk_key(name)
    handler = unlocked(name)
    try:
        assert handler.volume_kind(START) == 'luks'
        assert handler.inner_kind(START) == 'lvm'
        volumes = {v['name']: v for v in handler.logical_volumes(START)}
        assert set(volumes) == {'root', 'home'}
        assert [v['key'] for v in volumes.values()] == [
            k for k in handler.volume_offsets() if k in
            {v['key'] for v in volumes.values()}]
        for name_, record in key['volumes'].items():
            fs = handler.get_fs_info(volumes[name_]['key'])
            assert handler.get_fs_type(volumes[name_]['key']) == 'Ext4'
            for entry in record['files']:
                handle = fs.open(entry['path'])
                data = handle.read_random(0, handle.info.meta.size)
                assert hashlib.sha256(data).hexdigest() == entry['sha256']
    finally:
        handler.close_resources()


def test_a_luks2_header_is_read_in_python():
    from trace_app.core import luks2
    path = image_path('luks2-lvm.raw')
    with open(path, 'rb') as disk:
        def read(offset, length):
            disk.seek(START * 512 + offset)
            return disk.read(length)
        meta = luks2.read_header(read)
        (slot,) = meta['keyslots'].values()
        assert slot['kdf']['type'] == 'argon2id'
        assert meta['segments']['0']['sector_size'] == 4096
        with pytest.raises(luks2.Luks2Error, match='does not unlock'):
            luks2.unlock(read, 32 * 1024 * 1024, password='wrong')


def test_a_wrong_passphrase_is_said_plainly():
    from trace_app.core import containers
    from trace_app.core.image_handler import ImageHandler
    for name in DISKS:
        handler = ImageHandler(image_path(name))
        try:
            with pytest.raises(containers.ContainerError):
                handler.unlock_volume(START, 'luks', password='wrong')
            assert not handler.is_unlocked(START)
        finally:
            handler.close_resources()


@pytest.mark.parametrize('name', DISKS)
def test_carving_reaches_inside_the_unlocked_volume(name):
    from trace_app.core import carving
    from trace_app.core.image_handler import ImageHandler
    expected = disk_key(name)['volumes']['home']['deleted_png']

    def carve(handler):
        found = []
        carving.carve_image(
            handler, ['png'],
            lambda content, kind, offset, fragments=None: found.append(
                (offset, content)), True)
        return [(o, c) for o, c in found
                if hashlib.sha256(c).hexdigest() == expected['sha256']]

    locked = ImageHandler(image_path(name))
    try:
        assert carve(locked) == []        # ciphertext holds no PNG
    finally:
        locked.close_resources()
    handler = unlocked(name)
    try:
        ((offset, content),) = carve(handler)
        assert len(content) == expected['size']
        assert offset >= handler.CARVE_SPACE
        # The offset is an address like any other: read back after a
        # reopen and unlock, as a preview or an export does.
        handler.close_resources()
        handler = unlocked(name)
        assert handler.read(offset, len(content)) == content
    finally:
        handler.close_resources()


def test_a_carve_job_unlocks_and_records_the_carve(tmp_path):
    """The case's carve, as the background job runs it: the keys come in
    memory (apply_unlocks), the carve is recorded with its span ref."""
    from trace_app.core import carving
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    name = 'luks2-lvm.raw'
    expected = disk_key(name)['volumes']['home']['deleted_png']['sha256']
    case = Case.create(str(tmp_path / 'case'), 'LUKS')
    handler = ImageHandler(image_path(name))
    try:
        evidence = case.add_evidence(image_path(name))
        handler.apply_unlocks({START: {'_kind': 'luks',
                                       'password': 'PASSWORD'}})
        assert carving.carve_evidence(handler, case, evidence, ['png']) >= 1
        rows = [r for r in case.carved_files(evidence)
                if r.get('sha256') == expected]
        assert len(rows) == 1
        assert int(rows[0]['offset']) >= handler.CARVE_SPACE
        state = case.carving_state(evidence)
        assert state['bytes_total'] == carving.carve_extent(handler)
    finally:
        handler.close_resources()
        case.close()


def test_an_unlocked_luks2_node_lists_its_logical_volumes(qapp, monkeypatch):
    """The tree: the GPT partition shows LUKS, locked; unlocked through the
    dialog, its logical volumes are its children and list their files."""
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs import bitlocker, message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)

    def fake_exec(dialog):
        dialog.password.setText('PASSWORD')
        dialog._try()
        return dialog.result()
    monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)

    def children(item):
        return [(item.child(i).text(0), item.child(i).data(0, Qt.UserRole)
                 or {}) for i in range(item.childCount())]
    window = MainWindow()
    try:
        path = image_path('luks2-lvm.raw')
        assert window.open_evidence_image(path)
        tree = window.tree_viewer
        root = next(tree.topLevelItem(i) for i in range(
            tree.topLevelItemCount()) if (tree.topLevelItem(i).data(
                0, Qt.UserRole) or {}).get('image_path', '').endswith(
                    'luks2-lvm.raw'))
        index = next(i for i, (_t, d) in enumerate(children(root))
                     if d.get('encryption') == 'luks')
        assert 'LUKS, locked' in root.child(index).text(0)
        window.unlock_bitlocker_item(root.child(index))
        node = next(root.child(i) for i in range(root.childCount())
                    if (root.child(i).data(0, Qt.UserRole) or {})
                    .get('encryption') == 'luks')
        assert 'LVM volume group, LUKS unlocked' in node.text(0)
        volumes = children(node)
        assert [t.split(' (')[0] for t, _d in volumes] == [
            'vg2 / root', 'vg2 / home']
        home = node.child(1)
        home.setExpanded(True)
        window.on_item_expanded(home)
        assert 'data' in [t for t, _d in children(home)]
    finally:
        window.cleanup_resources()
