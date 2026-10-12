"""VeraCrypt / TrueCrypt volumes (core/veracrypt.py).

Two kinds of evidence that the reader is right:

* volumes made by VeraCrypt 1.26.29 itself (tools/testdata/build/
  make_veracrypt.py: Linux CI builds them, these tests skip elsewhere), each
  holding a FAT image written through VeraCrypt's own device -- decrypted
  bytes and every file must equal its answer key -- for AES and for every
  other encryption VeraCrypt offers (Serpent, Twofish, Camellia,
  Kuznyechik and the ten cascades);
* volumes written here from the format's rules (every hash, PIM and
  system iteration count, TrueCrypt's magic, hidden volumes, backup
  headers): what VeraCrypt can no longer make (TrueCrypt mode went in
  1.26) and what is quicker to check without it.
"""

import hashlib
import json
import os

import pytest

from tests.conftest import image_path
from trace_app.core import veracrypt

KEY = 'vc-key.json'
MIB = 1024 * 1024


# --- volumes written from the format's rules --------------------------------

def _volume(password, area=64 * 1024, prf='sha512', iterations=1000,
            magic=b'VERA', hidden=None, damage_primary=False):
    """(image bytes, plain area, hidden plain area or None)."""
    start = 131072
    size = start + area + 131072 + (area if hidden else 0)
    image = bytearray(os.urandom(size))
    keys = os.urandom(64)
    plain = os.urandom(area)
    header = veracrypt.make_header(password.encode(), os.urandom(64), keys,
                                   start, area, prf, iterations, magic)
    image[0:512] = header
    image[size - 131072:size - 131072 + 512] = header        # its backup
    image[start:start + area] = veracrypt.encrypt_area(keys, start, plain)
    hidden_plain = None
    if hidden:
        hidden_start = start + area
        hidden_keys = os.urandom(64)
        hidden_plain = os.urandom(area)
        image[65536:65536 + 512] = veracrypt.make_header(
            hidden.encode(), os.urandom(64), hidden_keys, hidden_start, area,
            prf, iterations, magic)
        image[hidden_start:hidden_start + area] = veracrypt.encrypt_area(
            hidden_keys, hidden_start, hidden_plain)
    if damage_primary:
        image[100:200] = bytes(100)
    return bytes(image), plain, hidden_plain


def _reader(image):
    return lambda offset, length: image[offset:offset + length]


@pytest.fixture
def few_iterations(monkeypatch):
    """VeraCrypt's iteration counts, scaled down a thousandfold so a test
    tries every hash in a moment (the counts' rules stay as written)."""
    real = veracrypt.attempts

    def quick(pim=None, system=False):
        return [(label, prf, max(1, n // 1000))
                for label, prf, n in real(pim, system)]
    monkeypatch.setattr(veracrypt, 'attempts', quick)


@pytest.mark.parametrize('prf', ['sha512', 'sha256', 'blake2s'])
def test_every_hash_veracrypt_offers_in_aes_opens(prf, few_iterations):
    iterations = 500  # VeraCrypt's 500,000, scaled as `few_iterations`
    image, plain, _ = _volume('secret', prf=prf, iterations=iterations)
    volume = veracrypt.unlock(_reader(image), len(image), 'secret')
    assert volume.read_buffer_at_offset(len(plain), 0) == plain
    assert volume.read_buffer_at_offset(1000, 1234) == plain[1234:2234]
    assert volume.fields['format'] == 'VeraCrypt'
    assert volume.get_size() == len(plain)


def test_iteration_counts_follow_veracrypts_rules():
    counts = {label: n for label, _prf, n in veracrypt.attempts()}
    assert counts == {'VeraCrypt SHA-512': 500000,
                      'VeraCrypt SHA-256': 500000,
                      'VeraCrypt BLAKE2s-256': 500000,
                      'TrueCrypt SHA-512': 1000}
    system = {label: n for label, _prf, n in veracrypt.attempts(system=True)}
    assert system['VeraCrypt SHA-256'] == 200000
    assert system['VeraCrypt SHA-512'] == 500000
    assert {n for _l, _p, n in veracrypt.attempts(pim=7)} == {22000}
    assert {n for _l, _p, n in veracrypt.attempts(pim=7, system=True)} == \
        {7 * 2048}
    # A PIM is VeraCrypt's: TrueCrypt is not tried with one.
    assert not any(l.startswith('TrueCrypt')
                   for l, _p, _n in veracrypt.attempts(pim=7))


def test_a_pim_changes_the_iterations(few_iterations):
    image, plain, _ = _volume('secret', prf='sha256', iterations=22)
    volume = veracrypt.unlock(_reader(image), len(image), 'secret', pim=7)
    assert volume.read_buffer_at_offset(len(plain), 0) == plain
    with pytest.raises(veracrypt.VeraCryptError):
        veracrypt.unlock(_reader(image), len(image), 'secret', pim=8)


def test_truecrypt_volumes_open(few_iterations):
    image, plain, _ = _volume('secret', iterations=1, magic=b'TRUE')
    volume = veracrypt.unlock(_reader(image), len(image), 'secret')
    assert volume.fields['format'] == 'TrueCrypt'
    assert volume.read_buffer_at_offset(len(plain), 0) == plain


def test_the_password_chooses_the_outer_or_hidden_volume(few_iterations):
    image, outer, hidden = _volume('outer', iterations=500, hidden='hidden')
    volume = veracrypt.unlock(_reader(image), len(image), 'outer')
    assert not volume.hidden
    assert volume.read_buffer_at_offset(len(outer), 0) == outer
    volume = veracrypt.unlock(_reader(image), len(image), 'hidden')
    assert volume.hidden
    assert volume.read_buffer_at_offset(len(hidden), 0) == hidden
    with pytest.raises(veracrypt.VeraCryptError):
        veracrypt.unlock(_reader(image), len(image), 'hidden', hidden=False)


def test_a_damaged_header_opens_from_its_backup(few_iterations):
    image, plain, _ = _volume('secret', iterations=500, damage_primary=True)
    volume = veracrypt.unlock(_reader(image), len(image), 'secret')
    assert volume.where == 'standard backup'
    assert volume.read_buffer_at_offset(len(plain), 0) == plain
    with pytest.raises(veracrypt.VeraCryptError):
        veracrypt.unlock(_reader(image), len(image), 'secret', backups=False)


def test_a_wrong_password_never_opens_and_says_what_else_it_may_be(
        few_iterations):
    image, _plain, _ = _volume('secret', iterations=500)
    with pytest.raises(veracrypt.VeraCryptError,
                       match='Whirlpool.*keyfiles'):
        veracrypt.unlock(_reader(image), len(image), 'Secret')
    with pytest.raises(veracrypt.VeraCryptError, match='whole number'):
        veracrypt.unlock(_reader(image), len(image), 'secret', pim='x')


def test_a_volume_cut_short_says_so(few_iterations):
    image, _plain, _ = _volume('secret', iterations=500)
    cut = image[:160 * 1024]          # inside the area (128-192 KiB)
    with pytest.raises(veracrypt.VeraCryptError, match='cut short'):
        veracrypt.unlock(_reader(cut), len(cut), 'secret', backups=False)


def test_both_crcs_guard_against_a_lucky_decryption():
    keys, salt = os.urandom(64), os.urandom(64)
    header = veracrypt.make_header(b'x', salt, keys, 131072, 65536,
                                   iterations=1)
    key = veracrypt.derive(b'x', salt, 'sha512', 1)
    plain = bytearray(salt + veracrypt._xts(key, 0, header[64:]))
    assert veracrypt.parse_header(bytes(plain)) is not None
    for spot in (300, 120):            # in the master keys; in a field
        damaged = bytearray(plain)
        damaged[spot] ^= 1
        assert veracrypt.parse_header(bytes(damaged)) is None


# --- volumes made by VeraCrypt itself ------------------------------------------

def _key(name):
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)[name]


BUILT_AES = ['vc-sha512.hc', 'vc-sha256-pim.hc', 'vc-blake2s.hc',
             'vc-hidden.hc', 'vc-partition.raw']
#: One volume per other encryption, VeraCrypt's own (2 MiB each).
BUILT_OTHERS = [f'vc-{name}.hc' for name in (
    'serpent',
    'twofish',
    'camellia',
    'kuznyechik',
    'aes-twofish',
    'aes-twofish-serpent',
    'serpent-aes',
    'serpent-twofish-aes',
    'twofish-serpent',
    'camellia-kuznyechik',
    'camellia-serpent',
    'kuznyechik-aes',
    'kuznyechik-serpent-camellia',
    'kuznyechik-twofish',
    )]


@pytest.mark.parametrize('name', BUILT_AES + BUILT_OTHERS)
def test_veracrypts_own_volumes_read_file_for_file(name):
    from trace_app.core.image_handler import ImageHandler
    entry = _key(name)
    handler = ImageHandler(image_path(name))
    try:
        assert handler.load_image()
        start = entry.get('start_sector', 0)
        assert handler.may_be_veracrypt(start)
        assert handler.get_fs_info(start) is None
        handler.unlock_volume(start, 'veracrypt', password=entry['password'],
                              pim=entry['pim'])
        assert handler.encryption(start) == 'veracrypt'
        volume = handler._bitlocker[start]
        assert volume.get_size() == entry['size']
        plain = volume.read_buffer_at_offset(entry['plain_length'], 0)
        assert hashlib.sha256(plain).hexdigest() == entry['plain_sha256']
        fs = handler.get_fs_info(start)
        assert fs is not None
        for path, digest in entry['files'].items():
            entry_file = fs.open(path)
            data = entry_file.read_random(0, entry_file.info.meta.size)
            assert hashlib.sha256(data).hexdigest() == digest, path
    finally:
        handler.close_resources()


def test_the_outer_password_opens_the_outer_volume():
    from trace_app.core.image_handler import ImageHandler
    entry = _key('vc-hidden.hc')
    handler = ImageHandler(image_path('vc-hidden.hc'))
    try:
        handler.unlock_volume(0, 'veracrypt',
                              password=entry['outer_password'])
        volume = handler._bitlocker[0]
        assert not volume.hidden
        assert volume.get_size() == entry['outer_size']
        assert volume.read_buffer_at_offset(65536, 0) == bytes(65536)
    finally:
        handler.close_resources()


@pytest.mark.parametrize('name', BUILT_OTHERS)
def test_the_encryption_found_is_the_one_veracrypt_used(name):
    entry = _key(name)
    path = image_path(name)
    with open(path, 'rb') as handle:
        data = handle.read()
    volume = veracrypt.unlock(lambda o, n: data[o:o + n], len(data),
                              entry['password'])
    assert volume.fields['encryption'] == entry['encryption']


@pytest.mark.parametrize('encryption', [e for e, _c in
                                        veracrypt.ENCRYPTIONS])
def test_every_encryption_written_here_reads_back(encryption):
    """make_header / encrypt_area for each encryption, unlocked again: the
    writing and reading sides agree on the key layout and order."""
    keys, salt = os.urandom(256), os.urandom(64)
    plain = os.urandom(8192)
    start = 131072
    image = bytearray(os.urandom(start + len(plain) + 131072))
    image[0:512] = veracrypt.make_header(b'pw', salt, keys, start,
                                         len(plain), iterations=1,
                                         encryption=encryption)
    image[start:start + len(plain)] = veracrypt.encrypt_area(
        keys, start, plain, encryption)
    plan = [('test', 'sha512', 1)]
    fields = veracrypt._try_header(bytes(image[:512]), b'pw', plan)
    assert fields['encryption'] == encryption
    volume = veracrypt.VeraCryptVolume(lambda o, n: bytes(image[o:o + n]),
                                       fields, 'standard')
    assert volume.read_buffer_at_offset(len(plain), 0) == plain
    assert volume.read_buffer_at_offset(700, 1000) == plain[1000:1700]


def test_a_job_unlocks_with_the_keys_it_is_handed():
    """What a background job does with params['unlock']."""
    from trace_app.core.image_handler import ImageHandler
    entry = _key('vc-sha256-pim.hc')
    handler = ImageHandler(image_path('vc-sha256-pim.hc'))
    try:
        handler.apply_unlocks({0: {'_kind': 'veracrypt',
                                   'password': entry['password'],
                                   'pim': entry['pim']}})
        assert handler.is_unlocked(0)
        assert handler.get_fs_info(0) is not None
    finally:
        handler.close_resources()


def test_the_tree_unlocks_a_container_through_the_dialog(qapp,
                                                         monkeypatch):
    from PySide6.QtCore import Qt
    from trace_app.ui.dialogs import bitlocker, message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    entry = _key('vc-sha256-pim.hc')

    def fake_exec(dialog):
        dialog.password.setText(entry['password'])
        dialog.pim.setText(str(entry['pim']))
        dialog._try()
        return dialog.result()
    monkeypatch.setattr(bitlocker.UnlockVolumeDialog, 'exec', fake_exec)
    window = MainWindow()
    try:
        path = image_path('vc-sha256-pim.hc')
        assert window.open_evidence_image(path)
        tree = window.tree_viewer
        root = next(tree.topLevelItem(i) for i in range(
            tree.topLevelItemCount()) if (tree.topLevelItem(i).data(
                0, Qt.UserRole) or {}).get('image_path', '').endswith(
                    'vc-sha256-pim.hc'))
        raw = next(root.child(i) for i in range(root.childCount())
                   if (root.child(i).data(0, Qt.UserRole) or {})
                   .get('is_unallocated'))
        window.unlock_veracrypt_item(raw)
        node = next(root.child(i) for i in range(root.childCount())
                    if (root.child(i).data(0, Qt.UserRole) or {})
                    .get('encryption') == 'veracrypt')
        assert 'VeraCrypt / TrueCrypt unlocked' in node.text(0)
        assert 'FAT' in node.text(0)
        keys = window._unlocks_for(path)
        assert keys[0]['_kind'] == 'veracrypt' and keys[0]['pim'] == 7
    finally:
        window.cleanup_resources()
