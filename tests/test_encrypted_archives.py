"""Password-protected archives (core/zip_aes.py, archives' session
passwords): WinZip AES ZIPs, ZipCrypto ZIPs and 7z AES, read with the
password the examiner gives.

The samples and their answers are libarchive's own (libarchive/test at
the pinned commit, BSD-2-Clause): test_read_format_zip_winzip_aes*.c,
..._traditional_encryption_data.c and ..._7zip_encryption*.c name each
archive's password, member names and sizes. On top of those: every
compression of the large AES set must decode to the same bytes, AES-128
and AES-256 to the same README, and a byte changed in the encrypted data
must be caught by the authentication code.
"""

import binascii
import hashlib

import pytest

from tests.conftest import data_path


def _uudecoded(name):
    """libarchive keeps its test archives uuencoded; decoded here with
    the standard library."""
    out = bytearray()
    with open(data_path('samples', f'libarchive-{name}'), 'rb') as handle:
        for line in handle:
            if line.startswith(b'begin') or line.strip() in (b'end', b''):
                continue
            count = (line[0] - 32) & 63
            out += binascii.a2b_uu(line[:(count * 4 + 5) // 3 + 1].rstrip()
                                   or b' ')
    return bytes(out)


@pytest.fixture(autouse=True)
def no_session_passwords():
    from trace_app.core import archives
    archives.forget_passwords()
    yield
    archives.forget_passwords()


LARGE = {'Makefile': 1456747, 'NEWS': 29357, 'README': 6818,
         'config.h': 32667}


def _contents(data):
    from trace_app.core import archives
    return {m['name']: archives.read_member(data, m['name'])
            for m in archives.list_members(data) if not m['is_dir']}


@pytest.mark.parametrize('name', ['zip_winzip_aes128.zip.uu',
                                  'zip_winzip_aes256.zip.uu',
                                  'zip_winzip_aes256_stored.zip.uu'])
def test_winzip_aes_as_libarchive_reads_it(name):
    from trace_app.core import archives
    data = _uudecoded(name)
    [member] = archives.list_members(data)
    assert (member['name'], member['size'], member['encrypted']) == \
        ('README', 6818, True)
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(data, 'README')            # no password yet
    # libarchive's test gives two wrong passphrases before the right one.
    for password in ('invalid_pass', 'invalid_phrase'):
        archives.remember_password(password)
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(data, 'README')
    archives.remember_password('password')
    content = archives.read_member(data, 'README')
    assert len(content) == 6818
    # The same README in each of the three archives.
    assert hashlib.sha256(content).hexdigest() == hashlib.sha256(
        _contents_with('zip_winzip_aes128.zip.uu', 'password')['README']
    ).hexdigest()


def _contents_with(name, password):
    from trace_app.core import archives
    archives.remember_password(password)
    return _contents(_uudecoded(name))


@pytest.mark.parametrize('compression', ['', '_bzip2', '_lzma', '_xz',
                                         '_zstd'])
def test_large_aes_set_in_every_compression(compression):
    """test_read_format_zip_winzip_aes_large.c: four files of known sizes,
    password 'password'. Every compression gives the same bytes."""
    found = _contents_with(
        f'zip_winzip_aes256_large{compression}.zip.uu', 'password')
    assert {name: len(content) for name, content in found.items()} == LARGE
    reference = _contents_with('zip_winzip_aes256_large.zip.uu', 'password')
    assert found == reference


def test_ppmd_inside_aes_is_refused_by_name():
    from trace_app.core import archives
    archives.remember_password('password')
    data = _uudecoded('zip_winzip_aes256_large_ppmd.zip.uu')
    with pytest.raises(archives.ArchiveError, match='PPMd'):
        archives.read_member(data, 'README')


def test_a_changed_byte_is_caught_by_the_authentication_code():
    import zipfile
    import io
    from trace_app.core import archives, zip_aes
    data = bytearray(_uudecoded('zip_winzip_aes256.zip.uu'))
    info = zipfile.ZipFile(io.BytesIO(bytes(data))).getinfo('README')
    stored = zip_aes.stored_bytes(bytes(data), info)
    at = bytes(data).index(stored) + 40                 # inside the body
    data[at] ^= 0x01
    archives.remember_password('password')
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(bytes(data), 'README')
    with pytest.raises(zip_aes.WrongPassword, match='authentication'):
        zip_aes.decrypt(zip_aes.stored_bytes(bytes(data), info), 'password',
                        3)


def test_zipcrypto_as_libarchive_reads_it():
    """test_read_format_zip_traditional_encryption_data.c: bar.txt and
    foo.txt, 495 bytes each, password '12345678'."""
    from trace_app.core import archives
    data = _uudecoded('zip_traditional_encryption_data.zip.uu')
    members = {m['name']: m for m in archives.list_members(data)
               if not m['is_dir']}
    assert {n: (m['size'], m['encrypted']) for n, m in members.items()} == \
        {'bar.txt': (495, True), 'foo.txt': (495, True)}
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(data, 'bar.txt')
    archives.remember_password('12345678')
    assert {n: len(archives.read_member(data, n)) for n in members} == \
        {'bar.txt': 495, 'foo.txt': 495}
    # A password passed directly works too, and a wrong one does not.
    archives.forget_passwords()
    assert len(archives.read_member(data, 'foo.txt',
                                    password='12345678')) == 495
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(data, 'foo.txt', password='nope')


def test_7z_aes_data_and_names():
    """test_read_format_7zip_encryption*.c: bar.txt, 4 bytes, password
    '12345678' -- data encrypted, then names encrypted too (nothing can be
    listed without it)."""
    from trace_app.core import archives
    data = _uudecoded('7zip_encryption.7z.uu')
    [member] = archives.list_members(data)
    assert (member['name'], member['size'], member['encrypted']) == \
        ('bar.txt', 4, True)
    with pytest.raises(archives.EncryptedArchive):
        archives.read_member(data, 'bar.txt')
    archives.remember_password('not-it')
    archives.remember_password('12345678')
    assert archives.read_member(data, 'bar.txt') == b'foo\n'
    archives.forget_passwords()
    hidden = _uudecoded('7zip_encryption_header.7z.uu')
    with pytest.raises(archives.EncryptedArchive):
        archives.list_members(hidden)
    archives.remember_password('12345678')
    assert [m['name'] for m in archives.list_members(hidden)] == ['bar.txt']
    assert archives.read_member(hidden, 'bar.txt') == b'foo\n'
