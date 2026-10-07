"""Virtual disks, BitLocker, Volume Shadow Copies and Outlook mailboxes.

The images are dfvfs's published test data, the mailboxes java-libpst's
(all fetched and SHA-256 pinned by tools/fetch_artifact_samples.py and
tools/carve_corpus.py). What each holds is fixed, so the assertions are about
content -- a file's bytes, a snapshot's files -- not merely "it opened".
"""

import datetime
import io
import os
import shutil

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
CARVE_SAMPLES = os.path.join(ROOT, 'test_images', 'carve_samples')

PASSWORDS_NTFS = 126           # passwords.txt on the dfvfs NTFS volumes
BDE_PASSWORD = 'bde-TEST'      # dfvfs's own tests use this


def sample(name, folder=SAMPLES):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        message = f"{name} is missing -- run tools/fetch_artifact_samples.py"
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    return path


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return handler


def _names(handler, start):
    return {e['name'] for e in handler.get_directory_contents(start)}


def _read(handler, start, name):
    entry = next(e for e in handler.get_directory_contents(start)
                 if e['name'] == name)
    content, _meta = handler.get_file_content(entry['inode_number'], start)
    return content


# --- virtual disks ---------------------------------------------------------------

def test_a_vhd_opens_as_a_disk_with_its_partition():
    handler = _handler(sample('ntfs-dynamic.vhd'))
    try:
        assert handler.container_note == 'VHD'
        starts = [p[2] for p in handler.get_partitions()
                  if handler.has_filesystem(p[2])]
        assert starts == [128] and handler.get_fs_type(128) == 'NTFS'
        assert {'a_directory', 'passwords.txt'} <= _names(handler, 128)
        assert len(_read(handler, 128, 'passwords.txt')) == PASSWORDS_NTFS
    finally:
        handler.close_resources()


def test_a_differencing_vhdx_reads_through_its_parent(tmp_path):
    from trace_app.core.containers import ContainerError, open_virtual_disk
    parent = _handler(sample('ntfs-parent.vhdx'))
    try:
        # The parent alone: an empty volume. The files are the child's.
        assert 'passwords.txt' not in _names(parent, 128)
    finally:
        parent.close_resources()
    child = _handler(sample('ntfs-differential.vhdx'))
    try:
        assert child.container_note == 'VHDX, differencing (1 parent)'
        assert len(_read(child, 128, 'passwords.txt')) == PASSWORDS_NTFS
    finally:
        child.close_resources()
    # Without its parent beside it, a differencing disk says so.
    alone = tmp_path / 'ntfs-differential.vhdx'
    shutil.copy(sample('ntfs-differential.vhdx'), alone)
    with pytest.raises(ContainerError, match='parent'):
        open_virtual_disk(str(alone))


def test_a_vmdk_opens():
    handler = _handler(sample('ext2.vmdk'))
    try:
        assert handler.container_note == 'VMDK'
        assert handler.get_fs_type(0) == 'Ext2'
        assert _read(handler, 0, 'passwords.txt').startswith(
            b'place,user,password')
    finally:
        handler.close_resources()


def test_a_virtual_disk_is_hashed_by_its_contents():
    import hashlib
    handler = _handler(sample('ext2.vmdk'))
    try:
        size = handler.get_size()
        whole = handler.read(0, size)
        result = handler.calculate_hashes()
        assert result['size'] == size
        assert result['computed_md5'] == hashlib.md5(whole).hexdigest()
        assert result['computed_sha256'] == hashlib.sha256(whole).hexdigest()
    finally:
        handler.close_resources()


# --- BitLocker ---------------------------------------------------------------------

def test_bitlocker_to_go_is_detected_and_described():
    handler = _handler(sample('bdetogo.raw'))
    try:
        # TSK sees only the FAT32 "discovery volume" To Go puts in front.
        assert handler.get_fs_type(0) == 'FAT32'
        assert handler.is_bitlocker(0) and not handler.is_unlocked(0)
        facts = handler.bitlocker_facts(0)
        assert facts['description'] == 'TESTBOX1 H: 6/2/2014'
        assert set(facts['protectors']) == {'password', 'recovery password'}
        assert facts['method'] == 'AES-128-CBC with diffuser'
        assert not handler.is_bitlocker(-1)
    finally:
        handler.close_resources()


def test_bitlocker_refuses_a_wrong_key_and_opens_with_the_right_one():
    from trace_app.core.containers import ContainerError
    handler = _handler(sample('bdetogo.raw'))
    try:
        with pytest.raises(ContainerError, match='does not unlock'):
            handler.unlock_bitlocker(0, password='wrong')
        with pytest.raises(ContainerError, match='48 digits'):
            handler.unlock_bitlocker(0, recovery_password='123-456')
        assert not handler.is_unlocked(0)
        handler.unlock_bitlocker(0, password=BDE_PASSWORD)
        assert handler.is_unlocked(0)
        assert handler.get_fs_type(0) == 'FAT16'        # the real volume
        assert _read(handler, 0, 'passwords.txt').startswith(
            b'place,user,password\nbank,joesmith,superrich')
    finally:
        handler.close_resources()


def test_a_background_job_unlocks_with_the_key_it_is_handed():
    from trace_app.core import background
    handler = background._open_image(
        sample('bdetogo.raw'), {0: {'password': BDE_PASSWORD}})
    try:
        assert handler.is_unlocked(0)
        assert 'passwords.txt' in _names(handler, 0)
    finally:
        handler.close_resources()


# --- Volume Shadow Copies --------------------------------------------------------

def test_shadow_copies_are_volumes_as_they_were():
    from trace_app.core.containers import shadow_key, split_shadow_key
    handler = _handler(sample('vss.raw'))
    try:
        shadows = handler.shadow_copies(0)
        assert [s['index'] for s in shadows] == [0, 1]
        assert shadows[0]['created'] == datetime.datetime(
            2021, 5, 1, 17, 40, 3, 223030, tzinfo=datetime.timezone.utc)
        assert shadows[0]['key'] == shadow_key(0, 0)
        assert split_shadow_key(shadows[1]['key']) == (0, 1)
        live = _names(handler, 0)
        first = _names(handler, shadows[0]['key'])
        second = _names(handler, shadows[1]['key'])
        # Each snapshot is the volume before the next file was written.
        assert {'vss1', 'vss2'} <= live
        assert 'vss1' not in first and 'vss2' not in first
        assert 'vss1' in second and 'vss2' not in second
        assert _read(handler, shadows[1]['key'], 'vss1')
    finally:
        handler.close_resources()


def test_a_reference_into_a_snapshot_resolves_after_reopening():
    """A bookmark into a shadow copy names it by its key alone; a fresh
    handler -- a reopened case -- finds the snapshot from that."""
    from trace_app.core.case import make_artifact_ref, parse_artifact_ref
    from trace_app.core.containers import shadow_key
    handler = _handler(sample('vss.raw'))
    key = shadow_key(0, 1)
    try:
        entry = next(e for e in handler.get_directory_contents(key)
                     if e['name'] == 'vss1')
        ref = make_artifact_ref(key, entry['inode_number'])
        expected, _ = handler.get_file_content(entry['inode_number'], key)
    finally:
        handler.close_resources()
    parsed = parse_artifact_ref(ref)
    assert parsed['start_offset'] == key
    fresh = _handler(sample('vss.raw'))
    try:
        content, _ = fresh.get_file_content(parsed['inode'], key)
        assert content == expected
    finally:
        fresh.close_resources()


def test_a_volume_without_snapshots_has_none():
    handler = _handler(sample('ext2.vmdk'))
    try:
        assert handler.shadow_copies(0) == []
    finally:
        handler.close_resources()


# --- Outlook mailboxes ----------------------------------------------------------------

def test_a_pst_is_listed_like_an_archive():
    from trace_app.core import archives
    with open(sample('dist-list.pst', CARVE_SAMPLES), 'rb') as handle:
        data = handle.read()
    assert archives.detect_archive(data) == 'pst'
    members = {m['name']: m for m in archives.list_members(data)}
    appointment = 'Top of Personal Folders/Calendar/0001 Test appointment.html'
    assert appointment in members
    assert members[appointment]['modified'] == '2016-08-02 00:27:12'
    assert members['Top of Personal Folders/Inbox']['is_dir']
    attachments = [n for n in members if '- attachments/' in n]
    assert len(attachments) == 2
    assert len(archives.read_member(data, attachments[0])) == 928


def test_an_ost_message_reads_as_a_page_with_its_headers():
    from trace_app.core import archives
    with open(sample('example-2013.ost', CARVE_SAMPLES), 'rb') as handle:
        data = handle.read()
    name = 'Root - Mailbox/IPM_SUBTREE/Sent Items/0001 Test 2.html'
    page = archives.read_member(data, name).decode('utf-8')
    assert 'Bernard Chung &lt;bernard.chung@apogeephysicians.com&gt;' in page
    assert 'arc.test1@apogeephysicians.com' in page
    assert '2014-04-09 16:38:31' in page              # sent
    assert 'Transport headers' in page


def test_a_mailbox_is_read_lazily_through_a_file_object():
    from trace_app.core import archives
    from trace_app.core.containers import ByteWindow
    with open(sample('example-2013.ost', CARVE_SAMPLES), 'rb') as handle:
        data = handle.read()
    reads = []

    def reader(offset, length):
        reads.append(length)
        return data[offset:offset + length]

    stream = ByteWindow(reader, 0, len(data))
    assert archives.detect_archive(stream) == 'pst'
    members = archives.list_members(stream)
    assert any(m['name'].endswith('Test 2.html') for m in members)
    # Read in pieces, never the whole file at once.
    assert max(reads) < len(data)


def test_a_message_page_escapes_what_the_mail_says():
    """Headers come from whoever sent the mail: they are text, not markup."""
    from trace_app.core.mailbox import render_message

    class Message:
        subject = '<script>alert(1)</script> Invoice'
        sender_name = 'Mallory <img src=x onerror=alert(1)>'
        client_submit_time = datetime.datetime(2024, 1, 2, 3, 4, 5)
        delivery_time = creation_time = modification_time = None
        number_of_attachments = 0
        html_body = None
        plain_text_body = b'Pay <b>now</b>'
        rtf_body = None
        transport_headers = 'X-Evil: <iframe>'
        recipients = None
        number_of_record_sets = 0

    page = render_message(Message()).decode()
    assert '<script>' not in page and '&lt;script&gt;' in page
    assert '<img' not in page and '<iframe>' not in page
    assert 'Pay &lt;b&gt;now&lt;/b&gt;' in page
    assert '2024-01-02 03:04:05' in page


def test_rtf_bodies_are_shown_as_text():
    from trace_app.core.mailbox import rtf_text
    slash = chr(92)
    rtf = ('{' + slash + 'rtf1' + slash + 'ansi Hello' + slash + 'par W'
           + slash + "'f6rld " + slash + 'u8364?}').encode('ascii')
    assert rtf_text(rtf) == 'Hello\nW' + chr(0xF6) + 'rld ' + chr(0x20AC)


def test_mailbox_messages_are_indexed_with_their_indicators(tmp_path):
    from trace_app.core import indexer
    from trace_app.core.search_index import SearchIndex
    with open(sample('example-2013.ost', CARVE_SAMPLES), 'rb') as handle:
        data = handle.read()
    index = SearchIndex(str(tmp_path))
    try:
        indexer._index_archive(index, 1, 'p0:i5', data, '/mail.ost', 2)
        index.commit()
        hits = index.search('email:bernard.chung@apogeephysicians.com')
        assert any(h['name'].endswith('Test 2.html') for h in hits)
    finally:
        index.close()


def test_an_image_read_from_two_threads_reads_true():
    """The window and its workers read one image at once. libyal handles
    are not safe for that: on Linux and macOS a DMG read while another
    thread read returned wrong bytes, and its APFS container failed its
    superblock checksum (every time, with a second reader running)."""
    import hashlib
    import threading
    handler = _handler(sample('apfs_encrypted.dmg'))
    try:
        expected = hashlib.sha256(handler.read(0, handler.get_size()))
        expected = expected.hexdigest()
        stop = threading.Event()
        bad = []

        def other_reader():
            while not stop.is_set():
                if handler.read(3_000_000, 65536) != tail:
                    bad.append('other')
        tail = handler.read(3_000_000, 65536)
        thread = threading.Thread(target=other_reader)
        thread.start()
        try:
            for _ in range(10):
                whole = handler.read(0, handler.get_size())
                if hashlib.sha256(whole).hexdigest() != expected:
                    bad.append('main')
                handler._apfs.clear()
                assert handler.apfs_volumes(40), "APFS container unreadable"
        finally:
            stop.set()
            thread.join()
        assert not bad
    finally:
        handler.close_resources()
