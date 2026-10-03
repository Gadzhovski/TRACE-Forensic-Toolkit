"""Linux, macOS, chat and cloud-sync evidence (core/activity/linux.py,
journal.py, macos.py, macbookmark.py, chat.py).

Plaso's test files, with the values plaso's own tests expect for them;
dissect.target's recently-used.xbel; wader/fq's .sfl2 shared file lists.
On NIST's Ubuntu image (ubnist1, local only) the whole run is checked
end to end.
"""

import datetime
import os

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
UTC = datetime.timezone.utc


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run tools/fetch_artifact_samples.py")
    with open(path, 'rb') as handle:
        return handle.read()


def at(*parts, micro=0):
    return datetime.datetime(*parts, micro, tzinfo=UTC)


# --- Linux ------------------------------------------------------------------------

def test_bash_history_timed_untimed_and_multi_line():
    from trace_app.core.activity import linux
    items = linux.bash_history(sample('bash_history').decode())
    assert len(items) == 4
    assert items[0] == (at(2013, 10, 1, 12, 36, 17), '/usr/lib/plaso')
    assert items[3] == (at(2021, 6, 10, 22, 30, 36),
                        'binary argument1 "--params=\\ param1=foo, '
                        'param2=bar " argument2')
    desync = linux.bash_history(sample('bash_history_desync').decode())
    assert len(desync) == 5 and desync[0] == (None, '/sbin/reboot')
    assert desync[1] == (at(2013, 10, 1, 12, 36, 17), '/usr/lib/plaso')
    # A history without HISTTIMEFORMAT: every line, in order, no time.
    assert linux.bash_history('ls\ncd /tmp\n') == [(None, 'ls'),
                                                   (None, 'cd /tmp')]


def test_zsh_and_fish_histories():
    from trace_app.core.activity import linux
    zsh = linux.zsh_history(sample('zsh_extended_history.txt').decode())
    assert len(zsh) == 4
    assert zsh[0] == (at(2016, 3, 12, 8, 26, 50), 0, 'cd plaso')
    fish = linux.fish_history(sample('fish_history').decode())
    assert len(fish) == 10
    assert fish[0][:2] == (at(2021, 4, 29, 22, 53), 'll')
    assert fish[3][2] == ['test']


def test_wtmp_and_utmp():
    from trace_app.core.activity import linux
    records = linux.utmp_records(sample('wtmp.1'))
    first = records[0]
    assert (first['user'], first['terminal'], first['host'], first['ip'],
            first['pid'], first['type'], first['terminal_id']) == \
        ('userA', 'pts/32', '10.10.122.1', '10.10.122.1', 20060, 7,
         842084211)
    assert first['time'] == at(2011, 12, 1, 17, 36, 38, micro=432935)
    activity = linux.wtmp_activity(sample('wtmp.1'), '/var/log/wtmp.1', 'r')
    assert activity[0]['what'] == 'Remote logon'
    assert activity[0]['subject'] == 'userA on pts/32 from 10.10.122.1'
    assert any(r['what'] == 'Logoff' for r in activity)
    failed = linux.wtmp_activity(sample('wtmp.1'), '/var/log/btmp', 'r',
                                 failed=True)
    assert {r['what'] for r in failed} == {'Failed logon'}
    assert linux.utmp_records(sample('utmp_x86_64'))


def test_journal_entries_xz_lz4_and_what_is_kept():
    from trace_app.core.activity import journal, linux
    reader = journal.Journal(sample('system.journal'))
    entries = list(reader.entries())
    assert len(entries) == 2101                         # plaso: 2101
    first = entries[0]
    assert first['MESSAGE'] == 'Started User Manager for UID 1000.'
    assert first['_REALTIME'] == at(2017, 1, 27, 9, 40, 55, micro=913258)
    assert journal.source_time(first) == \
        at(2017, 1, 27, 9, 40, 55, micro=855726)
    xz = entries[2098]                                  # an XZ field
    assert xz['MESSAGE'] == 'a' * 692 and xz['SYSLOG_IDENTIFIER'] == 'root'
    lz4 = list(journal.Journal(sample('system.journal.lz4')).entries())
    assert len(lz4) == 85                               # plaso: 85
    assert lz4[0]['MESSAGE'] == 'Reached target Paths.'
    records, count = linux.journal_activity(sample('system.journal'),
                                            'p', 'r')
    assert count == 2101
    what = [r['what'] for r in records]
    assert what.count('Remote logon (SSH)') == 2
    ssh = next(r for r in records if r['what'] == 'Remote logon (SSH)')
    assert ssh['subject'] == 'test from 10.0.2.2' and ssh['user'] == 'test'
    sudo = next(r for r in records if r['what'].endswith('(sudo)'))
    assert sudo['subject'] == '/bin/bash'
    assert sudo['detail']['terminal'] == 'pts/6'
    assert 'CRON' not in str(records)                   # noise left out


def test_a_zstd_journal_is_listed_not_dropped():
    from trace_app.core.activity import journal
    reader = journal.Journal(sample('user-1000.journal'))
    (entry,) = list(reader.entries())
    assert reader.compact
    if journal.zstd_available():
        assert entry.get('MESSAGE')
    else:
        assert entry[journal.UNDECODED] > 0


def test_lz4_block_overlapping_copy():
    from trace_app.core.activity import journal
    # "abc" then a match of 9 at offset 3: abcabcabcabc.
    block = bytes([0x35]) + b'abc' + bytes([3, 0])
    assert journal.lz4_block(block) == b'abc' * 4


def test_recently_used_xbel():
    from trace_app.core.activity import linux
    items = linux.recently_used(sample('recently-used.xbel'))
    first = items[0]
    assert first['href'] == 'file:///home/sjaak/.profile'
    assert first['visited'] == at(2023, 10, 18, 13, 12, 41, micro=905277)
    assert first['added'] == at(2023, 10, 18, 13, 12, 41, micro=905276)
    assert first['modified'] == at(2023, 10, 18, 13, 14, 9, micro=483576)
    assert first['mime'] == 'text/plain'
    assert first['apps'][0][0] == 'gedit'
    # dissect's 15 records are these 7 files, their 7 applications and
    # one icon.
    assert len(items) == 7 and sum(len(i['apps']) for i in items) == 7


def test_auth_log_lines_without_a_year():
    from trace_app.core.activity import linux
    text = ("Dec 31 23:59:01 box sshd[1]: Accepted publickey for ann from "
            "10.1.1.1 port 22 ssh2\n"
            "Jan  1 00:00:05 box sudo:      ann : TTY=pts/0 ; PWD=/home/ann "
            "; USER=root ; COMMAND=/usr/bin/id\n"
            "Jan  1 00:01:00 box sshd[2]: Failed password for invalid user "
            "bob from 10.9.9.9 port 4242 ssh2\n")
    records = linux.syslog_activity(text, '/var/log/auth.log', 'r', 2024)
    assert [r['what'] for r in records] == [
        'Remote logon (SSH)', 'Command run as root (sudo)',
        'Failed SSH logon']
    assert records[0]['time'] == '2023-12-31 23:59:01'   # year stepped back
    assert records[1]['time'] == '2024-01-01 00:00:05'
    assert all(r['local'] for r in records)
    assert records[2]['detail']['account exists'] == 'no'


# --- macOS ----------------------------------------------------------------------------

def test_knowledgec():
    from trace_app.core.activity import macos
    high_sierra = macos.knowledgec(sample('knowledgec-10.13.db'))
    assert len(high_sierra) == 17                       # plaso: 17
    first = high_sierra[0]
    assert first['value'] == 'com.apple.Installer-Progress'
    assert (first['start'], first['end'], first['seconds']) == \
        (at(2019, 2, 10, 16, 59, 57), at(2019, 2, 10, 16, 59, 58), 1)
    mojave = macos.knowledgec(sample('knowledgec-10.14.db'))
    assert len(mojave) == 77                            # plaso: 77
    assert (mojave[75]['value'], mojave[75]['seconds']) == \
        ('com.apple.Terminal', 1041)
    assert (mojave[70]['value'], mojave[70]['title']) == \
        ('https://www.instagram.com/', 'Instagram')
    records = macos.knowledgec_activity(sample('knowledgec-10.14.db'), None,
                                        'u', 'p', 'r')
    assert records[70]['category'] == 'browser'
    assert records[75]['what'] == 'Application in use'


def test_quarantine_install_history_and_utmpx():
    from trace_app.core.activity import macos
    downloads = macos.quarantine_activity(sample('quarantine.db'), None,
                                          'u', 'p', 'r')
    assert len(downloads) == 14                         # plaso: 14
    assert downloads[10]['time'] == '2013-07-12 19:30:16'
    assert downloads[10]['detail']['application'] == 'Google Chrome'
    assert downloads[10]['subject'].startswith(
        'http://download.mackeeper.zeobit.com/package.php?key=460245286')
    installs = macos.install_history(sample('InstallHistory.plist'))
    assert len(installs) == 7                           # plaso: 7
    assert (installs[0]['name'], installs[0]['version'],
            installs[0]['process']) == ('OS X', '10.9 (13A603)',
                                        'OS X Installer')
    assert installs[0]['time'] == at(2013, 11, 12, 2, 59, 35)
    assert len(installs[0]['packages']) == 14
    logons = macos.utmpx_records(sample('utmpx_mac'))
    moxilo = next(r for r in logons if r['pid'] == 67)
    assert (moxilo['user'], moxilo['terminal'], moxilo['terminal_id'],
            moxilo['type']) == ('moxilo', 'console', 65583, 7)
    assert moxilo['time'] == at(2013, 11, 13, 17, 52, 41, micro=736713)


def test_shared_file_lists_and_bookmarks():
    from trace_app.core.activity import macos
    documents = macos.shared_file_list(sample('recentdocs.sfl2'))
    assert len(documents) == 10
    assert documents[0]['path'] == \
        '/Users/davidvandriessen/Desktop/bin/book.pdf'
    assert documents[0]['volume'] == 'Macintosh HD'
    removable = next(d for d in documents
                     if d['path'] == '/Volumes/Untitled/file1.txt')
    assert removable['volume'] == 'Untitled'
    apps = macos.shared_file_list_activity(
        sample('recentapps.sfl2'),
        'com.apple.LSSharedFileList.RecentApplications.sfl2', 'u', 'p', 'r')
    assert apps[0]['what'] == 'Recent application'
    assert apps[0]['subject'] == '/System/Applications/Utilities/Terminal.app'
    assert apps[0]['detail']['order'] == 1


# --- chat and cloud ----------------------------------------------------------------

def _records(name):
    from trace_app.core.activity import chat
    return chat.read_database(sample(name), None, 'u', name, 'r')


def test_skype():
    records = _records('skype_main.db')
    message = next(r for r in records
                   if r['subject'] == 'need to know if you got it this time.')
    assert message['time'] == '2013-07-30 21:27:11'
    assert message['detail']['from'] == 'Gen Beringer <gen.beringer>'
    assert message['detail']['to'] == 'european.bbq.competitor'
    sms = next(r for r in records if r['what'] == 'SMS sent from Skype')
    assert sms['detail']['to'] == '+34123456789'
    assert sms['time'] == '2013-07-01 22:14:22'
    assert sms['subject'].startswith('If you want I can copy some documents')
    transfer = next(r for r in records if 'File sent' in r['what'])
    assert transfer['subject'] == 'secret-project.pdf'
    assert transfer['detail']['to'] == 'European BBQ <european.bbq.competitor>'
    assert transfer['detail']['path'] == \
        '/Users/gberinger/Desktop/secret-project.pdf'
    call = next(r for r in records if 'call' in r['what'])
    assert call['time'] == '2013-07-01 22:12:17'
    assert call['subject'] == 'European Competitor <european.bbq.competitor>'
    assert call['detail']['seconds'] == 646     # ends 22:23:03, as plaso's
    account = next(r for r in records if r['what'] == 'Skype account')
    assert account['detail']['email'] == 'genberinger@gmail.com'


def test_imessage_sms_and_dropbox():
    messages = _records('imessage_chat.db')
    assert len(messages) == 10                          # plaso: 10
    seventh = messages[7]
    assert seventh['subject'] == 'Did you try to send me a message?'
    assert seventh['time'] == '2015-11-30 10:48:40'
    assert seventh['detail']['from'] == 'xxxxxx2015@icloud.com'
    sms = _records('mmssms.db')
    assert len(sms) == 9                                # plaso: 9
    assert sms[0]['subject'] == 'Yo Fred this is my new number.'
    assert sms[0]['what'] == 'SMS sent'
    assert sms[0]['detail']['to'] == '1 555-521-5554'
    assert sms[0]['time'] == '2013-10-29 16:56:28'
    synced = _records('dropbox_sync_history.db')
    assert len(synced) == 6                             # plaso: 6
    assert synced[0]['subject'] == '/home/useraa/Dropbox/loc1/create_local.txt'
    assert synced[0]['what'] == 'Dropbox: add uploaded'
    assert synced[0]['time'] == '2022-02-17 10:57:18'


def test_a_carved_database_is_read_the_same_way():
    from trace_app.core.activity import chat
    records = chat.read_database(sample('mmssms.db'), None, '', 'x', 'r',
                                 carved=True)
    assert records and all(r['source'] == 'Android SMS (carved)'
                           for r in records)
    assert chat.read_database(b'not a database', None, '', 'x', 'r') == []


def test_google_drive_and_onedrive_logs():
    from trace_app.core.activity import chat
    text = sample('gdrive_sync_log.log').decode('utf-8')
    lines = chat.gdrive_log(text)
    assert len(lines) == 2190                           # plaso: 2190
    when, level, message = lines[2]
    assert message == 'SSL: OpenSSL 1.0.2m  2 Nov 2017' and level == 'INFO'
    assert when.isoformat(timespec='milliseconds') == \
        '2018-01-24T18:25:08.456-08:00'
    records = chat.gdrive_activity(text, 'John', 'p', 'r')
    assert records[0]['what'] == 'Google Drive account in use'
    assert records[0]['subject'] == 'johngalvin-fake-account@gmail.com'
    assert any(r['subject'] == 'New Document.gdoc' for r in records)
    starts = chat.onedrive_log_activity(
        sample('skydrive.log').decode('utf-8', 'replace'), 'u', 'p', 'r')
    assert starts[0]['time'] == '2013-08-12 01:08:52'
    assert starts[0]['subject'] == 'version 16.4.6012.0828'
    old = chat.onedrive_log_activity(
        sample('skydrive_v1.log').decode('utf-8', 'replace'), 'u', 'p', 'r')
    assert old[0]['time'] == '2013-08-01 21:22:28'


def test_a_real_ubuntu_image_end_to_end():
    """NIST's ubnist1 (local only): logons, sudo, the user's commands and
    the files GTK remembers, from one run."""
    from trace_app.core import activity
    from trace_app.core.image_handler import ImageHandler
    from tests.conftest import IMAGE_DIR
    path = os.path.join(IMAGE_DIR, 'ubnist1.casper-rw.gen3.E01')
    if not os.path.exists(path):
        pytest.skip("ubnist1.casper-rw.gen3.E01 is not in test_images/")
    handler = ImageHandler(path)
    assert handler.load_image()
    try:
        records = activity.collect(handler)
    finally:
        handler.close_resources()
    sources = {r['source'] for r in records}
    assert {'wtmp', 'bash history', 'syslog',
            'recently-used.xbel'} <= sources
    commands = [r['subject'] for r in records if r['source'] == 'bash history']
    assert 'scp /mnt/ubnist1.gen0.raw simsong@192.168.15.62:.' in commands
    boots = [r for r in records if r['what'] == 'System boot']
    assert boots and boots[0]['subject'].startswith('kernel ')
    assert any(r['subject'] == '/tmp/sp800-30.pdf' for r in records)
