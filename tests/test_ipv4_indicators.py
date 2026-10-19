"""IPv4 addresses among the indicators: judged in context.

The contexts are those an examiner's own case turned up (a flash drive
with Windows and source archives): 117 "addresses", of which one was an
address -- .NET assembly versions, file versions, OIDs, SVG path data,
package versions, version folders. Each must stay out; real addresses in
logs, URLs, UNC paths and configs must stay in.
"""

import sqlite3

import pytest


def _ips(text):
    from trace_app.core.search_index import entities_of
    return sorted(v for k, v in entities_of(text) if k == 'ip')


@pytest.mark.parametrize('text', [
    'org="com.mchange" name="c3p0" rev="0.9.5.5" />',
    'lib/c3p0-0.9.5.5.jar;lib/mchange-commons',
    'Microsoft.PowerShell.Commands.Management, Version=1.0.0.0, Culture=',
    'system.reflection.metadata, version=1.0.11.0, culture=neutral',
    'ImDisk Virtual Disk Driver\nFileVersion\n2.0.10.49\nInternalName',
    'ImDisk Virtual Disk Driver\x00FileVersion\x002.0.10.64\x00',
    '#define SQLITE_VERSION        "3.8.11.1"',
    '** version 3.8.11.1.  By combining all the individual',
    'versions of SQLite up to and including 3.6.23.1, a call to',
    'VirtualDubMod 1.5.4.1 (build 2178/release)',
    'update the affected app (Huawei PC Manager) to 11.1.6.31 or later.',
    '<b>activesupport 6.1.4.4 - MIT</b>',
    '# Doxyfile 1.8.1.2',
    'ANSI STD 1003.1 (1996)\n** section 6.5.2.2 lines 483',
    '1.3.6.1.4.1.311.10.3.6',                       # an OID
    '2.16.840.1.101.3.4.2.1',
    'Failed to encode the extended key usage\n2.5.29.37\nFailed',
    '*\\ 2.11.92.0.12\\ *) supports_anon_versioning=yes',
    'Releases of the GNU linker prior to 2.16.91.0.3 cannot',
    'm17.66 5.41.92.92-2.69 2.69-.92-.92',          # SVG path data
    '.18.3.44.56.76.74.32.18.68.28 1.06.28h2.85',
    '.!.".#.$.%.&.\'.(.).*.+.,.-.../.0.1.2.3.4.5.6.7.8.9.:.;',
    '<simsong@108.56.242.10.in-addr.arpa>',
    'amd64~~10.1.1.1\nSystem32',
    '\\windowspowershell\\modules\\packagemanagement\\1.0.0.1|microsoft',
    '%WINDIR%\\servicing\\0.0.0.1\\',
    'Looking for Chrome version folder under\n0.0.0.0\n',
    'subnetMask\n255.255.255.0\n',
    'Upgrade\n255.255.255.255\n',
    'RFC 5245 - 4.1.2.1.',
    'MSI 3.1 to be installed\n2.0.0.0\n3.0.0.0\n',
])
def test_a_version_or_number_is_not_an_address(text):
    assert _ips(text) == []


@pytest.mark.parametrize('text, address', [
    ('Accepted password for root from 192.168.1.20 port 22',
     '192.168.1.20'),
    ('Failed password for invalid user admin from 45.33.32.156 port 4022',
     '45.33.32.156'),
    ('GET http://93.184.216.34/index.html', '93.184.216.34'),
    ('net use \\\\10.0.0.5\\share', '10.0.0.5'),
    ('client 172.16.4.17:443 connected', '172.16.4.17'),
    ('host=203.0.113.9;port=3389', '203.0.113.9'),
    ('nameserver 8.8.8.8', '8.8.8.8'),
    ('DNS 1.1.1.1', '1.1.1.1'),
    ('allow 10.0.0.0/8', '10.0.0.0'),
    ('listening on 127.0.0.1', '127.0.0.1'),
    ('"RemoteAddress":"52.114.128.10"', '52.114.128.10'),
    ('Connected to 10.10.10.25.', '10.10.10.25'),
])
def test_an_address_is_kept(text, address):
    assert _ips(text) == [address]


def test_a_version_6_index_rejudges_its_addresses(tmp_path):
    """Indexes already built keep their hours of work: each item's
    addresses are found again from its stored text under the new rules."""
    from trace_app.core.search_index import INDEX_VERSION, SearchIndex
    index = SearchIndex(str(tmp_path))
    item = index.add_item(1, 'p0:i5:s1', 'file', 'app.config', '/app.config',
                          body='Version=4.0.0.0 then host=203.0.113.9')
    index.commit()
    index.close()
    db = sqlite3.connect(str(tmp_path / 'search.db'))
    # As version 6 found them.
    db.execute("DELETE FROM entities WHERE kind = 'ip'")
    db.executemany("INSERT INTO entities (item_id, evidence_id, kind, value) "
                   "VALUES (?, 1, 'ip', ?)",
                   [(item, '4.0.0.0'), (item, '203.0.113.9')])
    db.execute("PRAGMA user_version = 6")
    db.commit()
    db.close()
    index = SearchIndex(str(tmp_path))
    try:
        assert index._db.execute("PRAGMA user_version").fetchone()[0] == \
            INDEX_VERSION
        assert [r[0] for r in index._db.execute(
            "SELECT value FROM entities WHERE kind = 'ip'")] == \
            ['203.0.113.9']
        assert index.statistics()['items'] == 1
    finally:
        index.close()
