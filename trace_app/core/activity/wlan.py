"""Windows' saved Wi-Fi networks (WLAN AutoConfig profiles).

Windows keeps each wireless network it has been told to remember as an XML
file, %ProgramData%\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\{adapter
GUID}\\{profile GUID}.xml (Vista on), in the WLAN profile schema Microsoft
documents (http://www.microsoft.com/networking/WLAN/profile/v1..v4): the
profile's name, the SSID (as text and hex), whether it is hidden, how it
connects (automatically or not, ESS or ad hoc), and its security --
authentication, encryption, 802.1X. The registry's NetworkList says when a
network was first and last connected; this says which networks the machine
knew and how they were secured, per adapter.

**Key material is never read**: Windows stores the passphrase encrypted
(`protected` true) -- and an exported profile can hold it in clear -- so a
record says only that a key is kept and of what kind.
"""

import xml.etree.ElementTree as ET

from trace_app.core.activity import record

PROFILES = ('ProgramData', 'Microsoft', 'Wlansvc', 'Profiles', 'Interfaces')


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def _find(element, *path):
    """The first descendant along `path` (local names, any namespace)."""
    for name in path:
        if element is None:
            return None
        element = next((child for child in element
                        if _local(child.tag) == name), None)
    return element


def _text(element, *path):
    found = _find(element, *path)
    return (found.text or '').strip() if found is not None and \
        found.text else ''


def parse(data):
    """The facts of one WLAN profile XML, or None if it is not one. The
    key material is skipped."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    if _local(root.tag) != 'WLANProfile':
        return None
    ssid = _find(root, 'SSIDConfig', 'SSID')
    security = _find(root, 'MSM', 'security')
    shared = _find(security, 'sharedKey') if security is not None else None
    facts = {
        'profile': _text(root, 'name'),
        'ssid': _text(ssid, 'name') if ssid is not None else '',
        'ssid_hex': _text(ssid, 'hex') if ssid is not None else '',
        'hidden': _text(root, 'SSIDConfig', 'nonBroadcast').lower() == 'true',
        'type': _text(root, 'connectionType'),
        'mode': _text(root, 'connectionMode'),
        'auto_switch': _text(root, 'autoSwitch').lower() == 'true' or None,
        'authentication': _text(security, 'authEncryption',
                                'authentication') if security is not None
        else '',
        'encryption': _text(security, 'authEncryption', 'encryption')
        if security is not None else '',
        'one_x': _text(security, 'authEncryption', 'useOneX').lower()
        == 'true' if security is not None else False,
        'key': None,
        'mac_randomization': _text(root, 'MacRandomization',
                                   'enableRandomization') or None,
    }
    if shared is not None:
        kind = _text(shared, 'keyType')
        protected = _text(shared, 'protected').lower() == 'true'
        facts['key'] = (f"{kind or 'key'} kept, "
                        f"{'encrypted' if protected else 'in clear'} "
                        f"(not copied)")
    if not facts['ssid'] and facts['ssid_hex']:
        try:
            facts['ssid'] = bytes.fromhex(facts['ssid_hex']).decode(
                'utf-8', 'replace')
        except ValueError:
            pass
    return facts


def profile_record(facts, entry, ref, adapter=''):
    open_network = facts['authentication'].lower() == 'open' and \
        facts['encryption'].lower() == 'none'
    return record(
        'network', 'Wi-Fi profile (WLAN AutoConfig)', entry.modified,
        'Wi-Fi network remembered', facts['ssid'] or facts['profile'],
        {'profile name': facts['profile'],
         'SSID (hex)': facts['ssid_hex'],
         'hidden network': 'yes' if facts['hidden'] else None,
         'connects': {'auto': 'automatically', 'manual': 'when asked'}.get(
             facts['mode'], facts['mode']),
         'network type': {'ESS': 'infrastructure', 'IBSS': 'ad hoc'}.get(
             facts['type'], facts['type']),
         'authentication': facts['authentication'],
         'encryption': facts['encryption'],
         '802.1X': 'yes' if facts['one_x'] else None,
         'open network': 'yes' if open_network else None,
         'key': facts['key'],
         'MAC randomisation': facts['mac_randomization'],
         'adapter': adapter or None,
         'profile file created': entry.created,
         'basis': "the profile file's last-written time; NetworkList in "
                  "the SOFTWARE hive dates the connections"},
        path=entry.path, ref=ref)


def records(volume, step):
    out = []
    interfaces = volume.find(*PROFILES)
    for adapter in volume.children(interfaces, dirs=True):
        for entry in volume.children(adapter, '.xml'):
            step(entry.path)
            facts = parse(volume.read(entry))
            if facts is None:
                continue
            out.append(profile_record(facts, entry, volume.ref(entry),
                                      adapter.name))
    return out
