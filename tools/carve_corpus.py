"""A carving test image built from real, published files of every format.

The DFTT and DFRWS images test carving against answer keys, but they hold
only the formats of their day. For the rest -- SQLite, registry hives, EVTX,
PST, LNK, Office Open XML, HEIC, Opus, Matroska, Mach-O and so on -- this
builds an image the same way the DFRWS authors did: real files, taken from the
test suites and sample collections of projects that publish them, each pinned
by SHA-256, placed on sector boundaries among random filler.

    python tools/carve_corpus.py            fetch samples, build the image,
                                            write its answer key
    python tools/carve_score.py carve-corpus.dd

The image is deterministic -- a fixed seed and pinned inputs -- so its answer
key in tools/carve_ground_truth.json is stable and committed. Between the
files are decoys: each format's signature followed by junk, which a carver
that trusts signatures will "recover". None should be carved; the scorer
reports anything that is as an unaccounted carve.

Nothing downloaded is committed: the samples land in test_images/carve_samples
(gitignored, like every test image) and are verified before use.
"""

import base64
import gzip
import hashlib
import io
import json
import os
import random
import sys
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SAMPLES = os.path.join(ROOT, 'test_images', 'carve_samples')
IMAGE = os.path.join(ROOT, 'test_images', 'carve-corpus.dd')
TRUTH = os.path.join(HERE, 'carve_ground_truth.json')
SECTOR = 512
SEED = 20261002

_GH = 'https://raw.githubusercontent.com'

#: (name, type, url, sha256 of the download, how to turn it into the file).
#: `type` is the extension TRACE should carve it as. `unpack` is None, or
#: ('zip', member), ('targz', member), ('gunzip',) or ('base64',).
CATALOG = [
    # Pictures
    ('hopper.psd', 'psd', f'{_GH}/python-pillow/Pillow/main/Tests/images/hopper.psd', '108d58d6470f4787e8d16893d965a211efce0b28abdcb11e1b18af8081b96370', None),
    ('hopper.webp', 'webp', f'{_GH}/python-pillow/Pillow/main/Tests/images/hopper.webp', '3ad1cd060bff97c8090ca68efe9e25724e830bf5383397ffe7f448d5b825c6ad', None),
    ('gallery-1.webp', 'webp', 'https://www.gstatic.com/webp/gallery/1.webp', '4a5afeaff8483923da964bc7896f02d0283e8bff99b5b8f82a31ae3214dab1d0', None),
    ('hopper.avif', 'avif', f'{_GH}/python-pillow/Pillow/main/Tests/images/avif/hopper.avif', 'd4327b7ab11ed8f11d86978258fc04e5505bcfe511ca2c4efa4838c85d226fd2', None),
    ('example.heic', 'heic', f'{_GH}/strukturag/libheif/master/examples/example.heic', '7f8b363e4936c0666a25f64f3a92fda10bd8e5453be4592530b65a55dd98f3f2', None),
    # Documents
    ('test.docx', 'docx', f'{_GH}/python-openxml/python-docx/master/tests/test_files/test.docx', 'fba1c76b66ff30982e5281941ca1111eaeaeb092abb6dfbe1730bed3774f40b6', None),
    ('test.pptx', 'pptx', f'{_GH}/scanny/python-pptx/master/tests/test_files/test.pptx', '8765677cdf43181ef41657cedf28485b5f2cbf166667218c217af07f8336c96f', None),
    ('sample1.xlsx', 'xlsx', 'https://filesamples.com/samples/document/xlsx/sample1.xlsx', '3cf0f4791bec46c988b6a7a1064bf9f6e843e1d6a682fa9cc85b402495905fee', None),
    ('sample1.odt', 'odt', 'https://filesamples.com/samples/document/odt/sample1.odt', 'b1cbd771d3b5a7b0e02c7ecbf7330e2ca21c00d9aac88eea878b75fd9dbca23a', None),
    ('sample1.ods', 'ods', 'https://filesamples.com/samples/document/ods/sample1.ods', 'fc8a52b91eae638f19c79e513882e6a40af5518cddf1cba3a94da1db0938bf3c', None),
    ('sample1.odp', 'odp', 'https://filesamples.com/samples/document/odp/sample1.odp', 'cf44bad041029b78c5423be2ecf826605a87527e760b8a19f86c36c45167423b', None),
    ('accessible_epub_3.epub', 'epub', 'https://github.com/IDPF/epub3-samples/releases/download/20230704/accessible_epub_3.epub', '67f75b8e3cd1abe4bb143d91d5424191d5af3115c9d26ff029a38e19f8d16feb', None),
    ('sample1.rtf', 'rtf', 'https://filesamples.com/samples/document/rtf/sample1.rtf', 'a5fd556610a5719f1b00f3f80e1fe279a465a7cb1a9855da25fb867509500a3d', None),
    # Email
    ('dist-list.pst', 'pst', f'{_GH}/rjohnsondev/java-libpst/develop/src/test/resources/dist-list.pst', 'c86841da106036b5abe5a2141dc7644cbb2bf8b504873515eb35a2efeb8c28ac', None),
    ('passworded.pst', 'pst', f'{_GH}/rjohnsondev/java-libpst/develop/src/test/resources/passworded.pst', 'e1085e210bc823fcfbdd1220da08b51423f3c39301c563a99dde71895f2af217', None),
    ('example-2013.ost', 'ost', f'{_GH}/rjohnsondev/java-libpst/develop/src/test/resources/example-2013.ost', 'b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d', None),
    ('cpython-msg_01.eml', 'eml', f'{_GH}/python/cpython/v3.12.0/Lib/test/test_email/data/msg_01.txt', 'c15a3a17f6b65e9c51c58ed3a79d12bc517f867321ed118e5dc7b5c3a1ed7d4b', None),
    ('cpython-msg_02.eml', 'eml', f'{_GH}/python/cpython/v3.12.0/Lib/test/test_email/data/msg_02.txt', '05d5e533f5e590d9ee2c7692d26dc87ccbf381f4831cca3362baf596691a55bb', None),
    # Databases and logs
    ('Chinook_Sqlite.sqlite', 'sqlite', f'{_GH}/lerocha/chinook-database/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite', '7651ba378ac2fcd0dfc3c66fb101f7a7eed3ba39a612ec642b96e20702061f15', None),
    ('system.evtx', 'evtx', f'{_GH}/williballenthin/python-evtx/master/tests/data/system.evtx', 'ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e', None),
    ('security.evtx', 'evtx', f'{_GH}/williballenthin/python-evtx/master/tests/data/security.evtx', '5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d', None),
    ('StringValuesHive', 'regf', f'{_GH}/msuhanov/yarp/master/hives_for_tests/StringValuesHive', '711f6a66b304ce6b4ae6424d861d54f26657cfda91746ed8494a64924fa24747', None),
    ('BigDataHive', 'regf', f'{_GH}/msuhanov/yarp/master/hives_for_tests/BigDataHive', 'e8cdd62bd816aaede3404314ce5f6710c03c4538b1481da597462d01539e0617', None),
    # Windows artifacts -- LnkParse3 keeps its samples base64-encoded
    ('microsoft_example.lnk', 'lnk', f'{_GH}/Matmaus/LnkParse3/master/tests/samples/microsoft_example', 'adce00c167bb2479de86a90dcb17a252c16289f8098cfb13d9bcbffd6ec5b0c9', ('base64',)),
    ('sample.lnk', 'lnk', f'{_GH}/Matmaus/LnkParse3/master/tests/samples/sample', 'e69c9edd26718d0f4340f0124a1d06f04f9b1a202d7103c51a0588e50e73b980', ('base64',)),
    ('sample2.lnk', 'lnk', f'{_GH}/Matmaus/LnkParse3/master/tests/samples/sample2', '3031234e9b97d47d08fc36687154e915127760b91973a4c4105f55a5d4bc7099', ('base64',)),
    # Executables
    ('pageant.exe', 'exe', 'https://the.earth.li/~sgtatham/putty/0.83/w64/pageant.exe', '267d8be2912e897cd1cebe6dbde73c1e0ceb9bd865fd17817dd9debed6151de1', None),
    ('sqlite3.dll', 'dll', 'https://www.sqlite.org/2024/sqlite-dll-win-x64-3460000.zip', '87c8394712418dcc4a608fdc34c0a23a89a41e626b9e3294c0978bb2bda0a0d1', ('zip', 'sqlite3.dll')),
    ('busybox', 'elf', 'https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox', '6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348', None),
    ('rg', 'macho', 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-apple-darwin.tar.gz', 'fc87e78f7cb3fea12d69072e7ef3b21509754717b746368fd40d88963630e2b3', ('targz', 'ripgrep-14.1.1-x86_64-apple-darwin/rg')),
    ('junit-4.13.2.jar', 'jar', 'https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar', '8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3', None),
    ('TestActivity.apk', 'apk', f'{_GH}/androguard/androguard/master/tests/data/APK/TestActivity.apk', '3bb32dd50129690bce850124ea120aa334e708eaa7987cf2329fd1ea0467a0eb', None),
    # Archives
    ('hello-2.12.1.tar.gz', 'gz', 'https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz', '8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20', None),
    ('ripgrep-14.1.1-x86_64-apple-darwin.tar', 'tar', 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-apple-darwin.tar.gz', 'fc87e78f7cb3fea12d69072e7ef3b21509754717b746368fd40d88963630e2b3', ('gunzip',)),
    ('patch-2.7.6.tar.bz2', 'bz2', 'https://ftp.gnu.org/gnu/patch/patch-2.7.6.tar.bz2', '3d1d001210d76c9f754c12824aa69f25de7cb27bb6765df63455b77601a0dcc9', None),
    ('sed-4.9.tar.xz', 'xz', 'https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz', '6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181', None),
    # Audio
    ('Example.ogg', 'ogg', 'https://upload.wikimedia.org/wikipedia/commons/c/c8/Example.ogg', 'f57b56d8aae4c847cf01224fb45293610d801cfdac43d932b5eeab1cd318182a', None),
    ('sample1.opus', 'opus', 'https://filesamples.com/samples/audio/opus/sample1.opus', 'e573982a0f68fa98144cfcc04024fd05ed05713746205cd500e37c2b6dbd0557', None),
    ('sample1.m4a', 'm4a', 'https://filesamples.com/samples/audio/m4a/sample1.m4a', 'bea08a6237bb52ebf76da88e35ec44fb43aee922a6dabeadc184dc805b0d9ecb', None),
    # Video
    ('bbb-360-10s.mkv', 'mp4', 'https://test-videos.co.uk/vids/bigbuckbunny/mkv/360/Big_Buck_Bunny_360_10s_1MB.mkv', '8d8c580e2b0e8632bcf28b8591b6d18b47d0c86b684f6fe1cd5022b4462069da', None),
    ('bbb-360-10s.webm', 'webm', 'https://test-videos.co.uk/vids/bigbuckbunny/webm/vp9/360/Big_Buck_Bunny_360_10s_1MB.webm', '6b2afedd9fa041fdff5d9e1d6d909c393268669005041c572abcc5923c939c58', None),
    ('sample_640x360.mkv', 'mkv', 'https://filesamples.com/samples/video/mkv/sample_640x360.mkv', '534943eee427a8095bdc7d5452054e1fc4485a566f6ed54337a90f9d37499031', None),
    ('matroska-test1.mkv', 'mkv', 'https://raw.githubusercontent.com/ietf-wg-cellar/matroska-test-files/master/test_files/test1.mkv', '0996a309ff2095910b9d30d5253b044d637154297ddf7d0bda7f3adedf5addc1', None),
    ('sample_640x360.3gp', '3gp', 'https://filesamples.com/samples/video/3gp/sample_640x360.3gp', '91db0d3f84d623fca2b98b00d3308fa1ecfbb40420cda5b6bac57c8824614049', None),
]

#: What can honestly be carved of a file whose format records less than the
#: file holds: the bytes the format accounts for. (name -> reason). The
#: scorer compares against that prefix, and says so.
LOGICAL_ONLY = {
    'StringValuesHive': "hive slack after the last hbin has no recorded length",
    'BigDataHive': "hive slack after the last hbin has no recorded length",
    'security.evtx': "the zero-filled space preallocated after the last chunk "
                     "has no recorded length",
    'system.evtx': "the zero-filled space preallocated after the last chunk "
                   "has no recorded length",
}

#: Files whole inside other samples, which a carver rightly recovers too: an
#: uncompressed tar stores its members as they are, on 512-byte boundaries.
#: (sample -> [(member path in the tar, type)]); offsets come from tarfile.
EMBEDDED = {
    'ripgrep-14.1.1-x86_64-apple-darwin.tar': [
        ('ripgrep-14.1.1-x86_64-apple-darwin/rg', 'macho')],
}

#: What a file is, where its name says otherwise -- carved by content.
NOTES = {
    'bbb-360-10s.mkv': "published as .mkv, but an MP4 (ftyp isom): TRACE "
                       "names it by its content",
    'ripgrep-14.1.1-x86_64-apple-darwin.tar': "GNU tar format; a V7 tar has "
                                              "no magic to find it by",
}

#: Each format's signature, planted with junk after it. A carver that takes a
#: signature for a file writes these out; none should be.
DECOYS = [
    b'SQLite format 3\x00', b'regf', b'ElfFile\x00', b'!BDN', b'MZ',
    b'\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46',
    b'ID3\x03\x00', b'OggS\x00\x02', b'FLV\x01', b'\x00\x00\x01\xba',
    b'\x1a\x45\xdf\xa3', b'BZh9\x31\x41\x59\x26\x53\x59', b'\xfd7zXZ\x00',
    b'{\\rtf1', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'8BPS\x00\x01',
    b'From someone@example.com Mon Jan  1 00:00:00 2007\n', b'PK\x03\x04',
    b'RIFF\x00\x10\x00\x00WEBP', b'\x00\x00\x00\x18ftypheic',
]


def _download(url, attempts=4):
    """Fetch with retries: sample hosts are third parties, and a brief
    outage should not fail a test run."""
    import time
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                url, headers={'User-Agent': 'TRACE-tests'})
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except OSError as exc:
            if attempt == attempts - 1:
                raise SystemExit(f"Could not download {url}: {exc}")
            time.sleep(5 * (attempt + 1))


def _unpack(data, unpack):
    if not unpack:
        return data
    kind = unpack[0]
    if kind == 'base64':
        return base64.b64decode(data)
    if kind == 'gunzip':
        return gzip.decompress(data)
    if kind == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return archive.read(unpack[1])
    if kind == 'targz':
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            return archive.extractfile(unpack[1]).read()
    raise ValueError(kind)


def fetch(pin=False):
    """Download, verify and unpack every sample. Returns {name: bytes}."""
    os.makedirs(SAMPLES, exist_ok=True)
    cache = {}
    files = {}
    pins = {}
    for name, _type, url, sha, unpack in CATALOG:
        path = os.path.join(SAMPLES, name)
        if os.path.isfile(path) and not pin:
            data = open(path, 'rb').read()
        else:
            raw = cache.get(url) or _download(url)
            cache[url] = raw
            digest = hashlib.sha256(raw).hexdigest()
            pins[name] = digest
            if sha and digest != sha and not pin:
                raise SystemExit(f"{name}: download does not match its pinned "
                                 f"SHA-256 ({digest}); refusing to use it.")
            data = _unpack(raw, unpack)
            with open(path, 'wb') as handle:
                handle.write(data)
        files[name] = data
        print(f"  {name:28} {len(data):>11,} bytes", flush=True)
    if pin:
        print(json.dumps(pins, indent=1))
    return files


def build(files):
    """Lay the samples and decoys out among random filler; write the key."""
    rng = random.Random(SEED)
    layout = []
    image = bytearray()

    def filler(low, high):
        size = rng.randrange(low, high) // SECTOR * SECTOR
        image.extend(rng.randbytes(size))

    filler(64 * 1024, 256 * 1024)
    order = [entry for entry in CATALOG]
    rng.shuffle(order)
    decoys = list(DECOYS)
    for name, kind, _url, _sha, _unpack in order:
        data = files[name]
        offset = len(image)
        image.extend(data)
        image.extend(b'\x00' * (-len(image) % SECTOR))
        layout.append((name, kind, offset, data))
        filler(32 * 1024, 512 * 1024)
        if decoys:
            # A decoy: a signature at a sector start, then junk.
            image.extend(decoys.pop() + rng.randbytes(SECTOR * 8))
            image.extend(rng.randbytes(-len(image) % SECTOR))
            filler(16 * 1024, 64 * 1024)
    for decoy in decoys:
        image.extend(decoy + rng.randbytes(SECTOR * 8))
        image.extend(rng.randbytes(-len(image) % SECTOR))
    filler(64 * 1024, 128 * 1024)

    with open(IMAGE, 'wb') as handle:
        handle.write(image)

    entries = []
    from trace_app.core import carving_formats as formats
    measures = {'regf': formats.measure_regf, 'evtx': formats.measure_evtx}
    for name, kind, offset, data in layout:
        expected = data
        note = "contiguous"
        if name in LOGICAL_ONLY:
            size = measures[kind](formats.Source(data, 0), 0)[0]
            expected = data[:size]
            note = (f"contiguous; scored on the first {size:,} bytes -- "
                    f"{LOGICAL_ONLY[name]}")
        if name in NOTES:
            note += f"; {NOTES[name]}"
        entries.append({
            'name': name, 'type': kind, 'offset': hex(offset),
            'size': len(expected),
            'md5': hashlib.md5(expected).hexdigest(),
            'recoverable': True, 'note': note,
        })
        for member, member_kind in EMBEDDED.get(name, ()):
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                info = archive.getmember(member)
                content = archive.extractfile(info).read()
            entries.append({
                'name': f"{name}!/{member.rsplit('/', 1)[-1]}",
                'type': member_kind, 'offset': hex(offset + info.offset_data),
                'size': len(content),
                'md5': hashlib.md5(content).hexdigest(),
                'recoverable': True,
                'note': "inside the tar, stored whole on a 512-byte boundary",
            })

    with open(TRUTH, encoding='utf-8') as handle:
        truth = json.load(handle)
    truth[os.path.basename(IMAGE)] = {
        'source': 'tools/carve_corpus.py (built locally from pinned public '
                  'samples)',
        'title': 'Real published files of every format TRACE carves that the '
                 'DFTT/DFRWS images do not hold, among random filler and '
                 'signature decoys',
        'note': 'Deterministic: fixed seed, SHA-256-pinned inputs. Sources '
                'are listed in carve_corpus.py.',
        'sha256': hashlib.sha256(image).hexdigest(),
        'files': entries,
    }
    with open(TRUTH, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(truth, handle, indent=1)
        handle.write('\n')
    print(f"\n{IMAGE}: {len(image):,} bytes, {len(entries)} files, "
          f"{len(DECOYS)} decoys")
    print(f"SHA-256 {hashlib.sha256(image).hexdigest()}")


def main(argv):
    sys.path.insert(0, ROOT)
    if '--pin' in argv:
        fetch(pin=True)
        return 0
    print("Samples:")
    files = fetch()
    build(files)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
