"""DFRWS 2011 Forensics Challenge, scenario 1 (local only): a real Motorola
A855's eight NAND partitions, imaged with `dd if=/dev/block/mtdblockX` --
page data only, without the spare bytes where YAFFS2 keeps its tags.

What such a dump allows is a real-world check that none of TRACE's flash
readers (YAFFS, JFFS2, UBIFS, LittleFS, QNX...) takes it for a file
system: the object headers are there, but no data chunk says whose it is,
so anything listed would be invented. The challenge's winners carved them.

Get it (157 MB; the README lists the archive's SHA-1 as 'MD5'):
    https://github.com/dfrws/dfrws2011-challenge -> Case1.tgz
    SHA-1 9a756c41cbd3b628fb55d35e695efdee31efa58e, unpacked without
    SDCard.img into test_images/local/dfrws2011/.
"""

import hashlib
import os
import shutil

import pytest

from tests.conftest import data_path

#: postAcquisitionHashes.txt, the examiner's MD5s of the copies.
ACQUISITION_MD5 = {
    'mtdblock0.img': '10f39bed760d85980117a29364feeeb1',
    'mtdblock1.img': '5dfd83e314d645c6f41d86915a7b98eb',
    'mtdblock3.img': '7673f7ef637274d6bb48892a157d877d',
    'mtdblock4.img': 'fa503c91751afccf175092a29a2b2637',
    'mtdblock5.img': 'ade41709773a63a4ed09d66f3a7637cd',
    'mtdblock6.img': '0f1a515a89e2a368aff3fcd818bcab94',
    'mtdblock7.img': 'b23b5d09162b92c0284923a7f628d2a5',
}


@pytest.mark.parametrize('name', sorted(ACQUISITION_MD5))
def test_a_spareless_nand_dump_is_no_file_system(tmp_path, name):
    from trace_app.core.image_handler import ImageHandler
    source = data_path('local', 'dfrws2011', name)
    with open(source, 'rb') as handle:
        assert hashlib.md5(handle.read()).hexdigest() == \
            ACQUISITION_MD5[name]
    target = tmp_path / name
    try:
        os.link(source, target)
    except OSError:
        shutil.copy(source, target)
    handler = ImageHandler(str(target))
    try:
        assert handler.load_image()
        assert handler.get_fs_info(0) is None
        assert handler.get_fs_type(0) == 'N/A'
    finally:
        handler.close_resources()
