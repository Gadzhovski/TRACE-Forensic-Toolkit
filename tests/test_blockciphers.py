"""The block ciphers VeraCrypt uses beyond AES (core/blockciphers.py),
against their published test vectors -- what each cipher's authors give,
not TRACE's own encryption. tests/test_veracrypt.py then reads volumes
VeraCrypt itself made with each, alone and in cascades."""

import os

import pytest

from trace_app.core import blockciphers

VECTORS = [
    # Twofish paper, "Test vectors": the all-zero key and block.
    ('Twofish', '00' * 16, '00' * 16, '9f589f5cf6122c32b6bfec2f2ae8c35a'),
    ('Twofish', '00' * 32, '00' * 16, '57ff739d4dc92c1bd7fc01700cc8216f'),
    # NESSIE, Serpent set 1 vector 0 (128- and 256-bit keys).
    ('Serpent', '80' + '00' * 15, '00' * 16,
     '264e5481eff42a4606abda06c0bfda3d'),
    ('Serpent', '80' + '00' * 31, '00' * 16,
     'a223aa1288463c0e2be38ebd825616c0'),
    # GOST R 34.12-2015, appendix A.1.
    ('Kuznyechik',
     '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef',
     '1122334455667700ffeeddccbbaa9988', '7f679d90bebc24305a468d42b9d4edcd'),
    # Camellia (RFC 3713 family): the all-zero 256-bit key and block.
    ('Camellia', '00' * 32, '00' * 16, '396154111adefc500cf6e5c99038bc17'),
]


@pytest.mark.parametrize('name, key, plain, cipher', VECTORS)
def test_published_vectors(name, key, plain, cipher):
    algorithm = blockciphers.CIPHERS[name](bytes.fromhex(key))
    assert algorithm.encrypt_blocks(bytes.fromhex(plain)).hex() == cipher
    assert algorithm.decrypt_blocks(bytes.fromhex(cipher)).hex() == plain


@pytest.mark.parametrize('name', sorted(blockciphers.CIPHERS))
def test_many_blocks_at_once_equal_one_at_a_time(name):
    """Serpent works on a whole read at once (lanes): each block must come
    out as it would alone."""
    algorithm = blockciphers.CIPHERS[name](os.urandom(32))
    data = os.urandom(16 * 67)
    together = algorithm.encrypt_blocks(data)
    alone = b''.join(algorithm.encrypt_blocks(data[at:at + 16])
                     for at in range(0, len(data), 16))
    assert together == alone
    assert algorithm.decrypt_blocks(together) == data


def test_xts_matches_cryptography_for_aes():
    """The generic XTS over AES's block function is cryptography's AES-XTS:
    the layer every other cipher uses is the standard one."""
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    key = os.urandom(64)
    data = os.urandom(512 * 3)
    ours = blockciphers.xts_units(blockciphers.AES(key[:32]),
                                  blockciphers.AES(key[32:]), 77, data,
                                  decrypt=False)
    theirs = b''
    for unit in range(3):
        cipher = Cipher(algorithms.AES(key), modes.XTS(
            (77 + unit).to_bytes(16, 'little'))).encryptor()
        theirs += cipher.update(data[unit * 512:(unit + 1) * 512]) + \
            cipher.finalize()
    assert ours == theirs
