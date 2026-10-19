"""evidence_hash.sha256_file: the one SHA-256 of a file TRACE wrote (reports,
manifests, exports, programs) -- it was nine copies."""

import hashlib

import pytest


def test_equals_hashlib_across_blocks(tmp_path):
    from trace_app.core.evidence_hash import sha256_file
    data = bytes(range(256)) * 9000            # > 1 MiB: several blocks
    path = tmp_path / 'report.html'
    path.write_bytes(data)
    assert sha256_file(str(path)) == hashlib.sha256(data).hexdigest()
    empty = tmp_path / 'empty'
    empty.write_bytes(b'')
    assert sha256_file(str(empty)) == hashlib.sha256(b'').hexdigest()


def test_a_stop_raises_the_callers_exception_or_hashing_error(tmp_path):
    from trace_app.core.evidence_hash import HashingError, sha256_file
    path = tmp_path / 'big'
    path.write_bytes(b'x' * (3 << 20))

    class Stopped(Exception):
        pass

    with pytest.raises(Stopped):
        sha256_file(str(path), lambda: True, Stopped)
    # No exception named: it used to raise None() -- a TypeError.
    with pytest.raises(HashingError):
        sha256_file(str(path), lambda: True)
