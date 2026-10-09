"""Kept so old commands still work: the fetcher is tools/testdata/fetch.py.

    python tools/fetch_test_images.py [names...]  ==
    python -m tools.testdata.fetch [names...]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.testdata.fetch import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
