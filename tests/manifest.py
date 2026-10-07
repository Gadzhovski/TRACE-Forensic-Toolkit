"""Write manifests of test images (see trace_app/core/manifest.py).

    python -m tests.manifest test_images/7-ntfs-undel.dd -o tests/manifests
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trace_app.core.manifest import build_manifest  # noqa: E402


def manifest_path(directory, image_path):
    return os.path.join(directory,
                        os.path.basename(image_path) + '.manifest.json')


def write_manifest(image_path, directory):
    manifest = build_manifest(image_path)
    os.makedirs(directory, exist_ok=True)
    target = manifest_path(directory, image_path)
    with open(target, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write('\n')
    return target, manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('images', nargs='+')
    parser.add_argument('-o', '--out', required=True)
    args = parser.parse_args(argv)
    for image in args.images:
        target, manifest = write_manifest(image, args.out)
        count = sum(len(v['entries']) for v in manifest['volumes'])
        print(f"{os.path.basename(image)}: {len(manifest['volumes'])} "
              f"volume(s), {count} entries -> {target}", flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
