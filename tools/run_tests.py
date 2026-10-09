"""Run TRACE's tests at one of three depths.

    python tools/run_tests.py quick    # no test data: ~2 minutes, before a commit
    python tools/run_tests.py ci       # exactly what CI reads (the CI data set)
    python tools/run_tests.py full     # everything here, plus both scores
    python tools/run_tests.py full -- -k nist -x    # extra pytest arguments

'quick' needs nothing downloaded: every test that reads test data skips.
'ci' reads only what CI has (test_images/ci, samples, corpus, and on
Linux the built images) and fails on a missing CI image, as CI does: run
`python -m tools.testdata.fetch` first. Its skip list is the tests that
only run locally. 'full' reads everything in test_images/ -- local, NIST,
private -- then scores the carver against every published answer key
present (tools/score/carve_score.py) and Deleted File Recovery against
NIST's key (tools/score/dfr_score.py). Get the data with
`python -m tools.testdata.fetch --tier full`.

The tier reaches the tests as TRACE_TEST_TIER (tools/testdata): folders
outside it do not exist for the run, so no test can read them by any route.
"""

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: The carving images CI scores (the rest are scored by 'full').
CI_CARVE_SCORE = ('11-carve-fat.dd', '12-carve-ext2.dd', 'carve-corpus.dd')


def _run(label, command, env):
    print(f"\n=== {label}\n    {' '.join(command)}", flush=True)
    began = time.time()
    code = subprocess.call(command, cwd=ROOT, env=env)
    print(f"=== {label}: {'passed' if code == 0 else f'FAILED ({code})'} "
          f"in {time.time() - began:.0f} s", flush=True)
    return code


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    extra = []
    if '--' in argv:
        at = argv.index('--')
        argv, extra = argv[:at], argv[at + 1:]
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('tier', choices=('quick', 'ci', 'full'))
    parser.add_argument('-n', '--workers', default='auto',
                        help="pytest-xdist workers (default: one per core)")
    parser.add_argument('--no-scores', action='store_true',
                        help="skip the carving and DFR scores")
    args = parser.parse_args(argv)

    env = dict(os.environ, TRACE_TEST_TIER=args.tier,
               QT_QPA_PLATFORM=os.environ.get('QT_QPA_PLATFORM', 'offscreen'))
    if args.tier == 'ci':
        env['TRACE_REQUIRE_IMAGES'] = '1'
    else:
        env.pop('TRACE_REQUIRE_IMAGES', None)
    python = sys.executable
    results = {}
    results['tests'] = _run(
        f"tests ({args.tier})",
        [python, '-m', 'pytest', '-n', args.workers, '--dist', 'loadfile',
         '-q', '-rfEs'] + extra, env)
    if not args.no_scores and args.tier in ('ci', 'full'):
        # The scores read the real folders, whatever the tier.
        plain = dict(env)
        plain.pop('TRACE_TEST_TIER')
        names = list(CI_CARVE_SCORE) if args.tier == 'ci' else []
        results['carving score'] = _run(
            'carving score', [python, 'tools/score/carve_score.py'] + names,
            plain)
        if args.tier == 'full':
            results['DFR score'] = _run(
                'NIST deleted-file-recovery score',
                [python, 'tools/score/dfr_score.py', '-j', '3'], plain)
    print("\nSummary:")
    for label, code in results.items():
        print(f"  {label:16} {'passed' if code == 0 else 'FAILED'}")
    return 1 if any(results.values()) else 0


if __name__ == '__main__':
    sys.exit(main())
