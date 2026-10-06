"""Choose what CI tests, from what a change touched.

A change to the hex viewer has no business downloading DFRWS images or
scoring the carver; a change to the carver has every business doing both.
This reads the files a change touched and works out:

* the test files to run -- each test file depends on the modules it imports
  and, through them, on what those modules import at their top level. A
  changed module selects every test that reaches it. Imports inside
  functions are not followed between TRACE's own modules: nearly every
  module reaches the case, carving and activity code that way, and
  following them selected most of the suite for any change. A test's own
  imports count wherever they are. `trace_app.ui.main_window` and
  `trace_app.app` import nearly everything, so nothing is reached *through*
  them: the window's tests run when the window itself or a theme changes;
* the public images to download -- only those the chosen test files name;
* whether the carving score runs -- when a carver, or its scoring, changed.

Anything it cannot place (an installer, requirements, the shared test setup,
image access, an unknown path) runs everything, as does a push to the
default branch, the weekly run and a manual run -- those also catch what
the narrower rules above let through. CI keeps
TRACE_REQUIRE_IMAGES=1, so a test that needs an image this script did not
fetch fails loudly rather than passing by skipping.

    python tools/ci_select.py                    # what this branch would run
    python tools/ci_select.py --base HEAD~3      # ... for the last 3 commits
    python tools/ci_select.py --github           # in Actions: outputs + summary
"""

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Python versions: every one on a full run, the oldest and newest otherwise.
ALL_PYTHONS = ['3.10', '3.12', '3.14']
EDGE_PYTHONS = ['3.10', '3.14']

#: Changes that can break anything: everything runs.
FULL = (
    re.compile(r'^requirements\.txt$'),
    re.compile(r'^install\.sh$'),
    re.compile(r'^install_windows\.ps1$'),
    re.compile(r'^pytest\.ini$'),
    re.compile(r'^main\.py$'),
    re.compile(r'^\.github/workflows/tests\.yml$'),
    re.compile(r'^tests/conftest\.py$'),
    re.compile(r'^tools/(ci_select|fetch_test_images|fetch_artifact_samples|carve_corpus)\.py$'),
    re.compile(r'^trace_app/(__init__|app)\.py$'),
    re.compile(r'^trace_app/[^/]+/__init__\.py$'),
    re.compile(r'^trace_app/core/(image_handler|background|walk)\.py$'),
    re.compile(r'^trace_app/infra/'),
    re.compile(r'^resources/'),
)

#: Changes no test here can catch: documentation, and the packaged build
#: (build.yml builds and self-tests the package on its own).
IGNORED = (
    re.compile(r'\.md$'),
    re.compile(r'^(LICENSE|\.gitignore|\.gitattributes)$'),
    re.compile(r'^docs/'),
    re.compile(r'^Icons_archive/'),
    re.compile(r'^test_images/README'),
    re.compile(r'^(build_app\.py|TRACE\.spec)$'),
    re.compile(r'^\.github/workflows/build\.yml$'),
    re.compile(r'^trace_app/selftest\.py$'),
)

#: Look and feel: every test of the user interface.
INTERFACE = (
    re.compile(r'^styles/'),
    re.compile(r'^Icons/'),
)

#: Modules nothing is reached through (they import nearly everything).
HUBS = {'trace_app.ui.main_window', 'trace_app.app'}

#: A change reaching any of these runs the carving score.
CARVING_MODULES = re.compile(
    r'^trace_app\.core\.(carving\w*|carve_\w+|reassembly|deleted|slack)$')
CARVING_FILES = re.compile(r'^tools/(carve_score\.py|carve_ground_truth\.json)$')
#: What the carving score reads.
CARVE_SCORE_IMAGES = ['11-carve-fat.dd', '12-carve-ext2.dd']


# -- what changed --------------------------------------------------------

def _git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout.strip()


def changed_files(base):
    """Paths changed between `base` and the working tree's HEAD (and, run
    locally, anything uncommitted too)."""
    names = set(_git('diff', '--name-only', f'{base}...HEAD').splitlines())
    if not os.environ.get('GITHUB_ACTIONS'):
        names |= set(_git('diff', '--name-only', 'HEAD').splitlines())
        names |= set(_git('ls-files', '--others', '--exclude-standard')
                     .splitlines())
    return sorted(n for n in names if n)


# -- who imports what ----------------------------------------------------

def _module_of(path):
    """'trace_app/core/ntfs.py' -> 'trace_app.core.ntfs'."""
    name = path[:-3].replace('/', '.')
    return name[:-len('.__init__')] if name.endswith('.__init__') else name


def _exists(module):
    base = os.path.join(ROOT, *module.split('.'))
    return os.path.isfile(base + '.py') or \
        os.path.isfile(os.path.join(base, '__init__.py'))


def _imports(path):
    """The project modules a file imports: a test or tool anywhere in it,
    a module of TRACE's at its top level only (see the docstring)."""
    rel = os.path.relpath(path, ROOT).replace(os.sep, '/')
    module = _module_of(rel)
    package = module if path.endswith('__init__.py') else \
        module.rpartition('.')[0]
    with open(path, encoding='utf-8') as handle:
        tree = ast.parse(handle.read(), path)
    if rel.startswith('trace_app/'):
        tree = ast.Module(body=[node for node in tree.body if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))],
            type_ignores=[])
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split('.')
                parts = parts[:len(parts) - node.level + 1]
                origin = '.'.join(parts + ([node.module] if node.module else []))
            else:
                origin = node.module or ''
            found.add(origin)
            for alias in node.names:     # 'from pkg import module'
                if _exists(f'{origin}.{alias.name}'):
                    found.add(f'{origin}.{alias.name}')
    return {name for name in found
            if name.split('.')[0] in ('trace_app', 'tests', 'tools')
            and _exists(name)}


def _python_files(folder):
    for directory, _, files in os.walk(os.path.join(ROOT, folder)):
        if '__pycache__' in directory:
            continue
        for name in files:
            if name.endswith('.py'):
                yield os.path.join(directory, name)


def import_graph():
    """module -> the project modules it imports."""
    graph = {}
    for folder in ('trace_app', 'tests', 'tools'):
        for path in _python_files(folder):
            rel = os.path.relpath(path, ROOT).replace(os.sep, '/')
            graph[_module_of(rel)] = _imports(path)
    return graph


def dependents(graph, changed):
    """Every module that reaches one of `changed` by importing, not
    passing through a hub."""
    users = {}
    for module, imported in graph.items():
        for name in imported:
            users.setdefault(name, set()).add(module)
    reached, todo = set(changed), list(changed)
    while todo:
        for user in users.get(todo.pop(), ()):
            if user not in reached:
                reached.add(user)
                if user not in HUBS:
                    todo.append(user)
    return reached


# -- images --------------------------------------------------------------

def catalog():
    """The image names tools/fetch_test_images.py can fetch."""
    path = os.path.join(ROOT, 'tools', 'fetch_test_images.py')
    with open(path, encoding='utf-8') as handle:
        tree = ast.parse(handle.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, 'id', '') == 'CATALOG' for t in node.targets):
            return [key.value for key in node.value.keys]
    return []


def needs(test_files, graph):
    """(images, artifact samples?, carving corpus?) the test files read --
    named in them, or in the test modules they import."""
    modules = {_module_of(path) for path in test_files}
    todo = list(modules)
    while todo:
        for name in graph.get(todo.pop(), ()):
            # conftest names every image (it knows CI's set): not a need.
            if name.startswith('tests.') and name != 'tests.conftest'                     and name not in modules:
                modules.add(name)
                todo.append(name)
    text = ''
    for module in modules:
        path = os.path.join(ROOT, *module.split('.')) + '.py'
        if os.path.isfile(path):
            with open(path, encoding='utf-8') as handle:
                text += handle.read()
    images = [name for name in catalog() if name in text]
    if 'test_image_handling' in text or 'manifests' in text:
        images += [name[:-len('.json')] for name in sorted(os.listdir(
            os.path.join(ROOT, 'tests', 'manifests'))) if name.endswith('.json')
            and name[:-len('.json')] in catalog()]
    return (sorted(set(images)), 'artifact_samples' in text,
            'carve-corpus' in text or 'carve_samples' in text)


# -- the plan ------------------------------------------------------------

def plan(files, full_reason=None):
    graph = import_graph()
    tests = {m for m in graph if m.startswith('tests.test_')}
    reasons = []

    if full_reason is None:
        for path in files:
            if any(p.search(path) for p in FULL):
                full_reason = f'{path} can affect every test'
                break
    if full_reason is None:
        changed_modules, selected, carve = set(), set(), False
        for path in files:
            if any(p.search(path) for p in IGNORED):
                continue
            if CARVING_FILES.search(path):
                carve = True
                reasons.append(f'{path}: the carving score')
                continue
            if path.endswith('.py') and path.split('/')[0] in (
                    'trace_app', 'tests', 'tools'):
                module = _module_of(path)
                if not _exists(module):
                    if path.startswith('tests/'):
                        continue                  # a removed test
                    full_reason = f'{path} was removed'
                    break
                changed_modules.add(module)
            elif path.startswith('tests/manifests/') or path == 'tests/manifest.py':
                selected.add('tests.test_image_handling')
                reasons.append(f'{path}: image handling')
            elif any(p.search(path) for p in INTERFACE):
                interface = {t for t in tests if any(
                    n.startswith('trace_app.ui') for n in graph[t])}
                selected |= interface
                reasons.append(f'{path}: every interface test')
            else:
                full_reason = f'{path} is not mapped to any tests'
                break
    if full_reason is not None:
        return {'full': True, 'reason': full_reason, 'tests': [],
                'images': catalog(), 'artifacts': True, 'corpus': True,
                'carve_score': True, 'pythons': ALL_PYTHONS, 'files': files}

    reached = dependents(graph, changed_modules)
    for module in sorted(changed_modules):
        hits = sorted(tests & dependents(graph, {module}))
        reasons.append(f'{module}: ' + (', '.join(
            h.split('.')[-1] for h in hits) or 'no test reaches it'))
    selected |= tests & reached
    carve = carve or any(CARVING_MODULES.search(m) for m in reached)

    test_files = sorted(f"{m.replace('.', '/')}.py" for m in selected)
    images, artifacts, corpus = needs(test_files, graph)
    if carve:
        images = sorted(set(images) | set(CARVE_SCORE_IMAGES))
        corpus = True
    return {'full': False, 'reason': '; '.join(reasons), 'tests': test_files,
            'images': images, 'artifacts': artifacts, 'corpus': corpus,
            'carve_score': carve, 'pythons': EDGE_PYTHONS, 'files': files}


def summary(result):
    lines = ['## What this run tests', '']
    if result['full']:
        lines += [f"**Everything** -- {result['reason']}.", '']
    elif not result['tests'] and not result['carve_score']:
        lines += ['**Nothing** -- the change touches no tested code '
                  '(documentation, the packaged build).', '']
    else:
        lines += [f"**{len(result['tests'])} test files** on Python "
                  f"{', '.join(result['pythons'])}, chosen from what changed:",
                  '']
        lines += [f'- {r}' for r in result['reason'].split('; ') if r]
        lines += ['', 'Test files: ' + ', '.join(
            f"`{os.path.basename(t)}`" for t in result['tests']), '']
        lines += ['Images: ' + (', '.join(f'`{i}`' for i in result['images'])
                                or 'none'),
                  f"Artifact samples: {'yes' if result['artifacts'] else 'no'}"
                  f" | Carving corpus: {'yes' if result['corpus'] else 'no'}"
                  f" | Carving score: {'yes' if result['carve_score'] else 'no'}",
                  '']
    lines.append(f"{len(result['files'])} files changed.")
    return '\n'.join(lines)


def _github_base():
    """The commit to compare with in Actions, or (None, why everything)."""
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    if event in ('schedule', 'workflow_dispatch'):
        return None, f'a {event.replace("_", " ")} run tests everything'
    with open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8') as handle:
        payload = json.load(handle)
    default = (payload.get('repository') or {}).get('default_branch', 'master')
    if event == 'pull_request':
        return payload['pull_request']['base']['sha'], None
    if os.environ.get('GITHUB_REF') == f'refs/heads/{default}':
        return None, f'a push to {default} tests everything'
    # A branch: everything it changed since leaving the default branch --
    # not since the previous push, which a newer push may have cancelled.
    try:
        return _git('merge-base', f'origin/{default}', 'HEAD'), None
    except subprocess.CalledProcessError:
        return None, f'no common history with {default}'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--base', help='compare with this commit '
                        '(default: where the branch left origin/master)')
    parser.add_argument('--github', action='store_true',
                        help='write GitHub Actions outputs and summary')
    args = parser.parse_args(argv)

    full_reason = None
    if args.github:
        base, full_reason = _github_base()
    else:
        base = args.base or _git('merge-base', 'origin/master', 'HEAD')
    files = changed_files(base) if base else []
    result = plan(files, full_reason)
    text = summary(result)

    if not args.github:
        print(text)
        return 0
    run = result['full'] or bool(result['tests']) or result['carve_score']
    outputs = {
        'run': 'true' if run else 'false',
        'full': 'true' if result['full'] else 'false',
        # Empty on a full run: pytest's own testpaths, every file.
        'tests': ' '.join(result['tests']),
        # Empty on a full run: the fetcher's whole catalog.
        'images': '' if result['full'] else ' '.join(result['images']),
        'fetch_images': 'true' if result['images'] else 'false',
        'images_key': hashlib.sha256(' '.join(result['images']).encode())
                             .hexdigest()[:12],
        'artifacts': 'true' if result['artifacts'] else 'false',
        'corpus': 'true' if result['corpus'] else 'false',
        'carve_score': 'true' if result['carve_score'] else 'false',
        'pythons': json.dumps(result['pythons']),
    }
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as out:
        for key, value in outputs.items():
            out.write(f'{key}={value}\n')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as out:
        out.write(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
