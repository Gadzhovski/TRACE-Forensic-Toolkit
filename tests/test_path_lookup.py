"""libyal_fs.PathLookup: the one path walk behind the pure-Python file
systems' get_file_entry_by_path (it was ten copies in two shapes)."""

from trace_app.core.libyal_fs import PathLookup


class _Entry:
    def __init__(self, name, children=()):
        self.name = name
        self.children = list(children)
        self.built = 0

    @property
    def number_of_sub_file_entries(self):
        return len(self.children)

    def get_sub_file_entry(self, index):
        child = self.children[index]
        child.built += 1
        return child

    def _list(self):
        return [(child.name.encode('utf-8', 'surrogateescape'), 0, 0)
                for child in self.children]


def _tree():
    leaf = _Entry('passwd')
    etc = _Entry('etc', [_Entry('hosts'), leaf])
    return _Entry('', [_Entry('bin'), etc]), etc, leaf


class _Built(PathLookup):
    def __init__(self, root):
        self.root = root

    def get_root_directory(self):
        return self.root


class _Raw(_Built):
    def _names_in(self, entry):
        return [name.decode('utf-8', 'surrogateescape')
                for name, *_ in entry._list()]


def test_both_shapes_find_the_same_entries():
    for volume_class in (_Built, _Raw):
        root, etc, leaf = _tree()
        volume = volume_class(root)
        assert volume.get_file_entry_by_path('/etc/passwd') is leaf
        assert volume.get_file_entry_by_path('etc\\passwd') is leaf
        assert volume.get_file_entry_by_path('//etc/') is etc
        assert volume.get_file_entry_by_path('/') is root
        assert volume.get_file_entry_by_path('/etc/shadow') is None
        assert volume.get_file_entry_by_path('/ETC/passwd') is None


def test_raw_names_build_only_the_entries_followed():
    root, etc, leaf = _tree()
    _Raw(root).get_file_entry_by_path('/etc/passwd')
    assert (etc.built, leaf.built) == (1, 1)
    assert etc.children[0].built == 0          # 'hosts' never built
