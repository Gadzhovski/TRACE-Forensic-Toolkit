"""A small RDF Turtle reader -- as much as an AFF4 container uses (no Qt).

AFF4 describes its contents in `information.turtle`: what the image is, the
streams holding it, their chunking and compression, hashes, and the case
notes. rdflib reads Turtle, but pyaff4 pins a version of it (and of PyYAML,
`future`, aff4-snappy) with no wheels for the Pythons TRACE supports, and
the subset these files use is small: `@prefix`, IRIs, prefixed names, `a`,
string literals with a datatype or language, numbers, and the `;` / `,`
lists. Blank nodes and collections, which AFF4 does not use, are refused
rather than misread.

`parse(text)` -> {subject IRI: {predicate IRI: [object, ...]}}, objects
being an IRI (str) or a Literal.
"""

import re

RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'


class TurtleError(ValueError):
    """Turtle this reader does not understand."""


class Literal(str):
    """A literal's text, with its `datatype` (an IRI or '') and `lang`."""

    def __new__(cls, value, datatype='', lang=''):
        item = super().__new__(cls, value)
        item.datatype = datatype
        item.lang = lang
        return item

    def as_int(self):
        try:
            return int(self)
        except ValueError:
            return None


_TOKEN = re.compile(r'''
    (?P<space>\s+|\#[^\n]*)
  | (?P<prefix>@prefix|PREFIX)\b
  | (?P<iri><[^<>"{}|^`\\\s]*>)
  | (?P<string>"""(?:[^"\\]|\\.|"(?!""))*"""|"(?:[^"\\\n]|\\.)*")
  | (?P<datatype>\^\^)
  | (?P<lang>@[A-Za-z]+(?:-[A-Za-z0-9]+)*)
  | (?P<number>[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)
  | (?P<pname>[A-Za-z][\w\-.]*?:[\w\-.%:/]*(?<!\.)|:[\w\-.%:/]*(?<!\.)|:)
  | (?P<a>a)(?=[\s<"])
  | (?P<punct>[.;,\[\]()])
''', re.VERBOSE)

_ESCAPES = {'t': '\t', 'n': '\n', 'r': '\r', 'b': '\b', 'f': '\f',
            '"': '"', "'": "'", '\\': '\\'}


def _unescape(text):
    def replace(match):
        code = match.group(1)
        if code[0] in 'uU':
            return chr(int(code[1:], 16))
        return _ESCAPES.get(code, code)
    return re.sub(r'\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)', replace, text)


def _tokens(text):
    position = 0
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None:
            raise TurtleError(f"unexpected text at {position}: "
                              f"{text[position:position + 30]!r}")
        position = match.end()
        kind = match.lastgroup
        if kind != 'space':
            yield kind, match.group()


def parse(text):
    """Every triple, as {subject: {predicate: [objects]}}."""
    prefixes = {}
    graph = {}
    tokens = list(_tokens(text))
    i = 0

    def take():
        nonlocal i
        if i >= len(tokens):
            raise TurtleError("unexpected end")
        token = tokens[i]
        i += 1
        return token

    def peek():
        return tokens[i] if i < len(tokens) else (None, None)

    def resource(kind, value):
        if kind == 'iri':
            return value[1:-1]
        if kind == 'pname':
            prefix, _colon, local = value.partition(':')
            if prefix not in prefixes:
                raise TurtleError(f"unknown prefix {prefix!r}")
            return prefixes[prefix] + local
        raise TurtleError(f"expected an IRI, found {value!r}")

    def term():
        kind, value = take()
        if kind == 'string':
            body = value[3:-3] if value.startswith('"""') else value[1:-1]
            body = _unescape(body)
            next_kind, next_value = peek()
            if next_kind == 'datatype':
                take()
                return Literal(body, resource(*take()))
            if next_kind == 'lang':
                take()
                return Literal(body, lang=next_value[1:])
            return Literal(body)
        if kind == 'number':
            return Literal(value, 'http://www.w3.org/2001/XMLSchema#'
                           + ('integer' if value.lstrip('+-').isdigit()
                              else 'decimal'))
        if kind == 'punct' and value in '[(':
            raise TurtleError("blank nodes and collections are not "
                              "supported")
        return resource(kind, value)

    while i < len(tokens):
        kind, value = take()
        if kind == 'prefix':
            name_kind, name = take()
            if name_kind != 'pname' or not name.endswith(':'):
                raise TurtleError(f"bad prefix name {name!r}")
            prefixes[name[:-1]] = resource(*take())
            if value == '@prefix':
                end = take()
                if end != ('punct', '.'):
                    raise TurtleError("@prefix without its '.'")
            continue
        subject = resource(kind, value)
        predicates = graph.setdefault(subject, {})
        while True:
            p_kind, p_value = take()
            predicate = RDF_TYPE if p_kind == 'a' else \
                resource(p_kind, p_value)
            values = predicates.setdefault(predicate, [])
            values.append(term())
            while peek() == ('punct', ','):
                take()
                values.append(term())
            separator = take()
            if separator == ('punct', ';'):
                # A trailing ';' before '.' is allowed.
                if peek() == ('punct', '.'):
                    take()
                    break
                continue
            if separator == ('punct', '.'):
                break
            raise TurtleError(f"expected ';' or '.', found "
                              f"{separator[1]!r}")
    return graph
