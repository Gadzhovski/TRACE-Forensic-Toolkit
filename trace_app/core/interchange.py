"""What the analysis found, written for other tools: DFXML (files) and
CASE/UCO JSON-LD (the case, its evidence, files and findings).

Both read the case database only -- `file_analysis` (names, sizes,
hashes, types), `fs_events` (each file's own times) and `file_findings`
-- so they say exactly what the analysis recorded, never re-reading the
image. Run the file analysis first; a file it did not reach is not here.

* DFXML (Garfinkel's Digital Forensics XML, schema 1.2.0) is one document
  per image: a `fileobject` per file with its name, size, inode, whether
  it is deleted, MACB times and hashes -- what fiwalk writes, so
  dfxml_tool and the DFXML Python library read it.
* CASE/UCO (the Cyber-investigation Analysis Standard Expression over the
  Unified Cyber Ontology, 1.x) is one JSON-LD graph: an Investigation, a
  File per image (its acquisition hashes) and per analysed file
  (FileFacet, ContentDataFacet with hashes), a Contained_Within
  Relationship from each file to its image, and an Annotation per
  finding naming its module, kind and grade. Identifiers are stable
  (uuid5 of the case, image and artifact reference), so exporting twice
  names the same things the same way.

Times as stored: UTC ones with their zone; local, zoneless ones (FAT,
exFAT) without one. No Qt.
"""

import datetime
import json
import logging
import uuid
from xml.sax.saxutils import escape, quoteattr

logger = logging.getLogger('TRACE.Interchange')

DFXML_NS = 'http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML'

CASE_CONTEXT = {
    'kb': 'http://example.org/kb/',
    'case-investigation':
        'https://ontology.caseontology.org/case/investigation/',
    'uco-core': 'https://ontology.unifiedcyberontology.org/uco/core/',
    'uco-observable':
        'https://ontology.unifiedcyberontology.org/uco/observable/',
    'uco-types': 'https://ontology.unifiedcyberontology.org/uco/types/',
    'uco-vocabulary':
        'https://ontology.unifiedcyberontology.org/uco/vocabulary/',
    'uco-tool': 'https://ontology.unifiedcyberontology.org/uco/tool/',
    'xsd': 'http://www.w3.org/2001/XMLSchema#',
}

#: The fs_events sources that are a file's own times, preferred in this
#: order ($STANDARD_INFORMATION on NTFS; every other file system's one
#: set).
_OWN_TIMES = ('SI', 'FS', 'FS-local')
_MACB_NAMES = {'M': 'mtime', 'A': 'atime', 'C': 'ctime', 'B': 'crtime'}
_HASHES = (('md5', 'MD5'), ('sha1', 'SHA1'), ('sha256', 'SHA256'))


class NothingToExport(Exception):
    """No analysed files: the file analysis has not run on this image."""


# --- reading the case ------------------------------------------------------------

def _evidence(connection, evidence_id=None):
    sql = ("SELECT id, path, display_name, size, md5, sha1, sha256, "
           "stored_md5, stored_sha1, exhibit_number, description, "
           "acquired_by, acquired_on FROM evidence")
    params = ()
    if evidence_id is not None:
        sql += " WHERE id = ?"
        params = (evidence_id,)
    columns = ('id', 'path', 'name', 'size', 'md5', 'sha1', 'sha256',
               'stored_md5', 'stored_sha1', 'exhibit', 'description',
               'acquired_by', 'acquired_on')
    return [dict(zip(columns, row)) for row in
            connection.execute(sql + " ORDER BY id", params)]


def _files(connection, evidence_id):
    columns = ('ref', 'name', 'path', 'size', 'deleted', 'mime', 'md5',
               'sha1', 'sha256')
    cursor = connection.execute(
        "SELECT artifact_ref, name, path, size, is_deleted, mime, md5, sha1, "
        "sha256 FROM file_analysis WHERE evidence_id = ? ORDER BY id",
        (evidence_id,))
    return [dict(zip(columns, row)) for row in cursor]


def _times(connection, evidence_id):
    """{ref: ({'mtime': text, ...}, local)} -- each file's own times."""
    found = {}
    try:
        cursor = connection.execute(
            "SELECT artifact_ref, macb, source, time_utc FROM fs_events "
            "WHERE evidence_id = ? AND source IN (?, ?, ?)",
            (evidence_id,) + _OWN_TIMES)
    except Exception:
        return found
    rank = {source: n for n, source in enumerate(_OWN_TIMES)}
    best = {}
    for ref, macb, source, text in cursor:
        if ref in best and rank[source] > best[ref]:
            continue
        if ref not in best or rank[source] < best[ref]:
            best[ref] = rank[source]
            found[ref] = ({}, source == 'FS-local')
        for letter in macb:
            name = _MACB_NAMES.get(letter)
            if name:
                found[ref][0][name] = text
    return found


def _findings(connection, evidence_id):
    columns = ('ref', 'module', 'kind', 'grade', 'summary', 'path')
    try:
        cursor = connection.execute(
            "SELECT artifact_ref, module, kind, grade, summary, path "
            "FROM file_findings WHERE evidence_id = ? ORDER BY id",
            (evidence_id,))
    except Exception:
        return []
    return [dict(zip(columns, row)) for row in cursor]


def _iso(text, local):
    """'YYYY-MM-DD HH:MM:SS[.fffffff]' -> ISO 8601 (Z unless local)."""
    if not text:
        return None
    base, _, fraction = str(text).partition('.')
    stamp = base[:19].replace(' ', 'T')
    if fraction:
        stamp += '.' + ''.join(c for c in fraction if c.isdigit())
    return stamp if local else stamp + 'Z'


def _inode(ref):
    for part in (ref or '').split(':'):
        if part.startswith('i') and part[1:].isdigit():
            return int(part[1:])
    return None


# --- DFXML ---------------------------------------------------------------------------

def write_dfxml(connection, evidence_id, path, version):
    """One image's analysed files as DFXML. Returns the number of
    fileobjects; NothingToExport when the analysis has not run."""
    evidence = _evidence(connection, evidence_id)
    if not evidence:
        raise ValueError(f"no evidence {evidence_id}")
    evidence = evidence[0]
    files = _files(connection, evidence_id)
    if not files:
        raise NothingToExport(f"{evidence['name'] or evidence['path']}: "
                              f"run the file analysis first")
    times = _times(connection, evidence_id)
    now = datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ')

    def element(name, value, **attributes):
        attrs = ''.join(f" {k}={quoteattr(str(v))}"
                        for k, v in attributes.items())
        return f"<{name}{attrs}>{escape(str(value))}</{name}>"

    with open(path, 'w', encoding='utf-8', newline='\n') as out:
        out.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        out.write(f"<dfxml xmlns={quoteattr(DFXML_NS)} "
                  f"xmlns:dc='http://purl.org/dc/elements/1.1/' "
                  f"version='1.2.0'>\n")
        out.write("  <metadata>\n    "
                  + element('dc:type', 'File system walk') + "\n  "
                  "</metadata>\n")
        out.write("  <creator version='1.0'>\n    "
                  + element('program', 'TRACE') + "\n    "
                  + element('version', version) + "\n    "
                  "<execution_environment>"
                  + element('start_date', now) +
                  "</execution_environment>\n  </creator>\n")
        out.write("  <source>\n    "
                  + element('image_filename', evidence['path']))
        if evidence['size']:
            out.write("\n    " + element('image_size', evidence['size']))
        out.write("\n  </source>\n")
        for entry in files:
            out.write("  <fileobject>\n")
            out.write("    " + element('filename', _clean(entry['path']
                                                          or entry['name']))
                      + "\n")
            if entry['size'] is not None:
                out.write("    " + element('filesize', entry['size']) + "\n")
            allocated = 0 if entry['deleted'] else 1
            out.write("    " + element('alloc_inode', allocated) + "\n"
                      "    " + element('alloc_name', allocated) + "\n")
            inode = _inode(entry['ref'])
            if inode is not None:
                out.write("    " + element('inode', inode) + "\n")
            own, local = times.get(entry['ref'], ({}, False))
            for name in ('mtime', 'atime', 'ctime', 'crtime'):
                stamp = _iso(own.get(name), local)
                if stamp:
                    out.write("    " + element(name, stamp) + "\n")
            for column, label in _HASHES:
                if entry[column]:
                    out.write("    " + element('hashdigest', entry[column],
                                               type=label.lower()) + "\n")
            out.write("  </fileobject>\n")
        out.write("</dfxml>\n")
    return len(files)


def _clean(text):
    """XML 1.0 cannot hold control characters (raw names can)."""
    return ''.join(c if c in '\t\n\r' or ord(c) >= 0x20 else
                   f"\\x{ord(c):02x}" for c in str(text))


# --- CASE / UCO -----------------------------------------------------------------------

def case_graph(connection, case_name, case_id, version, evidence_ids=None,
               with_findings=True):
    """The JSON-LD document (a dict). NothingToExport if no image chosen
    has analysed files."""
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"trace-case:{case_id}")

    def kb(kind, *parts):
        name = uuid.uuid5(namespace, '/'.join(str(p) for p in parts))
        return f"kb:{kind}-{name}"

    def hashes(row, prefix=''):
        out = []
        for column, label in _HASHES:
            value = row.get(prefix + column)
            if value:
                out.append({
                    '@id': kb('hash', row.get('_id'), prefix, label),
                    '@type': 'uco-types:Hash',
                    'uco-types:hashMethod': {
                        '@type': 'uco-vocabulary:HashNameVocab',
                        '@value': label},
                    'uco-types:hashValue': {'@type': 'xsd:hexBinary',
                                            '@value': value.upper()}})
        return out

    graph = []
    tool = {'@id': kb('tool', 'trace', version), '@type': 'uco-tool:Tool',
            'uco-core:name': 'TRACE', 'uco-tool:version': version}
    graph.append(tool)
    investigation = {'@id': kb('investigation', case_id),
                     '@type': 'case-investigation:Investigation',
                     'uco-core:name': case_name, 'uco-core:object': []}
    graph.append(investigation)
    total = 0
    wanted = None if evidence_ids is None else set(evidence_ids)
    for evidence in _evidence(connection):
        if wanted is not None and evidence['id'] not in wanted:
            continue
        evidence_node = kb('evidence', evidence['id'])
        evidence['_id'] = evidence_node
        facets = [{'@id': kb('facet', 'evidence', evidence['id'], 'file'),
                   '@type': 'uco-observable:FileFacet',
                   'uco-observable:fileName': evidence['name'] or
                   evidence['path'],
                   'uco-observable:filePath': evidence['path']}]
        if evidence['size']:
            facets[0]['uco-observable:sizeInBytes'] = {
                '@type': 'xsd:integer', '@value': str(evidence['size'])}
        recorded = hashes(evidence)
        if recorded:
            facets.append({'@id': kb('facet', 'evidence', evidence['id'],
                                     'content'),
                           '@type': 'uco-observable:ContentDataFacet',
                           'uco-observable:hash': recorded})
        node = {'@id': evidence_node, '@type': 'uco-observable:File',
                'uco-core:hasFacet': facets}
        if evidence['description'] or evidence['exhibit']:
            node['uco-core:description'] = ' -- '.join(
                p for p in (evidence['exhibit'], evidence['description'])
                if p)
        graph.append(node)
        investigation['uco-core:object'].append({'@id': evidence_node})
        times = _times(connection, evidence['id'])
        file_nodes = {}
        for entry in _files(connection, evidence['id']):
            total += 1
            file_id = kb('file', evidence['id'], entry['ref'])
            file_nodes[entry['ref']] = file_id
            entry['_id'] = file_id
            facet = {'@id': kb('facet', evidence['id'], entry['ref'],
                               'file'),
                     '@type': 'uco-observable:FileFacet',
                     'uco-observable:fileName': _clean(entry['name']),
                     'uco-observable:isDirectory': False}
            if entry['path']:
                facet['uco-observable:filePath'] = _clean(entry['path'])
            if entry['size'] is not None:
                facet['uco-observable:sizeInBytes'] = {
                    '@type': 'xsd:integer', '@value': str(entry['size'])}
            own, local = times.get(entry['ref'], ({}, False))
            for name, prop in (('mtime', 'modifiedTime'),
                               ('atime', 'accessedTime'),
                               ('ctime', 'metadataChangeTime'),
                               ('crtime', 'observableCreatedTime')):
                stamp = _iso(own.get(name), local)
                if stamp:
                    facet[f'uco-observable:{prop}'] = {
                        '@type': 'xsd:dateTime', '@value': stamp}
            facets = [facet]
            content = hashes(entry)
            if content or entry['mime']:
                data = {'@id': kb('facet', evidence['id'], entry['ref'],
                                  'content'),
                        '@type': 'uco-observable:ContentDataFacet'}
                if content:
                    data['uco-observable:hash'] = content
                if entry['mime']:
                    data['uco-observable:mimeType'] = entry['mime']
                if entry['size'] is not None:
                    data['uco-observable:sizeInBytes'] = {
                        '@type': 'xsd:integer', '@value': str(entry['size'])}
                facets.append(data)
            node = {'@id': file_id, '@type': 'uco-observable:File',
                    'uco-core:hasFacet': facets}
            if entry['deleted']:
                node['uco-core:tag'] = ['deleted']
            graph.append(node)
            graph.append({
                '@id': kb('relationship', evidence['id'], entry['ref']),
                '@type': 'uco-observable:ObservableRelationship',
                'uco-core:source': {'@id': file_id},
                'uco-core:target': {'@id': evidence_node},
                'uco-core:kindOfRelationship': 'Contained_Within',
                'uco-core:isDirectional': True})
        if with_findings:
            for number, finding in enumerate(_findings(connection,
                                                       evidence['id'])):
                target = file_nodes.get(finding['ref'])
                annotation = {
                    '@id': kb('annotation', evidence['id'], finding['ref'],
                              finding['module'], finding['kind'], number),
                    '@type': 'uco-core:Annotation',
                    'uco-core:statement': finding['summary'] or
                    finding['kind'],
                    'uco-core:tag': [finding['module'], finding['kind'],
                                     finding['grade']],
                    'uco-core:object': [{'@id': target or evidence_node}]}
                graph.append(annotation)
    if total == 0:
        raise NothingToExport("no analysed files: run the file analysis "
                              "first")
    return {'@context': CASE_CONTEXT, '@graph': graph}


def write_case_uco(connection, path, case_name, case_id, version,
                   evidence_ids=None, with_findings=True):
    """Write the CASE/UCO JSON-LD file. Returns the number of files."""
    document = case_graph(connection, case_name, case_id, version,
                          evidence_ids, with_findings)
    with open(path, 'w', encoding='utf-8', newline='\n') as out:
        json.dump(document, out, ensure_ascii=False, indent=1)
    return sum(1 for node in document['@graph']
               if node.get('@type') == 'uco-observable:File') - \
        sum(1 for node in document['@graph']
            if str(node.get('@id', '')).startswith('kb:evidence-'))
