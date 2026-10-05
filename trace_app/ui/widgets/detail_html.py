"""The look of a detail pane's rich text: one style for every part of it.

The Timeline's detail pane is built by two hands -- the panel writes the
event, the window adds the file's NTFS times and findings -- and each had
its own idea of a label (bold, near-black, as heavy as the value it named).
These helpers give them one: labels in grey at normal weight, values in the
text colour, section headings small and grey under a rule, times in a fixed
pitch so columns line up, long paths breakable at their separators.

Colours are mid-tones chosen to read on both themes: Qt's rich text has no
access to the style sheet.
"""

import html

#: Labels, headings, secondary text.
MUTED = '#8A8F98'
#: A value worth a second look (an $SI time earlier than its $FN one).
ATTENTION = '#D9822B'
#: Finding grades, as the triage lists colour them.
GRADE_COLOURS = {'suspicious': '#E5534B', 'notable': ATTENTION}

STYLE = (
    "<style>"
    "h3 { font-size: 14px; font-weight: 600; margin: 0px; }"
    f".sub {{ color: {MUTED}; margin-top: 2px; margin-bottom: 8px; }}"
    f"h4 {{ color: {MUTED}; font-size: 11px; font-weight: 600; "
    "margin-top: 4px; margin-bottom: 4px; }"
    "td { padding-top: 2px; padding-bottom: 2px; padding-right: 16px; "
    "vertical-align: top; }"
    f"td.k {{ color: {MUTED}; padding-right: 14px; white-space: nowrap; }}"
    f"th {{ color: {MUTED}; font-weight: normal; text-align: left; "
    "padding-right: 14px; }"
    ".mono { font-family: 'Consolas', 'Menlo', 'DejaVu Sans Mono', "
    "monospace; }"
    f".mark {{ color: {ATTENTION}; }}"
    f".note {{ color: {MUTED}; font-size: 11px; }}"
    "</style>")


def e(value):
    return html.escape('' if value is None else str(value))


def breakable(value):
    """Escaped, with a break opportunity after each path separator -- a
    long path otherwise wraps mid-word, or not at all."""
    return e(value).replace('/', '/&#8203;').replace('\\', '\\&#8203;')


def heading(title, subtitle=''):
    return (f"<h3>{e(title)}</h3>"
            + (f"<p class='sub'>{e(subtitle)}</p>" if subtitle else ''))


def facts(pairs):
    """A label / value table. Each pair is (label, value) or (label, value,
    'path' | 'mono'); empty values are left out."""
    rows = []
    for pair in pairs:
        label, value = pair[0], pair[1]
        kind = pair[2] if len(pair) > 2 else ''
        if value in (None, ''):
            continue
        text = breakable(value) if kind in ('path', 'mono') else e(value)
        css = " class='mono'" if kind == 'mono' else ''
        rows.append(f"<tr><td class='k'>{e(label)}</td>"
                    f"<td{css}>{text}</td></tr>")
    if not rows:
        return ''
    return "<table cellspacing='0' cellpadding='0'>" + ''.join(rows) + \
        "</table>"


def section(title):
    """A section heading under a thin rule."""
    return f"<hr/><h4>{e(title)}</h4>"
