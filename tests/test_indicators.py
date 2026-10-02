"""Indicators: what indexing extracts, and how the Indicators tab asks for it.

Every input is generated here. The window's use of it -- indexing as a job on
the shared queue, the Triage tab, the Findings tree -- is tested on the real
two-device case in tests/test_ui.py.
"""

import pytest

TEXT_ONE = """
Invoice for alice@example.com, see https://pay.example.org/inv/42 from 10.0.0.7.
Card on file: 4111 1111 1111 1111 (Visa), also 5555-5555-5555-4444.
Not cards: order 1234567890123456, ISBN 9780306406157, 4111-1111-1111-1112.
Wire to GB82 WEST 1234 5698 7654 32; a typo GB82 WEST 1234 5698 7654 33 is not.
Call +44 20 7946 0958. Version +1.2 and +12 3 are not numbers anyone calls.
"""

TEXT_TWO = """
Second device: alice@example.com again, and DE89 3704 0044 0532 0130 00.
Amex 3782 822463 10005 written oddly, and 378282246310005 written plainly.
"""


@pytest.fixture
def index(tmp_path):
    from trace_app.core.search_index import SearchIndex
    idx = SearchIndex(str(tmp_path))
    idx.add_item(1, 'p0:i10:s1', 'file', 'one.txt', '/one.txt', TEXT_ONE,
                 size=len(TEXT_ONE))
    idx.add_item(2, 'p0:i20:s1', 'file', 'two.txt', '/docs/two.txt', TEXT_TWO,
                 size=len(TEXT_TWO))
    idx.commit()
    yield idx
    idx.close()


def _values(index, kind, evidence_id=None):
    return {row['value'] for row in index.indicators(kind, evidence_id)}


def test_card_numbers_must_pass_luhn_and_a_scheme(index):
    assert _values(index, 'card') == {'4111111111111111', '5555555555554444',
                                      '378282246310005'}


def test_ibans_must_have_their_countrys_length_and_check_digits(index):
    from trace_app.core.search_index import iban_valid
    assert _values(index, 'iban') == {'GB82WEST12345698765432',
                                      'DE89370400440532013000'}
    assert not iban_valid('GB82WEST12345698765433')
    assert not iban_valid('ZZ82WEST12345698765432')     # not a country


def test_phone_numbers_are_international_with_enough_digits(index):
    assert _values(index, 'phone') == {'+442079460958'}


def test_luhn():
    from trace_app.core.search_index import luhn_valid
    assert luhn_valid('79927398713')
    assert not luhn_valid('79927398710')


def test_indicators_follow_the_image_filter(index):
    assert index.indicator_summary(2) == {'email': 1, 'domain': 1,
                                          'card': 1, 'iban': 1}
    everywhere = {row['value']: row for row in index.indicators('email')}
    assert everywhere['alice@example.com']['files'] == 2
    assert everywhere['alice@example.com']['evidence_ids'] == [1, 2]
    assert _values(index, 'email', evidence_id=1) == {'alice@example.com'}
    assert _values(index, 'iban', evidence_id=1) == {'GB82WEST12345698765432'}
    assert index.statistics(1)['items'] == 1
    assert index.statistics()['images'] == 2


def test_a_value_lists_the_files_holding_it_with_context(index):
    files = index.items_with('card', '4111111111111111')
    assert [f['name'] for f in files] == ['one.txt']
    # Stored as digits, found in the text as written -- spaced.
    assert '4111 1111 1111 1111' in files[0]['excerpt']
    assert 'body' not in files[0]
    both = index.items_with('email', 'alice@example.com')
    assert {f['evidence_id'] for f in both} == {1, 2}
    assert [f['name'] for f in index.items_with(
        'email', 'alice@example.com', evidence_id=2)] == ['two.txt']


def test_every_indicator_kind_can_be_searched(index):
    from trace_app.core.search_index import parse_query
    assert parse_query('iban:GB82')['kind'] == 'entity'
    assert [r['name'] for r in index.search('card:4111')] == ['one.txt']
    assert [r['name'] for r in index.search('phone:')] == ['one.txt']


def test_a_filter_narrows_the_values(index):
    assert _values(index, None) >= {'alice@example.com', '+442079460958'}
    narrowed = index.indicators(None, None, contains='example.org')
    assert {r['value'] for r in narrowed} == {
        'https://pay.example.org/inv/42', 'pay.example.org'}


# --- the dialog -------------------------------------------------------------------

def test_indexing_is_an_analysis_module(qapp):
    from trace_app.core.analysis import MODULES
    from trace_app.ui.dialogs.analysis_modules import (
        AnalysisModulesDialog, MODULE_INDEX, default_choice)
    # Offered, and ticked the first time like every other module.
    dialog = AnalysisModulesDialog(preselected=default_choice(MODULES),
                                   evidence=[(1, 'a.dd'), (2, 'b.dd')])
    assert dialog.boxes[MODULE_INDEX].isChecked()
    for key, box in dialog.boxes.items():
        box.setChecked(key == MODULE_INDEX)
    dialog._accept()
    assert dialog.choice['index'] is True
    assert dialog.choice['modules'] == []       # not a file-walk module
    assert dialog.choice['carve_types'] == []
    dialog.deleteLater()


def test_the_search_tab_no_longer_builds_the_index(qapp):
    from trace_app.ui.viewers.search_panel import EXAMPLES, SearchPanel
    panel = SearchPanel()
    assert not hasattr(panel, 'index_button')
    # The "every X" listings moved to Triage > Indicators; patterns stay.
    assert ('Every email address', 'email:') not in EXAMPLES
    assert any(label == 'IBAN' for label, _ in EXAMPLES)
    panel.deleteLater()
