"""The whole interface larger or smaller (no Qt).

Everything TRACE draws is sized in logical pixels -- the themes' font sizes
and paddings, the controls' fixed heights, the icons -- so one factor
scales it all evenly: Qt's QT_SCALE_FACTOR, read when the application
object is made, on top of the scaling Windows, macOS or the desktop already
apply for the screen. Hence the setting takes effect at the next start
(View > Interface Size offers a restart).

An examiner who sets QT_SCALE_FACTOR themselves keeps it: their variable
wins over the setting.
"""

import logging
import os

logger = logging.getLogger('TRACE.UiScale')

#: The sizes offered (Settings > Display, View > Interface Size).
SCALES = ('80%', '90%', '100%', '110%', '125%', '150%', '175%', '200%')
DEFAULT = '100%'
#: Whether QT_SCALE_FACTOR was ours (set from the setting) or the user's.
_OURS = 'TRACE_UI_SCALE_SET'


def factor(text):
    """'125%' -> 1.25; anything unreadable -> 1.0."""
    try:
        value = float(str(text).strip().rstrip('%')) / 100
    except (TypeError, ValueError):
        return 1.0
    return value if 0.5 <= value <= 3.0 else 1.0


def apply_env(chosen=None):
    """Set QT_SCALE_FACTOR from the setting before the QApplication is
    made. Returns the factor in effect (the user's own variable, if set)."""
    if chosen is None:
        from trace_app.core import settings
        chosen = settings.user('ui_scale')
    own = os.environ.get('QT_SCALE_FACTOR')
    if own and not os.environ.get(_OURS):
        logger.info("Interface size from QT_SCALE_FACTOR=%s (the setting, "
                    "%s, is not used)", own, chosen)
        try:
            return float(own)
        except ValueError:
            return 1.0
    value = factor(chosen)
    if value == 1.0:
        os.environ.pop('QT_SCALE_FACTOR', None)
        os.environ.pop(_OURS, None)
    else:
        os.environ['QT_SCALE_FACTOR'] = f"{value:g}"
        os.environ[_OURS] = '1'
    return value


def step(current, direction):
    """The size one step larger (+1) or smaller (-1) than `current`."""
    try:
        index = SCALES.index(current)
    except ValueError:
        index = SCALES.index(DEFAULT)
    return SCALES[max(0, min(len(SCALES) - 1, index + direction))]
