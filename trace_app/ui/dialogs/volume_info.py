"""Volume and image information view.

The "View Image Information" dialog: per-partition tables, filesystem details,
and the space-allocation pie chart. Roughly 520 lines that had no reason to sit
inside MainWindow.

Provided as a mixin because the methods read `self.image_handler`,
`self.db_manager` and `self.tree_viewer` from the window they belong to;
mixing in keeps those references working without threading a context object
through every method.
"""

import datetime
import logging
import os

import pytsk3
from PySide6.QtCharts import QChart, QChartView, QPieSeries
from PySide6.QtCore import Qt, QMargins, QSize
from PySide6.QtGui import QBrush, QColor, QFontMetrics, QIcon, QPainter
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QScrollArea, QSizePolicy, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from trace_app.infra.constants import BUTTON_WIDTH, TABLE_ICON_SIZE
from trace_app.infra.utils import FileSystemUtils
from trace_app.ui import icons

logger = logging.getLogger('TRACE.VolumeInfo')


class VolumeInfoMixin:
    """Builds the image/volume information dialog."""

    def view_os_information(self, index):
        """Show the image information dialog for the tree's selected image.

        Kept for the tree's context menu, which hands over a model index. The
        dialog itself is built by show_image_information, so the Tools menu can
        open it without a tree item.
        """
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            # Ensure that only the root item triggers the information display
            return
        self.show_image_information()

    def show_image_information(self):
        """Display comprehensive disk image information with space allocation pie chart."""
        # Create modern dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Disk Image Information")
        dialog.resize(1200, 800)

        # Main vertical layout
        main_layout = QVBoxLayout(dialog)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # === TOP SECTION: Image Overview with Chart ===
        top_widget = QWidget()
        top_widget.setObjectName("volumeInfoHeader")
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(20, 20, 20, 20)
        top_layout.setSpacing(30)

        # Left: Image Summary Card
        summary_card = QWidget()
        summary_card.setObjectName("volumeInfoCard")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(20, 20, 20, 20)
        summary_layout.setSpacing(12)

        # Title
        title_label = QLabel("Disk Image Overview")
        title_label.setObjectName("volumeInfoTitle")
        summary_layout.addWidget(title_label)

        # Key info
        image_info = self._get_image_info()
        key_fields = ["Image Path", "Image Type", "Total Size", "Partition Scheme", "Number of Partitions", "Status"]

        def add_row(field, text):
            info_row = QWidget()
            info_row.setObjectName("volumeInfoRow")
            info_row_layout = QHBoxLayout(info_row)
            info_row_layout.setContentsMargins(0, 0, 0, 0)
            info_row_layout.setSpacing(10)

            label = QLabel(f"{field}:")
            label.setObjectName("volumeInfoFieldLabel")
            label.setMinimumWidth(140)

            value = QLabel(str(text))
            value.setObjectName("volumeInfoFieldValue")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setWordWrap(True)

            info_row_layout.addWidget(label)
            info_row_layout.addWidget(value, 1)
            summary_layout.addWidget(info_row)

        for field in key_fields:
            if field in image_info:
                add_row(field, image_info[field])

        # Installed system, from whichever volume carries one. It is the first
        # thing an examiner wants to know about an image and would otherwise be
        # buried in a column of the table below, off the right edge.
        systems = self._installed_systems()
        for index, (start_offset, installed) in enumerate(systems):
            # Name the volume when a disk carries more than one system, so a
            # dual-boot image says which partition each belongs to.
            title = "Installed System"
            if len(systems) > 1:
                title = f"Installed System {index + 1}  (sector {start_offset:,})"
            heading = QLabel(title)
            heading.setObjectName("volumeInfoSectionHeading")
            summary_layout.addSpacing(10)
            summary_layout.addWidget(heading)
            for field, text in installed.items():
                add_row(field, text)

        # Nothing installed: say so, and describe what the media is instead.
        if not systems:
            heading = QLabel("Storage Media")
            heading.setObjectName("volumeInfoSectionHeading")
            summary_layout.addSpacing(10)
            summary_layout.addWidget(heading)
            for field, text in self._media_summary().items():
                add_row(field, text)

        # Acquisition record. An E01 carries the case and evidence numbers, the
        # examiner, the date and the tool that wrote it -- the provenance of
        # the evidence. It was being read off disk by libewf and discarded.
        # Raw images carry no such record, so the section is omitted for them.
        acquisition = self.image_handler.get_acquisition_info()
        if acquisition:
            heading = QLabel("Acquisition")
            heading.setObjectName("volumeInfoSectionHeading")
            summary_layout.addSpacing(10)
            summary_layout.addWidget(heading)
            for field, text in acquisition.items():
                add_row(field, text)

        summary_layout.addStretch()
        summary_card.setFixedWidth(450)

        # Right: Pie Chart with Legend
        chart_widget = QWidget()
        chart_widget.setObjectName("volumeInfoCard")
        chart_outer_layout = QVBoxLayout(chart_widget)
        chart_outer_layout.setContentsMargins(15, 15, 15, 15)
        chart_outer_layout.setSpacing(10)

        chart_title = QLabel("Space Allocation")
        chart_title.setObjectName("volumeInfoSubtitle")
        chart_title.setAlignment(Qt.AlignCenter)
        chart_outer_layout.addWidget(chart_title)

        # Create horizontal layout for legend (left) and chart (right)
        chart_content_layout = QHBoxLayout()
        chart_content_layout.setSpacing(15)

        # Create chart
        chart_view, partition_info_list = self._create_space_allocation_chart()

        # Compact legend on the left
        if partition_info_list:
            legend_widget = QWidget()
            legend_widget.setObjectName("volumeInfoRow")
            legend_layout = QVBoxLayout(legend_widget)
            legend_layout.setContentsMargins(5, 5, 5, 5)
            legend_layout.setSpacing(6)

            for label_text, color in partition_info_list:
                legend_row = QWidget()
                legend_row.setObjectName("volumeInfoRow")
                legend_row_layout = QHBoxLayout(legend_row)
                legend_row_layout.setContentsMargins(0, 0, 0, 0)
                legend_row_layout.setSpacing(8)

                color_indicator = QLabel()
                color_indicator.setFixedSize(16, 16)
                color_indicator.setStyleSheet(f"""
                    background-color: rgb({color.red()}, {color.green()}, {color.blue()});
                    border: 1px solid #adb5bd;
                    border-radius: 3px;
                """)

                text_label = QLabel(label_text)
                text_label.setObjectName("volumeInfoLegendLabel")
                text_label.setWordWrap(True)

                legend_row_layout.addWidget(color_indicator)
                legend_row_layout.addWidget(text_label, 1)

                legend_layout.addWidget(legend_row)

            legend_layout.addStretch()
            legend_widget.setMaximumWidth(300)
            chart_content_layout.addWidget(legend_widget)

        chart_content_layout.addWidget(chart_view, 1)
        chart_outer_layout.addLayout(chart_content_layout, 1)

        # The overview plus the acquisition record is more than fits a fixed
        # card, so it scrolls rather than being clipped.
        summary_scroll = QScrollArea()
        summary_scroll.setObjectName("volumeInfoScroll")
        summary_scroll.setWidget(summary_card)
        summary_scroll.setWidgetResizable(True)
        summary_scroll.setFrameShape(QScrollArea.NoFrame)
        summary_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        summary_scroll.setFixedWidth(470)

        top_layout.addWidget(summary_scroll)
        top_layout.addWidget(chart_widget, 1)

        main_layout.addWidget(top_widget)

        # === BOTTOM SECTION: Detailed Partition Information ===
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(20, 20, 20, 20)
        bottom_layout.setSpacing(15)

        # Section title
        details_title = QLabel("Volumes and Analysis")
        details_title.setObjectName("volumeInfoSectionTitle")
        bottom_layout.addWidget(details_title)

        # Professional table view for volume information
        volume_table = QTableWidget()
        volume_table.setSortingEnabled(True)
        volume_table.verticalHeader().setVisible(False)
        volume_table.setObjectName("volumeInfoTable")
        volume_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        volume_table.setAlternatingRowColors(True)
        volume_table.setEditTriggers(QTableWidget.NoEditTriggers)
        volume_table.setIconSize(QSize(TABLE_ICON_SIZE, TABLE_ICON_SIZE))
        volume_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Enable horizontal scrolling for smaller windows
        volume_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        volume_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Set column count and headers
        volume_table.setColumnCount(14)
        volume_table.setHorizontalHeaderLabels([
            'Volume', 'Filesystem', 'Offset (Sectors)', 'Block Size', 'Volume Size',
            'Total Blocks', 'First Block', 'Last Block', 'Inode Count', 'Root Inode',
            'Volume Serial', 'Operating System', 'Time Zone', 'Computer Name'
        ])

        # Configure header - all columns use Interactive mode for horizontal scrolling
        header = volume_table.horizontalHeader()
        for i in range(14):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Widths are set from the content once the rows exist -- see
        # _fit_volume_columns. Guessing them here meant anything longer than
        # the guess was elided and had to be dragged wider by hand.

        # Set header alignment
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        # Populate table with partition data
        partitions = self.image_handler.get_partitions()

        if partitions:
            self._populate_volume_table(volume_table, partitions)
        else:
            # Show message in table if no partitions
            volume_table.setRowCount(1)
            no_part_item = QTableWidgetItem("No partitions detected or single filesystem image")
            no_part_item.setForeground(QBrush(QColor(108, 117, 125)))
            font = no_part_item.font()
            font.setItalic(True)
            no_part_item.setFont(font)
            volume_table.setItem(0, 0, no_part_item)
            volume_table.setSpan(0, 0, 1, 10)

        # Volumes, and beside them what the case's analysis found in this
        # image (core/evidence_summary.py) -- the window used to stop at
        # what the image is, however much had been learned from it.
        from PySide6.QtWidgets import QTabWidget
        from trace_app.ui.widgets.property_table import PropertyTable
        tabs = QTabWidget()
        tabs.setObjectName("volumeInfoTabs")
        tabs.addTab(volume_table, icons.icon(icons.CASE), "Volumes")
        analysis_table = PropertyTable("Field", "Value")
        analysis_table.setObjectName("volumeInfoAnalysis")
        analysis_table.set_rows(self._analysis_rows())
        tabs.addTab(analysis_table, icons.icon(icons.TRIAGE), "Analysis")
        bottom_layout.addWidget(tabs, 1)

        # Close button at bottom right
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        close_button.setMinimumWidth(BUTTON_WIDTH)

        button_layout.addWidget(close_button)
        bottom_layout.addLayout(button_layout)

        main_layout.addWidget(bottom_widget, 1)

        dialog.exec()

    def _analysis_rows(self):
        """What the case recorded about the image on screen, for the
        Analysis tab -- or why there is nothing to show."""
        case = getattr(self, 'case', None)
        if case is None:
            return [(None, "Analysis"),
                    ("Not recorded", "Analysis results are kept in a case; "
                                     "this is a quick-triage session.")]
        path = getattr(self, 'current_image_path', None) or \
            getattr(self.image_handler, 'image_path', None)
        row = case.evidence_for_path(path) if path else None
        if row is None:
            return [(None, "Analysis"),
                    ("Not recorded", "This image is not part of the case.")]
        from trace_app.core import evidence_summary
        return evidence_summary.rows_for(case, row['id'])

    def _populate_volume_table(self, table, partitions):
        """Populate the volume table with partition information."""
        table.setRowCount(len(partitions))
        table.setSortingEnabled(False)  # Disable sorting while populating

        for idx, partition in enumerate(partitions):
            addr, desc, start, length = partition

            # Get volume information
            volume_info = self._extract_comprehensive_volume_info(start)

            # Combine all info
            all_info = {}
            all_info.update(volume_info["basic"])
            all_info.update(volume_info["filesystem"])

            # Get filesystem type for icon
            fs_type = all_info.get("Filesystem Type", "Unknown")
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')

            # Column 0: Volume (with icon)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            volume_text = f"vol{addr}"
            if desc_str and desc_str.strip():
                volume_text += f" ({desc_str})"

            volume_item = QTableWidgetItem(volume_text)
            volume_item.setIcon(QIcon(icon_path))
            table.setItem(idx, 0, volume_item)

            # Column 1: Filesystem
            fs_item = QTableWidgetItem(fs_type)
            table.setItem(idx, 1, fs_item)

            # Column 2: Offset (Sectors)
            offset_value = all_info.get("Partition Offset", "N/A")
            # Extract just the sector count
            if "sectors" in offset_value:
                offset_value = offset_value.split("sectors")[0].strip()
            offset_item = QTableWidgetItem(offset_value)
            table.setItem(idx, 2, offset_item)

            # Column 3: Block Size
            block_size = all_info.get("Block Size", "N/A")
            block_size_item = QTableWidgetItem(block_size)
            table.setItem(idx, 3, block_size_item)

            # Column 4: Volume Size
            volume_size = all_info.get("Volume Size", "N/A")
            volume_size_item = QTableWidgetItem(volume_size)
            table.setItem(idx, 4, volume_size_item)

            # Column 5: Total Blocks
            total_blocks = all_info.get("Total Blocks", "N/A")
            total_blocks_item = QTableWidgetItem(total_blocks)
            table.setItem(idx, 5, total_blocks_item)

            # Column 6: First Block
            first_block = all_info.get("First Block", "N/A")
            first_block_item = QTableWidgetItem(first_block)
            table.setItem(idx, 6, first_block_item)

            # Column 7: Last Block
            last_block = all_info.get("Last Block", "N/A")
            last_block_item = QTableWidgetItem(last_block)
            table.setItem(idx, 7, last_block_item)

            # Column 8: Inode Count
            inode_count = all_info.get("Inode Count", "N/A")
            inode_count_item = QTableWidgetItem(inode_count)
            table.setItem(idx, 8, inode_count_item)

            # Column 9: Root Inode
            root_inode = all_info.get("Root Inode", "N/A")
            root_inode_item = QTableWidgetItem(root_inode)
            table.setItem(idx, 9, root_inode_item)

            # Column 10: Volume Serial -- identifies the volume independently
            # of the partition layout, which is how an image is tied back to
            # the device it came from.
            serial = all_info.get("Volume Serial", "N/A")
            table.setItem(idx, 10, QTableWidgetItem(serial))

            # Columns 11-13: what the registry says about the installation on
            # this volume. Blank on a data volume, which has no registry.
            operating_system = all_info.get("Operating System", "")
            build = all_info.get("Build", "")
            if operating_system and build:
                operating_system = f"{operating_system} (build {build})"
            table.setItem(idx, 11, QTableWidgetItem(operating_system or "N/A"))

            time_zone = all_info.get("Time Zone", "")
            offset_text = all_info.get("UTC Offset", "")
            if time_zone and offset_text:
                time_zone = f"{time_zone} ({offset_text})"
            table.setItem(idx, 12, QTableWidgetItem(time_zone or offset_text or "N/A"))

            table.setItem(idx, 13,
                          QTableWidgetItem(all_info.get("Computer Name", "N/A")))

        table.setSortingEnabled(True)  # Re-enable sorting after populating
        self._fit_volume_columns(table)

    @staticmethod
    def _fit_volume_columns(table):
        """Widen every column to its longest cell, header included.

        resizeColumnsToContents measures the cells but leaves the last column
        to absorb the slack, and it can size a column narrower than its own
        header, so the width is taken as the larger of the two and the last
        column is left as measured rather than stretched.
        """
        table.resizeColumnsToContents()
        header = table.horizontalHeader()
        metrics = QFontMetrics(header.font())
        for column in range(table.columnCount()):
            heading = table.horizontalHeaderItem(column)
            needed = metrics.horizontalAdvance(heading.text()) + 24 if heading else 0
            table.setColumnWidth(column, max(table.columnWidth(column), needed))

    def _extract_comprehensive_volume_info(self, start_offset):
        """Extract basic pytsk3 information from a volume."""
        info = {
            "basic": {},
            "filesystem": {}
        }

        try:
            # Get filesystem info
            fs_info = self.image_handler.get_fs_info(start_offset)
            if not fs_info:
                # TSK could not open it, which is not the same as there being
                # nothing there. A partition formatted twice keeps both sets of
                # structures and TSK refuses to guess between them; reporting
                # only "unable to access" hides a volume whose earlier contents
                # are still recoverable.
                present = self.image_handler.detect_filesystems(start_offset)
                if len(present) > 1:
                    info["basic"]["Status"] = (
                        f"{' + '.join(present)} -- two file systems present. "
                        "The volume was reformatted without being wiped, so "
                        "the earlier one's data may still be recoverable by "
                        "carving.")
                elif present:
                    info["basic"]["Status"] = (
                        f"{present[0]} present, but its structures are damaged "
                        "and cannot be read. Carving may still recover files.")
                else:
                    info["basic"]["Status"] = "Unable to access filesystem"
                return info

            fs_type = self.image_handler.get_fs_type(start_offset)

            # === BASIC INFO ===
            sector_size = self.image_handler.sector_size
            info["basic"]["Partition Offset"] = (
                f"{start_offset:,} sectors ({start_offset * sector_size:,} bytes)")
            info["basic"]["Filesystem Type"] = fs_type or "Unknown"

            if hasattr(fs_info.info, 'block_size'):
                info["basic"]["Block Size"] = f"{fs_info.info.block_size:,} bytes"
            if hasattr(fs_info.info, 'block_count'):
                total_blocks = fs_info.info.block_count
                total_size = total_blocks * fs_info.info.block_size
                info["basic"]["Total Blocks"] = f"{total_blocks:,}"
                info["basic"]["Volume Size"] = FileSystemUtils.get_readable_size(total_size)

            # === FILESYSTEM DETAILS ===
            if hasattr(fs_info.info, 'first_block'):
                info["filesystem"]["First Block"] = f"{fs_info.info.first_block:,}"
            if hasattr(fs_info.info, 'last_block'):
                info["filesystem"]["Last Block"] = f"{fs_info.info.last_block:,}"
            if hasattr(fs_info.info, 'inum_count'):
                info["filesystem"]["Inode Count"] = f"{fs_info.info.inum_count:,}"
            if hasattr(fs_info.info, 'root_inum'):
                info["filesystem"]["Root Inode"] = f"{fs_info.info.root_inum}"
            if hasattr(fs_info.info, 'last_inum'):
                info["filesystem"]["Last Inode"] = f"{fs_info.info.last_inum:,}"

            # Volume serial number. TSK hands this back as a fixed-length byte
            # array with fs_id_used saying how many of those bytes are real;
            # the rest are padding and must not be printed.
            serial = self._format_volume_serial(fs_info.info)
            if serial:
                info["filesystem"]["Volume Serial"] = serial

            if hasattr(fs_info.info, 'endian'):
                info["filesystem"]["Byte Order"] = (
                    "Little endian" if int(fs_info.info.endian) == 1 else "Big endian")

            # Operating system and timezone, read from the registry when this
            # volume carries a Windows installation. The timezone is the piece
            # that makes the rest usable: NTFS stores every timestamp in UTC,
            # so the machine's offset is what turns them into the local times
            # the user actually saw. A data volume returns nothing.
            try:
                info["filesystem"].update(
                    self.image_handler.get_os_info(start_offset))
            except Exception as e:
                logger.debug("Could not read OS information: %s", e)

        except Exception as e:
            logger.error(f"Error extracting volume info: {e}")
            info["basic"]["Error"] = str(e)

        return info

    #: Directories that say what a device was, when it holds no OS. Phones,
    #: cameras and music players all leave a recognisable top-level layout.
    _MEDIA_SIGNATURES = (
        ('/DCIM', 'Camera or phone storage (DCIM present)'),
        ('/PRIVATE/AVCHD', 'Camcorder storage (AVCHD)'),
        ('/Android', 'Android device storage'),
        ('/MP_ROOT', 'Camera storage (Sony MP_ROOT)'),
        ('/System Volume Information', None),
        ('/$RECYCLE.BIN', 'Attached to a Windows machine (Recycle Bin present)'),
        ('/.Trashes', 'Attached to a macOS machine (.Trashes present)'),
        ('/.Spotlight-V100', 'Indexed by macOS Spotlight'),
        ('/GARMIN', 'Garmin device storage'),
        ('/GRMN', 'Garmin device storage'),
        ('/APPLE', 'Apple device storage'),
    )

    def _media_summary(self):
        """Describe an image with no operating system on it.

        A flash drive, camera card or watch backup is still worth describing:
        what the volumes are, how they are formatted, how full they are, and
        any top-level directory that says what wrote them. Without this the
        dialog simply had nothing to say about the majority of small exhibits.
        """
        summary = {}
        handler = self.image_handler
        if handler is None:
            return summary

        filesystems = []
        labels = []
        traces = []

        # An unpartitioned image -- a formatted USB stick or camera card, which
        # is most of what this section exists for -- has no partition list, so
        # its single filesystem sits at offset 0.
        starts = [p[2] for p in handler.get_partitions()]
        if not starts:
            starts = [0]

        for start in starts:
            fs_type = handler.get_fs_type(start)
            if not fs_type or fs_type == 'N/A':
                # TSK could not open one, but the partition may still hold a
                # filesystem it refuses to guess between -- a volume formatted
                # twice keeps both sets of structures, and the older data is
                # still recoverable. Saying nothing here is what makes such a
                # partition look empty.
                for name in handler.detect_filesystems(start):
                    entry = f"{name} (not mountable)"
                    if entry not in filesystems:
                        filesystems.append(entry)
                continue
            if fs_type not in filesystems:
                filesystems.append(fs_type)

            # A second signature under a mountable filesystem means the volume
            # was reformatted without being wiped.
            buried = [n for n in handler.detect_filesystems(start)
                      if not n.startswith(fs_type[:3])]
            for name in buried:
                entry = f"{name} (overwritten, data may survive)"
                if entry not in filesystems:
                    filesystems.append(entry)

            fs_info = handler.get_fs_info(start)
            if fs_info is None:
                continue

            used = self._volume_usage(fs_info)
            if used:
                labels.append(f"{fs_type} at sector {start:,}: {used}")

            for path, description in self._MEDIA_SIGNATURES:
                if description is None:
                    continue
                try:
                    fs_info.open(path)
                except Exception:
                    continue
                if description not in traces:
                    traces.append(description)

        if filesystems:
            summary['Filesystems'] = ', '.join(filesystems)
        else:
            summary['Filesystems'] = 'None recognised'

        if labels:
            summary['Usage'] = '   ·   '.join(labels)

        if traces:
            summary['Indications'] = '; '.join(traces)
        else:
            summary['Indications'] = 'No device-specific directories found'

        return summary

    @staticmethod
    def _volume_usage(fs_info):
        """How much of a volume is in use, from its own block accounting."""
        try:
            block_size = fs_info.info.block_size
            total = fs_info.info.block_count * block_size
        except Exception:
            return ''
        if total <= 0:
            return ''
        return FileSystemUtils.get_readable_size(total) + ' formatted'

    def _installed_systems(self):
        """Every volume that carries an operating system, in partition order.

        Returned as a list rather than the first match: a dual-boot disk holds
        more than one, and reporting only the first would hide the rest --
        exactly the volumes an examiner most wants to know about.
        """
        found = []
        for partition in self.image_handler.get_partitions():
            start = partition[2]
            try:
                info = self.image_handler.get_os_info(start)
            except Exception as e:
                logger.debug("Could not read OS info at %s: %s", start, e)
                continue
            if info.get("Operating System"):
                found.append((start, info))
        return found

    def _installed_system_summary(self):
        """The first installed system, kept for callers wanting just one."""
        systems = self._installed_systems()
        return systems[0][1] if systems else {}

    @staticmethod
    def _format_volume_serial(fs_info_struct):
        """The filesystem's serial number, as the acquisition tools print it.

        Identifies the volume independently of any partition layout, so it is
        how an image is tied back to the device it came from. Only the first
        `fs_id_used` bytes of `fs_id` are meaningful; the remainder is padding.
        """
        try:
            raw = list(fs_info_struct.fs_id)
            used = int(getattr(fs_info_struct, 'fs_id_used', 0) or 0)
        except Exception:
            return None
        if used <= 0 or not raw:
            return None
        digits = ''.join(f'{byte:02X}' for byte in raw[:used])
        # NTFS serials are conventionally shown in 8-character halves.
        if len(digits) == 16:
            return f"{digits[:8]}-{digits[8:]}"
        return digits

    def _get_image_info(self):
        """Extract comprehensive disk image information."""
        info = {}

        try:
            # Basic image info
            info["Image Path"] = self.image_handler.image_path
            info["Image Type"] = self.image_handler.get_image_type().upper()

            # Image size
            total_size = self.image_handler.get_size()
            info["Total Size"] = FileSystemUtils.get_readable_size(total_size)
            info["Total Size (Bytes)"] = f"{total_size:,}"

            # Sector information, read from the image rather than assumed.
            # This is reported to the examiner as a fact about the evidence,
            # so it must not be a literal: it was hardcoded to "512", which
            # would have been a false statement on a 4Kn drive.
            sector_size = self.image_handler.sector_size
            sector_count = total_size // sector_size
            info["Total Sectors"] = f"{sector_count:,}"
            info["Bytes per Sector"] = f"{sector_size:,}"

            # Volume information
            if self.image_handler.volume_info:
                try:
                    vol_type = self.image_handler.volume_info.info.vstype
                    volume_types = {
                        pytsk3.TSK_VS_TYPE_DOS: "DOS/MBR",
                        pytsk3.TSK_VS_TYPE_GPT: "GPT (GUID Partition Table)",
                        pytsk3.TSK_VS_TYPE_MAC: "Mac Partition Map",
                        pytsk3.TSK_VS_TYPE_BSD: "BSD Disk Label",
                        pytsk3.TSK_VS_TYPE_SUN: "Sun VTOC",
                    }
                    info["Partition Scheme"] = volume_types.get(vol_type, f"Unknown ({vol_type})")
                    info["Number of Partitions"] = len(self.image_handler.get_partitions())
                except Exception as e:
                    logger.debug(f"Could not get volume type: {e}")
            else:
                info["Partition Scheme"] = "No partition table detected"

            # Check if wiped
            if self.image_handler.is_wiped():
                info["Status"] = "⚠️ Wiped/Empty Image"
            else:
                info["Status"] = "✓ Valid Image"

            # File modification time
            if os.path.exists(self.image_handler.image_path):
                mod_time = os.path.getmtime(self.image_handler.image_path)
                info["File Modified"] = datetime.datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d %H:%M:%S")

        except Exception as e:
            logger.error(f"Error getting image info: {e}")
            info["Error"] = str(e)

        return info

    def _get_filesystem_colors(self):
        """Return consistent color mapping for filesystem types."""
        return {
            "NTFS": QColor(41, 128, 185),      # Blue
            "FAT32": QColor(46, 204, 113),     # Green
            "FAT16": QColor(26, 188, 156),     # Turquoise
            "FAT12": QColor(22, 160, 133),     # Dark Turquoise
            "exFAT": QColor(52, 152, 219),     # Light Blue
            "EXT4": QColor(231, 76, 60),       # Red
            "EXT3": QColor(192, 57, 43),       # Dark Red
            "EXT2": QColor(155, 89, 182),      # Purple
            "HFS+": QColor(241, 196, 15),      # Yellow
            "APFS": QColor(243, 156, 18),      # Orange
            "ISO9660": QColor(230, 126, 34),   # Dark Orange
            "Unallocated": QColor(149, 165, 166),  # Gray
            "Unknown": QColor(127, 140, 141),  # Dark Gray
        }

    def _create_space_allocation_chart(self):
        """Create a pie chart showing allocated vs unallocated space."""
        # Create pie series
        series = QPieSeries()
        legend_items = []  # Track items for legend

        try:
            total_size = self.image_handler.get_size()
            partitions = self.image_handler.get_partitions()

            # Get filesystem color mapping
            fs_colors = self._get_filesystem_colors()

            # Calculate allocated space (partitions)
            allocated_space = 0
            partition_details = []

            if partitions:
                sector_size = self.image_handler.sector_size
                for part in partitions:
                    addr, desc, start, length = part
                    size = length * sector_size
                    allocated_space += size

                    # Get filesystem type
                    fs_type = self.image_handler.get_fs_type(start)
                    if not fs_type:
                        fs_type = "Unknown"

                    partition_details.append((fs_type, size, part[0]))

            # Calculate unallocated space
            unallocated_space = total_size - allocated_space

            # Add partition slices with consistent colors
            for idx, (fs_type, size, part_num) in enumerate(partition_details):
                percentage = (size / total_size) * 100

                # Don't show label on slice - use legend instead
                slice = series.append("", size)

                # Use consistent color based on filesystem type
                color = fs_colors.get(fs_type, fs_colors["Unknown"])
                slice.setColor(color)
                slice.setLabelVisible(False)  # Hide labels on pie

                # Add border between slices for clear separation
                slice.setBorderColor(QColor(255, 255, 255))
                slice.setBorderWidth(3)

                # Add to legend with full details
                legend_label = f"{fs_type} - Partition {part_num} ({FileSystemUtils.get_readable_size(size)}, {percentage:.1f}%)"
                legend_items.append((legend_label, color))

            # Add unallocated space
            if unallocated_space > 0:
                percentage = (unallocated_space / total_size) * 100
                unalloc_slice = series.append("", unallocated_space)
                unalloc_slice.setColor(fs_colors["Unallocated"])
                unalloc_slice.setLabelVisible(False)
                unalloc_slice.setBorderColor(QColor(255, 255, 255))
                unalloc_slice.setBorderWidth(3)

                # Add to legend
                legend_label = f"Unallocated Space ({FileSystemUtils.get_readable_size(unallocated_space)}, {percentage:.1f}%)"
                legend_items.append((legend_label, fs_colors["Unallocated"]))

            # If no partitions, show entire disk as unallocated
            if not partitions:
                slice = series.append("", total_size)
                slice.setColor(fs_colors["Unallocated"])
                slice.setLabelVisible(False)

                # Add to legend
                legend_label = f"Entire Disk ({FileSystemUtils.get_readable_size(total_size)}, 100%)"
                legend_items.append((legend_label, fs_colors["Unallocated"]))

        except Exception as e:
            logger.error(f"Error creating allocation chart: {e}")
            # Add error slice
            series.append("Error Loading Data", 1)

        # Create chart
        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setVisible(False)  # Use custom legend instead

        # Minimal margins for maximum chart size
        chart.setMargins(QMargins(0, 0, 0, 0))
        chart.setBackgroundVisible(False)

        # Create chart view
        chart_view = QChartView(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        chart_view.setMinimumSize(350, 350)
        chart_view.setObjectName("volumeInfoChartView")

        return chart_view, legend_items
