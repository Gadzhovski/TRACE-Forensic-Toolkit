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
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from modules.utils import FileSystemUtils

logger = logging.getLogger('TRACE.VolumeInfo')


class VolumeInfoMixin:
    """Builds the image/volume information dialog."""

    def view_os_information(self, index):
        """Display comprehensive disk image information with space allocation pie chart."""
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            # Ensure that only the root item triggers the information display
            return

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
        top_widget.setStyleSheet("background-color: #f8f9fa; border-bottom: 2px solid #dee2e6;")
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(20, 20, 20, 20)
        top_layout.setSpacing(30)

        # Left: Image Summary Card
        summary_card = QWidget()
        summary_card.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dee2e6;
            }
        """)
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(20, 20, 20, 20)
        summary_layout.setSpacing(12)

        # Title
        title_label = QLabel("Disk Image Overview")
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #212529; border: none;")
        summary_layout.addWidget(title_label)

        # Key info
        image_info = self._get_image_info()
        key_fields = ["Image Path", "Image Type", "Total Size", "Partition Scheme", "Number of Partitions", "Status"]

        for field in key_fields:
            if field in image_info:
                info_row = QWidget()
                info_row.setStyleSheet("border: none;")
                info_row_layout = QHBoxLayout(info_row)
                info_row_layout.setContentsMargins(0, 0, 0, 0)
                info_row_layout.setSpacing(10)

                label = QLabel(f"{field}:")
                label.setStyleSheet("font-weight: bold; color: #495057; font-size: 10pt; border: none;")
                label.setMinimumWidth(140)

                value = QLabel(str(image_info[field]))
                value.setStyleSheet("color: #212529; font-size: 10pt; border: none;")
                value.setTextInteractionFlags(Qt.TextSelectableByMouse)
                value.setWordWrap(True)

                info_row_layout.addWidget(label)
                info_row_layout.addWidget(value, 1)

                summary_layout.addWidget(info_row)

        summary_layout.addStretch()
        summary_card.setFixedWidth(450)

        # Right: Pie Chart with Legend
        chart_widget = QWidget()
        chart_widget.setStyleSheet("""
            QWidget {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #dee2e6;
            }
        """)
        chart_outer_layout = QVBoxLayout(chart_widget)
        chart_outer_layout.setContentsMargins(15, 15, 15, 15)
        chart_outer_layout.setSpacing(10)

        chart_title = QLabel("Space Allocation")
        chart_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #212529; border: none;")
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
            legend_widget.setStyleSheet("border: none;")
            legend_layout = QVBoxLayout(legend_widget)
            legend_layout.setContentsMargins(5, 5, 5, 5)
            legend_layout.setSpacing(6)

            for label_text, color in partition_info_list:
                legend_row = QWidget()
                legend_row.setStyleSheet("border: none;")
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
                text_label.setStyleSheet("color: #495057; font-size: 9pt; border: none;")
                text_label.setWordWrap(True)

                legend_row_layout.addWidget(color_indicator)
                legend_row_layout.addWidget(text_label, 1)

                legend_layout.addWidget(legend_row)

            legend_layout.addStretch()
            legend_widget.setMaximumWidth(300)
            chart_content_layout.addWidget(legend_widget)

        chart_content_layout.addWidget(chart_view, 1)
        chart_outer_layout.addLayout(chart_content_layout, 1)

        top_layout.addWidget(summary_card)
        top_layout.addWidget(chart_widget, 1)

        main_layout.addWidget(top_widget)

        # === BOTTOM SECTION: Detailed Partition Information ===
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(20, 20, 20, 20)
        bottom_layout.setSpacing(15)

        # Section title
        details_title = QLabel("Volume Details")
        details_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #212529; padding-bottom: 10px;")
        bottom_layout.addWidget(details_title)

        # Professional table view for volume information
        volume_table = QTableWidget()
        volume_table.setSortingEnabled(True)
        volume_table.verticalHeader().setVisible(False)
        volume_table.setObjectName("volumeInfoTable")
        volume_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        volume_table.setAlternatingRowColors(True)
        volume_table.setEditTriggers(QTableWidget.NoEditTriggers)
        volume_table.setIconSize(QSize(24, 24))
        volume_table.setSelectionBehavior(QTableWidget.SelectRows)

        # Enable horizontal scrolling for smaller windows
        volume_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        volume_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Set column count and headers
        volume_table.setColumnCount(10)
        volume_table.setHorizontalHeaderLabels([
            'Volume', 'Filesystem', 'Offset (Sectors)', 'Block Size', 'Volume Size',
            'Total Blocks', 'First Block', 'Last Block', 'Inode Count', 'Root Inode'
        ])

        # Configure header - all columns use Interactive mode for horizontal scrolling
        header = volume_table.horizontalHeader()
        for i in range(10):
            header.setSectionResizeMode(i, QHeaderView.Interactive)

        # Set column widths
        volume_table.setColumnWidth(0, 100)   # Volume
        volume_table.setColumnWidth(1, 120)   # Filesystem
        volume_table.setColumnWidth(2, 140)   # Offset
        volume_table.setColumnWidth(3, 100)   # Block Size
        volume_table.setColumnWidth(4, 120)   # Volume Size
        volume_table.setColumnWidth(5, 120)   # Total Blocks
        volume_table.setColumnWidth(6, 120)   # First Block
        volume_table.setColumnWidth(7, 120)   # Last Block
        volume_table.setColumnWidth(8, 120)   # Inode Count
        volume_table.setColumnWidth(9, 100)   # Root Inode

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

        bottom_layout.addWidget(volume_table, 1)

        # Close button at bottom right
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        close_button.setMinimumWidth(100)

        button_layout.addWidget(close_button)
        bottom_layout.addLayout(button_layout)

        main_layout.addWidget(bottom_widget, 1)

        dialog.exec()

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

        table.setSortingEnabled(True)  # Re-enable sorting after populating

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
                info["basic"]["Status"] = "Unable to access filesystem"
                return info

            fs_type = self.image_handler.get_fs_type(start_offset)

            # === BASIC INFO ===
            info["basic"]["Partition Offset"] = f"{start_offset:,} sectors ({start_offset * 512:,} bytes)"
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

        except Exception as e:
            logger.error(f"Error extracting volume info: {e}")
            info["basic"]["Error"] = str(e)

        return info

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

            # Sector information
            sector_count = total_size // 512
            info["Total Sectors"] = f"{sector_count:,}"
            info["Bytes per Sector"] = "512"

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
                for part in partitions:
                    addr, desc, start, length = part
                    size = length * 512
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
        chart_view.setStyleSheet("border: none; background: transparent;")

        return chart_view, legend_items
