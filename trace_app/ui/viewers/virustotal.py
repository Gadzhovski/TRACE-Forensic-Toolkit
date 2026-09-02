import logging
import io
import zipfile
from datetime import date
from time import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel,
                               QMessageBox, QPushButton, QSizePolicy, QTableWidget,
                               QTableWidgetItem, QTextBrowser, QToolBar, QVBoxLayout,
                               QWidget, QWidgetAction)
from datetime import datetime

from requests import get as requests_get, post as requests_post
from requests.exceptions import RequestException
from trace_app.infra.paths import resource_path
from trace_app.infra.constants import BUTTON_WIDTH_WIDE, TOOLBAR_HEIGHT
from trace_app.ui import icons
from trace_app.ui.widgets.property_table import PropertyTable

logger = logging.getLogger('TRACE.VirusTotal')


class VirusTotal(QWidget):
    def __init__(self):
        super().__init__()
        self.last_request_time = 0
        self.requests_made_last_minute = 0
        self.daily_requests_made = 0
        self.current_date = date.today()
        self.api_key = None
        self.current_file_hash = None
        self.current_file_content = None
        self.current_file_name = None

        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)

        # First toolbar for the VirusTotal logo
        self.logo_toolbar = QToolBar(self)
        self.logo_toolbar.setContentsMargins(0, 0, 0, 0)  # Add some margins to the toolbar for better aesthetics

        self.setup_logo_toolbar()
        self.layout.addWidget(self.logo_toolbar)

        self.action_toolbar = QToolBar(self)
        self.action_toolbar.setContentsMargins(0, 0, 0, 0)
        self.setup_action_toolbar()
        self.layout.addWidget(self.action_toolbar)
        self.action_toolbar.setVisible(False)  # Hide this toolbar initially

        buttonLayout = QHBoxLayout()
        # align the button vertically and horizontally
        buttonLayout.setAlignment(Qt.AlignCenter)  # Align the buttons to the center

        self.pass_hash_button = QPushButton("Pass Hash")
        self.pass_hash_button.clicked.connect(self.pass_hash)
        self.pass_hash_button.setFixedSize(BUTTON_WIDTH_WIDE, TOOLBAR_HEIGHT)

        buttonLayout.addWidget(self.pass_hash_button)

        # Upload File Button
        self.upload_file_button = QPushButton("Upload File")
        self.upload_file_button.clicked.connect(self.upload_file)
        self.upload_file_button.setFixedSize(BUTTON_WIDTH_WIDE, TOOLBAR_HEIGHT)

        buttonLayout.addWidget(self.upload_file_button)
        self.layout.addLayout(buttonLayout)

        # Status messages (errors, rate limits) stay in a text pane.
        self.info_text_edit = QTextBrowser(self)
        self.info_text_edit.setReadOnly(True)
        self.info_text_edit.setVisible(False)
        self.layout.addWidget(self.info_text_edit)

        # The report itself is tabular, so it is built from real widgets: a
        # summary block plus a table of engine results. Previously this was a
        # generated HTML document, which ignored the application theme.
        self.results_widget = QWidget(self)
        results_layout = QVBoxLayout(self.results_widget)
        results_layout.setContentsMargins(8, 8, 8, 8)
        results_layout.setSpacing(6)

        self.verdict_label = QLabel(self.results_widget)
        self.verdict_label.setObjectName("vtVerdict")
        results_layout.addWidget(self.verdict_label)

        self.summary_table = PropertyTable("Property", "Value", self.results_widget)
        self.summary_table.setMaximumHeight(170)
        results_layout.addWidget(self.summary_table)

        engines_label = QLabel("Detections by engine", self.results_widget)
        engines_label.setObjectName("vtSectionLabel")
        results_layout.addWidget(engines_label)

        self.engine_table = QTableWidget(0, 5, self.results_widget)
        self.engine_table.setObjectName("propertyTable")
        self.engine_table.setHorizontalHeaderLabels(
            ["Engine", "Detected", "Version", "Updated", "Result"])
        self.engine_table.verticalHeader().setVisible(False)
        self.engine_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.engine_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.engine_table.setAlternatingRowColors(True)
        self.engine_table.setSortingEnabled(True)
        self.engine_table.setShowGrid(False)
        eh = self.engine_table.horizontalHeader()
        eh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        eh.setSectionResizeMode(4, QHeaderView.Stretch)
        results_layout.addWidget(self.engine_table)

        self.results_widget.setVisible(False)
        self.layout.addWidget(self.results_widget)

    def set_api_key(self, key):
        self.api_key = key

    def spacer(self, policy1, policy2):
        spacer = QWidget(self)
        spacer.setSizePolicy(policy1, policy2)
        # A bare QWidget picks up the content-surface colour, which is lighter
        # than a toolbar and shows as a pale band in the gap.
        spacer.setStyleSheet("background: transparent;")
        return spacer

    def setup_logo_toolbar(self):
        self.logo_toolbar.addWidget(self.spacer(QSizePolicy.Expanding, QSizePolicy.Preferred))
        self.virus_total_logo = icons.apply_svg(QSvgWidget(), icons.VIRUSTOTAL_LOGO)
        self.virus_total_logo.setFixedSize(141, 27)
        logo_action = QWidgetAction(self)
        logo_action.setDefaultWidget(self.virus_total_logo)
        self.logo_toolbar.addAction(logo_action)
        self.virus_total_logo.mousePressEvent = self.virus_total_website
        self.virus_total_logo.setCursor(Qt.PointingHandCursor)

    def setup_action_toolbar(self):
        self.view_in_browser_action = icons.action(icons.WEB_BROWSER, "View in Browser",
                                              self)
        self.view_in_browser_action.triggered.connect(self.view_in_browser)
        self.action_toolbar.addAction(self.view_in_browser_action)
        self.view_in_browser_action.setVisible(True)

        self.back_action = icons.action(icons.BACK, "Back", self)
        self.back_action.triggered.connect(self.reset_ui)
        self.action_toolbar.addAction(self.back_action)
        self.action_toolbar.addWidget(self.spacer(QSizePolicy.Expanding, QSizePolicy.Preferred))

        self.virus_total_logo = icons.apply_svg(QSvgWidget(), icons.VIRUSTOTAL_LOGO)
        self.virus_total_logo.setFixedSize(141, 27)
        logo_action = QWidgetAction(self)
        logo_action.setDefaultWidget(self.virus_total_logo)
        self.action_toolbar.addAction(logo_action)
        self.virus_total_logo.mousePressEvent = self.virus_total_website
        self.virus_total_logo.setCursor(Qt.PointingHandCursor)

    def virus_total_website(self, event):
        import webbrowser
        webbrowser.open("https://www.virustotal.com")

    def reset_ui(self):
        self.info_text_edit.setVisible(False)
        self.pass_hash_button.setVisible(True)
        self.upload_file_button.setVisible(True)
        self.action_toolbar.setVisible(False)  # Hide action toolbar

    def set_file_hash(self, file_hash):
        self.current_file_hash = file_hash

    # set file content to expect file content as bytes and name as string
    def set_file_content(self, file_content, file_name="unnamed_file"):
        """Sets the current file content and assigns a default name if none is provided."""
        self.current_file_content = file_content
        if not file_name:
            self.current_file_name = "unnamed_file"
        else:
            self.current_file_name = file_name

    def upload_file(self):
        """Prepares the file content and name for upload."""
        if not self.api_key:
            QMessageBox.warning(self, "API Key Not Set",
                                "Please set the API key in the Options menu before uploading a file.")
            return

        if self.current_file_content and self.current_file_name:
            # Assuming current_file_content is the content of the file to upload,
            # and current_file_name is the name of the file.
            self.upload_file_to_virustotal(self.current_file_content, self.current_file_name)
        else:
            self.info_text_edit.setText("No file content or name provided.")
            self.info_text_edit.setVisible(True)

    def zip_file_in_memory(self, content: bytes, file_name: str):
        """Creates a zip archive in memory containing the given file."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr(file_name, content)
        zip_buffer.seek(0)
        return zip_buffer

    def upload_file_to_virustotal(self, file_content, file_name):
        """Uploads a zipped file to VirusTotal."""
        # Here, file_content should be the content of the file to upload,
        # and file_name should be the name of the file inside the zip.
        zip_buffer = self.zip_file_in_memory(file_content, file_name)

        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": self.api_key
        }
        files = {'file': (file_name + '.zip', zip_buffer.getvalue())}
        response = requests_post(url, headers=headers, files=files)

        if response.status_code == 200:
            self.process_vt_response(response.json())
        else:
            logger.error("Failed to upload file to VirusTotal:", response.text)

    def process_vt_response(self, response):
        data = response.get('data', {})
        file_id = data.get('id', 'N/A')
        file_hash = data.get('attributes', {}).get('sha256', 'N/A')
        upload_date = data.get('attributes', {}).get('date', 'N/A')
        self.current_file_hash = file_hash
        self.update_virustotal_info()
        self.logo_toolbar.setVisible(False)
        self.action_toolbar.setVisible(True)
        self.view_in_browser_action.setVisible(False)

    def pass_hash(self):
        if not self.api_key:
            QMessageBox.warning(self, "API Key Not Set",
                                "Please set the API key in the Options menu before passing a hash.")
            return

        if not self.current_file_hash:
            self.info_text_edit.setText("No hash provided.")
            self.info_text_edit.setVisible(True)
            return
        self.update_virustotal_info()
        self.action_toolbar.setVisible(True)
        self.view_in_browser_action.setVisible(True)
        self.logo_toolbar.setVisible(False)

    def update_virustotal_info(self):
        self.info_text_edit.setVisible(True)
        self.results_widget.setVisible(False)
        self.pass_hash_button.setVisible(False)
        self.upload_file_button.setVisible(False)
        if self.current_file_hash:
            data = self.vt_getresult(self.current_file_hash)
            if not data:  # Check if the data is empty. If empty, it means there was a rate limit error.
                self.info_text_edit.setText("Failed to fetch data.")
                return
            self.show_report(data)

    def vt_getresult(self, hashes):
        # Check if we're on a new day
        if date.today() != self.current_date:
            self.current_date = date.today()
            self.daily_requests_made = 0

        # Check if we've exceeded daily limit
        if self.daily_requests_made >= 500:
            self.info_text_edit.setPlainText("Daily request limit exceeded. Please try again tomorrow.")
            return {}

        # Check if we made a request in the last minute
        current_time = time()
        if current_time - self.last_request_time < 60:
            self.requests_made_last_minute += 1
            if self.requests_made_last_minute > 3:
                # Inform the user about the rate limit with enhanced formatting
                # Plain text: the previous HTML hardcoded a blue link colour and
                # carried an onclick handler, which Qt's rich text never runs.
                self.info_text_edit.setPlainText(
                    "Rate limit exceeded.\n\n"
                    "Please wait a minute and try again, or use "
                    "'View in Browser' above.")
                return {}
        else:
            # If it's been more than a minute since the last request, reset the counter
            self.requests_made_last_minute = 1

        # Update the last request time and daily requests count
        self.last_request_time = current_time
        self.daily_requests_made += 1

        # v3, matching the upload path. The v2 endpoint this used to call has
        # been retired, and it passed the API key in the query string, where it
        # ends up in proxy and server logs; v3 sends it in a header.
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        url = f"https://www.virustotal.com/api/v3/files/{hashes}"

        try:
            response = requests_get(url, headers=headers, timeout=30)
        except RequestException as e:
            logger.error("VirusTotal request failed: %s", e)
            self.info_text_edit.setPlainText(f"Could not reach VirusTotal: {e}")
            return {}

        if response.status_code == 404:
            self.info_text_edit.setPlainText(
                "This file is not in the VirusTotal database. Upload it to have it scanned.")
            return {}
        if response.status_code == 401:
            self.info_text_edit.setPlainText("VirusTotal rejected the API key. Check it in Options > API Keys.")
            return {}
        if response.status_code != 200:
            logger.error("VirusTotal returned HTTP %s", response.status_code)
            self.info_text_edit.setPlainText(f"VirusTotal returned an error (HTTP {response.status_code}).")
            return {}

        try:
            payload = response.json()
        except ValueError as e:
            logger.error("Could not decode VirusTotal response: %s", e)
            self.info_text_edit.setPlainText("Error decoding the response from VirusTotal. Please try again.")
            return {}

        return self._normalise_v3_report(payload, hashes)

    @staticmethod
    def _normalise_v3_report(payload, resource):
        """Map a v3 file report onto the flat shape the HTML renderer expects.

        v3 nests everything under data.attributes and renames the per-engine
        fields (engine_version -> version, engine_update -> update, and
        `category` carries the verdict instead of a boolean `detected`).
        Converting here keeps format_data_as_html() unchanged.
        """
        attributes = (payload.get('data') or {}).get('attributes') or {}
        results = attributes.get('last_analysis_results') or {}
        stats = attributes.get('last_analysis_stats') or {}

        scans = {}
        for engine, result in results.items():
            category = result.get('category')
            scans[engine] = {
                'detected': category in ('malicious', 'suspicious'),
                'version': result.get('engine_version') or 'N/A',
                'update': result.get('engine_update') or 'N/A',
                'result': result.get('result') or 'N/A',
            }

        scan_date = attributes.get('last_analysis_date')
        if scan_date:
            scan_date = datetime.utcfromtimestamp(scan_date).strftime('%Y-%m-%d %H:%M:%S')

        sha256 = attributes.get('sha256', resource)
        return {
            'md5': attributes.get('md5', 'N/A'),
            'sha1': attributes.get('sha1', 'N/A'),
            'sha256': sha256,
            'scan_date': scan_date or 'N/A',
            'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
            'total': sum(v for v in stats.values() if isinstance(v, int)),
            'permalink': f"https://www.virustotal.com/gui/file/{sha256}/detection",
            'scans': scans,
        }

    def show_report(self, data):
        """Populate the summary and engine table from a normalised report."""
        positives = data.get('positives', 0)
        total = data.get('total', 0)

        if positives:
            self.verdict_label.setText(f"{positives} of {total} engines flagged this file")
            self.verdict_label.setProperty("state", "malicious")
        else:
            self.verdict_label.setText(f"No engine flagged this file ({total} checked)")
            self.verdict_label.setProperty("state", "clean")
        # Re-polish so the state property takes effect.
        self.verdict_label.style().unpolish(self.verdict_label)
        self.verdict_label.style().polish(self.verdict_label)

        self.summary_table.set_rows([
            ("MD5", data.get('md5', 'N/A')),
            ("SHA-1", data.get('sha1', 'N/A')),
            ("SHA-256", data.get('sha256', 'N/A')),
            ("Last scanned", data.get('scan_date', 'N/A')),
            ("Score", f"{positives}/{total}"),
        ])

        scans = data.get('scans', {})
        self.engine_table.setSortingEnabled(False)
        self.engine_table.setRowCount(len(scans))
        for row, (engine, result) in enumerate(sorted(scans.items())):
            detected = bool(result.get('detected'))
            cells = [
                engine,
                "Yes" if detected else "No",
                result.get('version', 'N/A'),
                result.get('update', 'N/A'),
                result.get('result', 'N/A') or 'N/A',
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                if detected:
                    item.setData(Qt.UserRole + 1, "malicious")
                self.engine_table.setItem(row, col, item)
        self.engine_table.setSortingEnabled(True)

        self.info_text_edit.setVisible(False)
        self.results_widget.setVisible(True)

    def vt_getresult(self, hashes):
        # Check if we're on a new day
        if date.today() != self.current_date:
            self.current_date = date.today()
            self.daily_requests_made = 0

        # Check if we've exceeded daily limit
        if self.daily_requests_made >= 500:
            self.info_text_edit.setPlainText("Daily request limit exceeded. Please try again tomorrow.")
            return {}

        # Check if we made a request in the last minute
        current_time = time()
        if current_time - self.last_request_time < 60:
            self.requests_made_last_minute += 1
            if self.requests_made_last_minute > 3:
                # Inform the user about the rate limit with enhanced formatting
                # Plain text: the previous HTML hardcoded a blue link colour and
                # carried an onclick handler, which Qt's rich text never runs.
                self.info_text_edit.setPlainText(
                    "Rate limit exceeded.\n\n"
                    "Please wait a minute and try again, or use "
                    "'View in Browser' above.")
                return {}
        else:
            # If it's been more than a minute since the last request, reset the counter
            self.requests_made_last_minute = 1

        # Update the last request time and daily requests count
        self.last_request_time = current_time
        self.daily_requests_made += 1

        # v3, matching the upload path. The v2 endpoint this used to call has
        # been retired, and it passed the API key in the query string, where it
        # ends up in proxy and server logs; v3 sends it in a header.
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        url = f"https://www.virustotal.com/api/v3/files/{hashes}"

        try:
            response = requests_get(url, headers=headers, timeout=30)
        except RequestException as e:
            logger.error("VirusTotal request failed: %s", e)
            self.info_text_edit.setPlainText(f"Could not reach VirusTotal: {e}")
            return {}

        if response.status_code == 404:
            self.info_text_edit.setPlainText(
                "This file is not in the VirusTotal database. Upload it to have it scanned.")
            return {}
        if response.status_code == 401:
            self.info_text_edit.setPlainText("VirusTotal rejected the API key. Check it in Options > API Keys.")
            return {}
        if response.status_code != 200:
            logger.error("VirusTotal returned HTTP %s", response.status_code)
            self.info_text_edit.setPlainText(f"VirusTotal returned an error (HTTP {response.status_code}).")
            return {}

        try:
            payload = response.json()
        except ValueError as e:
            logger.error("Could not decode VirusTotal response: %s", e)
            self.info_text_edit.setPlainText("Error decoding the response from VirusTotal. Please try again.")
            return {}

        return self._normalise_v3_report(payload, hashes)

    @staticmethod
    def _normalise_v3_report(payload, resource):
        """Map a v3 file report onto the flat shape the HTML renderer expects.

        v3 nests everything under data.attributes and renames the per-engine
        fields (engine_version -> version, engine_update -> update, and
        `category` carries the verdict instead of a boolean `detected`).
        Converting here keeps format_data_as_html() unchanged.
        """
        attributes = (payload.get('data') or {}).get('attributes') or {}
        results = attributes.get('last_analysis_results') or {}
        stats = attributes.get('last_analysis_stats') or {}

        scans = {}
        for engine, result in results.items():
            category = result.get('category')
            scans[engine] = {
                'detected': category in ('malicious', 'suspicious'),
                'version': result.get('engine_version') or 'N/A',
                'update': result.get('engine_update') or 'N/A',
                'result': result.get('result') or 'N/A',
            }

        scan_date = attributes.get('last_analysis_date')
        if scan_date:
            scan_date = datetime.utcfromtimestamp(scan_date).strftime('%Y-%m-%d %H:%M:%S')

        sha256 = attributes.get('sha256', resource)
        return {
            'md5': attributes.get('md5', 'N/A'),
            'sha1': attributes.get('sha1', 'N/A'),
            'sha256': sha256,
            'scan_date': scan_date or 'N/A',
            'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
            'total': sum(v for v in stats.values() if isinstance(v, int)),
            'permalink': f"https://www.virustotal.com/gui/file/{sha256}/detection",
            'scans': scans,
        }

    def format_data_as_html(self, data):
        # Extract main details from the data
        md5 = data.get('md5', 'N/A')
        sha1 = data.get('sha1', 'N/A')
        sha256 = data.get('sha256', 'N/A')
        scan_date = data.get('scan_date', 'N/A')
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        permalink = data.get('permalink', 'N/A')

        # Extract and format the scan results
        scans = data.get('scans', {})
        scan_rows = ""
        for antivirus, result in scans.items():
            detected = "Yes" if result.get('detected') else "No"
            version = result.get('version', 'N/A')
            last_update = result.get('update', 'N/A')
            scan_result = result.get('result', 'N/A') or 'N/A'
            scan_rows += f"""
            <tr>
                <td>{antivirus}</td>
                <td>{detected}</td>
                <td>{version}</td>
                <td>{last_update}</td>
                <td>{scan_result}</td>
            </tr>
            """

        # Create the HTML content
        html_content = f"""
        <div style="font-family: Arial;">
            <h2>VirusTotal Information</h2>
            <p><strong>MD5:</strong> {md5}</p>
            <p><strong>SHA1:</strong> {sha1}</p>
            <p><strong>SHA256:</strong> {sha256}</p>
            <p><strong>Last Scanned:</strong> {scan_date}</p>
            <p><strong>Score:</strong> {positives}/{total}</p>
            <p><strong>Permalink:</strong> <a href="{permalink}">{permalink}</a></p>

            <h3>Scan Results:</h3>
            <table border="1" cellpadding="5">
                <thead>
                    <tr>
                        <th>Antivirus</th>
                        <th>Detected</th>
                        <th>Version</th>
                        <th>Last Update</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    {scan_rows}
                </tbody>
            </table>
        </div>
        """
        return html_content

    def view_in_browser(self):
        """Open the VirusTotal URL in the default web browser."""
        if self.current_file_hash:
            import webbrowser
            webbrowser.open(f"https://www.virustotal.com/gui/file/{self.current_file_hash}/detection")
