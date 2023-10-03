from requests import post as requests_post
from requests.exceptions import RequestException
from datetime import date
from time import time

from PySide6.QtGui import QAction
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import QWidget, QVBoxLayout, QToolBar, QWidgetAction, QSizePolicy, QTextBrowser


class VirusTotal(QWidget):
    def __init__(self):
        super().__init__()
        # Add a timestamp for the last API request and other rate limiting attributes
        self.last_request_time = 0
        self.requests_made_last_minute = 0
        self.daily_requests_made = 0
        self.current_date = date.today()

        # Hardcoded API key
        self.api_key = "014e215d1cc11255fe69d71bea313e31bc0fbb1c2358edfdd7059621e6e1218a"  # Replace with your API key

        self.current_file_hash = None

        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar setup
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(10, 0, 10, 0)  # Add some margins to the toolbar for better aesthetics
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")
        self.layout.addWidget(self.toolbar)

        # Add the "View in Browser" button to the toolbar as an action on the left side
        self.view_in_browser_action = QAction("View in Browser", self)
        self.view_in_browser_action.triggered.connect(self.view_in_browser)
        self.toolbar.addAction(self.view_in_browser_action)

        # Add a spacer to push the logo action to the right side of the toolbar
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        spacer_action = QWidgetAction(self)
        spacer_action.setDefaultWidget(spacer)
        self.toolbar.addAction(spacer_action)

        # Add VirusTotal Logo to the toolbar on the right side
        self.virus_total_logo = QSvgWidget("C:\\Users\\Radi\\Desktop\\VirusTotal_logo.svg")
        self.virus_total_logo.setFixedSize(141, 27)
        logo_action = QWidgetAction(self)
        logo_action.setDefaultWidget(self.virus_total_logo)
        self.toolbar.addAction(logo_action)

        self.info_text_edit = QTextBrowser(self)
        self.info_text_edit.setReadOnly(True)
        self.info_text_edit.setStyleSheet("border: 0px;")
        self.info_text_edit.anchorClicked.connect(self.view_in_browser)
        self.layout.addWidget(self.info_text_edit)

    def set_file_hash(self, file_hash):
        """Set the hash of the current file."""
        self.current_file_hash = file_hash
        self.update_virustotal_info()

    def update_virustotal_info(self):
        """Fetch and display the VirusTotal information for the current file hash."""
        if self.current_file_hash:
            data = self.vt_getresult(self.current_file_hash)
            if not data:  # Check if the data is empty. If empty, it means there was a rate limit error.
                return
            info_text = self.format_data_as_html(data)
            self.info_text_edit.setHtml(info_text)

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
            if self.requests_made_last_minute > 3:  # Adjusted based on your requirement
                # Inform the user about the rate limit with enhanced formatting
                self.info_text_edit.setHtml(
                    '<div style="text-align: center; padding: 20px;">'
                    '<p style="font-size: 20px; font-weight: bold;">Rate Limit Exceeded</p>'
                    '<p style="font-size: 16px;">Please wait a minute and try again.</p>'
                    '<p style="font-size: 16px;">Or <a href="#" style="color: blue; text-decoration: underline;" '
                    'onclick="viewInBrowser()">view in browser</a>.</p>'
                    '</div>'
                )
                return {}
        else:
            # If it's been more than a minute since the last request, reset the counter
            self.requests_made_last_minute = 1

        # Update the last request time and daily requests count
        self.last_request_time = current_time
        self.daily_requests_made += 1

        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip, My Python requests library example client or username"
        }
        params = {'apikey': self.api_key, 'resource': hashes}
        response = requests_post('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

        # Handle the case where the response is not a valid JSON (for example, if the rate limit is exceeded)
        try:
            return response.json()
        except RequestException:
            self.info_text_edit.setPlainText("Error decoding JSON from the response. Please try again.")
            return {}

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
