""" Old database manager using when used The Sleuth Kit binaries"""


from sqlite3 import connect as sqlite3_connect


class DatabaseManager:
    def __init__(self, db_path):
        self.db_conn = sqlite3_connect(db_path)

    def __del__(self):
        self.db_conn.close()

    def get_icon_path(self, icon_type, extension):
        c = self.db_conn.cursor()
        try:
            c.execute("SELECT path FROM icons WHERE type = ? AND extention = ?", (icon_type, extension))
            result = c.fetchone()

            if result:
                return result[0]
            else:
                # Fallback to default icons
                if icon_type == 'folder':
                    c.execute("SELECT path FROM icons WHERE type = ? AND extention = ?", (icon_type, 'folder'))
                    result = c.fetchone()
                    return result[0] if result else 'gui/Eleven/24/mimetypes/application-x-zerosize.svg'
                else:
                    return 'gui/Eleven/24/mimetypes/application-x-zerosize.svg'
        finally:
            c.close()
