import sqlite3


class DatabaseManager:
    def __init__(self, db_path):
        self.db_conn = sqlite3.connect(db_path)

    def __del__(self):
        self.db_conn.close()

    def get_icon_path(self, icon_type, name):
        c = self.db_conn.cursor()
        try:
            c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (icon_type, name))
            result = c.fetchone()

            if result:
                return result[0]
            else:
                # Fallback to default icons
                if icon_type == 'folder':
                    c.execute("SELECT path FROM icons WHERE type = ? AND name = ?", (icon_type, 'Default_Folder'))
                    result = c.fetchone()
                    return result[0] if result else 'gui/icons/unknown.png'
                else:
                    return 'gui/icons/unknown.png'
        finally:
            c.close()
