import sqlite3

def create_icon_db():
    conn = sqlite3.connect('../icon_mappings_new.db')
    c = conn.cursor()

    # Create table with UNIQUE constraint
    c.execute('''CREATE TABLE IF NOT EXISTS icons (
                 type TEXT, 
                 name TEXT, 
                 path TEXT, 
                 UNIQUE(type, name, path))''')

    # Insert file icon data
    file_icon_data = [
        ('file', 'java', 'gui/new_icons/java.png'),
        ('file', 'cdr', 'gui/new_icons/cdr.png'),
        ('file', 'docx', 'gui/new_icons/docx.png'),
        ('file', 'autocad', 'gui/new_icons/autocad.png'),
        ('file', 'gif', 'gui/new_icons/gif.png'),
        ('file', 'eps', 'gui/new_icons/eps.png'),
        ('file', 'html', 'gui/new_icons/html.png'),
        ('file', 'hlp', 'gui/new_icons/hlp.png'),
        ('file', 'database', 'gui/new_icons/database.png'),
        ('file', 'css', 'gui/new_icons/css.png'),
        ('file', 'documents', 'gui/new_icons/documents.png'),
        ('file', 'auto', 'gui/new_icons/auto.png'),
        ('file', 'bin', 'gui/new_icons/bin.png'),
        ('file', 'csv', 'gui/new_icons/csv.png'),
        ('file', 'bmp', 'gui/new_icons/bmp.png'),
        ('file', 'jpg', 'gui/new_icons/jpg.png'),
        ('file', 'iso', 'gui/new_icons/iso.png'),
        ('file', 'aac', 'gui/new_icons/aac.png'),
        ('file', 'illustrator', 'gui/new_icons/illustrator.png'),
        ('file', 'exe', 'gui/new_icons/exe.png'),
        ('file', 'file', 'gui/new_icons/file.png'),
        ('file', 'flv', 'gui/new_icons/flv.png'),
        ('file', 'avi', 'gui/new_icons/avi.png'),
        ('file', 'mov', 'gui/new_icons/mov.png'),
        ('file', 'mkv', 'gui/new_icons/mkv.png'),
        ('file', 'mp3', 'gui/new_icons/mp3.png'),
        ('file', 'mp4', 'gui/new_icons/mp4.png'),
        ('file', 'mpeg', 'gui/new_icons/mpeg.png'),
        ('file', 'mpg', 'gui/new_icons/mpg.png'),
        ('file', 'pdf', 'gui/new_icons/pdf.png'),
        ('file', 'png', 'gui/new_icons/png.png'),
        ('file', 'php', 'gui/new_icons/php.png'),
        ('file', 'ppt', 'gui/new_icons/ppt.png'),
        ('file', 'psd', 'gui/new_icons/psd.png'),
        ('file', 'rar', 'gui/new_icons/rar.png'),
        ('file', 'rss', 'gui/new_icons/rss.png'),
        ('file', 'rtf', 'gui/new_icons/rtf.png'),
        ('file', 'sql', 'gui/new_icons/sql.png'),
        ('file', 'svg', 'gui/new_icons/svg.png'),
        ('file', 'swf', 'gui/new_icons/swf.png'),
        ('file', 'sys', 'gui/new_icons/sys.png'),
        ('file', 'txt', 'gui/new_icons/txt.png'),
        ('file', 'wma', 'gui/new_icons/wma.png'),
        ('file', 'xls', 'gui/new_icons/xls.png'),
        ('file', 'xlsx', 'gui/new_icons/xlsx.png'),
        ('file', 'xml', 'gui/new_icons/xml.png'),
        ('file', 'zip', 'gui/new_icons/zip.png'),
        ('file', 'db', 'gui/new_icons/database.png'),
    ]

    # Insert folder icon data
    folder_icon_data = [
        ('folder', 'Default_Folder', 'gui/new_icons/folder.png'),
        ('folder', 'Desktop', 'gui/icons/folder_types/user-desktop.png'),
        ('folder', 'Documents', 'gui/icons/folder_types/folder-documents.png'),
        ('folder', 'Downloads', 'gui/icons/folder_types/folder-download.png'),
        ('folder', 'Music', 'gui/icons/folder_types/folder-music.png'),
        ('folder', 'Pictures', 'gui/icons/folder_types/folder-pictures.png'),
        ('folder', 'Videos', 'gui/icons/folder_types/folder-videos.png'),
        ('folder', 'Templates', 'gui/icons/folder_types/folder-templates.png'),
        ('folder', 'Public', 'gui/icons/folder_types/folder-public-share.png'),
        ('folder', 'Searches', 'gui/icons/folder_types/folder-saved-search.png')
    ]

    # Insert partition and image icon data
    special_icon_data = [
        ('special', 'Partition', 'gui/new_icons/disk.png'),
        ('special', 'Image', 'gui/new_icons/diskette.png')
    ]

    c.executemany('INSERT INTO icons VALUES (?, ?, ?)', file_icon_data)
    c.executemany('INSERT INTO icons VALUES (?, ?, ?)', folder_icon_data)
    c.executemany('INSERT OR IGNORE INTO icons VALUES (?, ?, ?)', special_icon_data)

    # Commit and close
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_icon_db()
