import sqlite3

def create_icon_db():
    conn = sqlite3.connect('../icon_mappings.db')
    c = conn.cursor()

    # Create table with UNIQUE constraint
    c.execute('''CREATE TABLE IF NOT EXISTS icons (
                 type TEXT, 
                 name TEXT, 
                 path TEXT, 
                 UNIQUE(type, name, path))''')

    # Insert file icon data
    file_icon_data = [
        ('file', 'txt', 'gui/icons/text-x-generic.png'),
        ('file', 'pdf', 'gui/icons/application-pdf.png'),
        ('file', 'jpg', 'gui/icons/application-image-jpg.png'),
        ('file', 'png', 'gui/icons/application-image-png.png'),
        ('file', 'cd', 'application-x-cd-image.png'),
        ('file', 'iso', 'application-x-cd-image.png'),
        ('file', 'xml', 'gui/icons/application-xml.png'),
        ('file', 'zip', 'file-roller.png'),
        ('file', 'rar', 'file-roller.png'),
        ('file', 'gz', 'file-roller.png'),
        ('file', 'tar', 'file-roller.png'),
        ('file', 'mp4', 'gui/icons/video-x-generic.png'),
        ('file', 'mov', 'gui/icons/video-x-generic.png'),
        ('file', 'avi', 'gui/icons/video-x-generic.png'),
        ('file', 'wmv', 'gui/icons/video-x-generic.png'),
        ('file', 'mp3', 'gui/icons/audio-x-generic.png'),
        ('file', 'wav', 'gui/icons/audio-x-generic.png'),
        ('file', 'xls', 'gui/icons/libreoffice-oasis-spreadsheet.png'),
        ('file', 'xlsx', 'gui/icons/libreoffice-oasis-spreadsheet.png'),
        ('file', 'doc', 'gui/icons/libreoffice-oasis-text.png'),
        ('file', 'docx', 'gui/icons/libreoffice-oasis-text.png'),
        ('file', 'ppt', 'gui/icons/libreoffice-oasis-presentation.png'),
        ('file', 'pptx', 'gui/icons/libreoffice-oasis-presentation.png'),
        ('file', 'eml', 'gui/icons/emblem-mail.png'),
        ('file', 'msg', 'gui/icons/emblem-mail.png'),
        ('file', 'exe', 'gui/icons/application-x-executable.png'),
        ('file', 'html', 'gui/icons/text-html.png'),
        ('file', 'htm', 'gui/icons/text-html.png')
    ]

    # Insert folder icon data
    folder_icon_data = [
        ('folder', 'Default_Folder', 'gui/icons/folder_types/folder.png'),
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
        ('special', 'Partition', 'gui/icons/volume.png'),
        ('special', 'Image', 'gui/icons/media-optical.png')
    ]

    c.executemany('INSERT INTO icons VALUES (?, ?, ?)', file_icon_data)
    c.executemany('INSERT INTO icons VALUES (?, ?, ?)', folder_icon_data)
    c.executemany('INSERT OR IGNORE INTO icons VALUES (?, ?, ?)', special_icon_data)

    # Commit and close
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_icon_db()
