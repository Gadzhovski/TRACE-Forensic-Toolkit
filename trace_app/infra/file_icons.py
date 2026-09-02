"""File-type, folder and device icons.

Maps a file extension (or a folder/device name) to the icon shown for it in
the tree and listing views.

This used to live in a SQLite table queried once per rendered row. That table
had grown to 308 rows of which only 72 were reachable: 161 "app" icons, 16
"status", 12 "animation" and 21 entirely empty rows were never queried by any
code path, and only one of its 13 folder variants was ever asked for. A plain
dict is easier to read, extend and grep, needs no database connection or
cache, and cannot silently drift from the files on disk.

Paths are relative to the project root. Resolve them through
DatabaseManager.get_icon_path(), which caches the result.
"""


#: Shown when an extension is not listed below.
UNKNOWN = 'Icons/mimetypes/application-x-zerosize.svg'

#: Shown for a directory.
FOLDER = 'Icons/places/folder.svg'


#: Extension -> icon. Several extensions deliberately share one icon.
FILE_ICONS = {
    '7z': 'Icons/mimetypes/application-7zip.svg',
    'aac': 'Icons/mimetypes/audio-x-generic.svg',
    'm4a': 'Icons/mimetypes/audio-x-generic.svg',
    'mp3': 'Icons/mimetypes/audio-x-generic.svg',
    'ogg': 'Icons/mimetypes/audio-x-generic.svg',
    'wav': 'Icons/mimetypes/audio-x-generic.svg',
    'wma': 'Icons/mimetypes/audio-x-generic.svg',
    'arc': 'Icons/mimetypes/application-x-arc.svg',
    'arj': 'Icons/mimetypes/application-x-arj.svg',
    'avi': 'Icons/mimetypes/video-x-generic.svg',
    'flv': 'Icons/mimetypes/video-x-generic.svg',
    'mkv': 'Icons/mimetypes/video-x-generic.svg',
    'mov': 'Icons/mimetypes/video-x-generic.svg',
    'mp4': 'Icons/mimetypes/video-x-generic.svg',
    'wmw': 'Icons/mimetypes/video-x-generic.svg',
    'axx': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'cha': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'epm': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'key': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'bat': 'Icons/mimetypes/application-x-executable.svg',
    'bin': 'Icons/mimetypes/application-octet-stream.svg',
    'bmp': 'Icons/mimetypes/image-x-generic.svg',
    'gif': 'Icons/mimetypes/image-x-generic.svg',
    'jpeg': 'Icons/mimetypes/image-x-generic.svg',
    'jpg': 'Icons/mimetypes/image-x-generic.svg',
    'png': 'Icons/mimetypes/image-x-generic.svg',
    'psd': 'Icons/mimetypes/image-x-generic.svg',
    'svg': 'Icons/mimetypes/image-x-generic.svg',
    'tiff': 'Icons/mimetypes/image-x-generic.svg',
    'bzip': 'Icons/mimetypes/application-x-bzip.svg',
    'css': 'Icons/mimetypes/text-css.svg',
    'db': 'Icons/mimetypes/application-x-desktop.svg',
    'dll': 'Icons/mimetypes/application-x-sharedlib.svg',
    'doc': 'Icons/mimetypes/application-vnd.ms-word.svg',
    'docx': 'Icons/mimetypes/application-vnd.ms-word.template.macroenabled.12.svg',
    'eof': 'Icons/mimetypes/font-x-generic.svg',
    'otf': 'Icons/mimetypes/font-x-generic.svg',
    'ttf': 'Icons/mimetypes/font-x-generic.svg',
    'woff': 'Icons/mimetypes/font-x-generic.svg',
    'exe': 'Icons/mimetypes/application-x-ms-dos-executable.svg',
    'flac': 'Icons/mimetypes/audio-x-flac.svg',
    'gz': 'Icons/mimetypes/application-x-gzip.svg',
    'htm': 'Icons/mimetypes/text-x-html.svg',
    'html': 'Icons/mimetypes/text-x-html.svg',
    'iso': 'Icons/mimetypes/application-x-iso.svg',
    'jar': 'Icons/mimetypes/text-x-java.svg',
    'js': 'Icons/mimetypes/application-x-javascript.svg',
    'json': 'Icons/mimetypes/application-json.svg',
    'md': 'Icons/mimetypes/text-x-markdown.svg',
    'msi': 'Icons/mimetypes/application-x-msi.svg',
    'pdf': 'Icons/mimetypes/application-pdf.svg',
    'pl': 'Icons/mimetypes/application-x-perl.svg',
    'ppt': 'Icons/mimetypes/application-vnd.ms-powerpoint.svg',
    'pptm': 'Icons/mimetypes/application-vnd.ms-powerpoint.template.macroenabled.12.svg',
    'pptx': 'Icons/mimetypes/application-vnd.ms-powerpoint.template.macroenabled.12.svg',
    'py': 'Icons/mimetypes/text-x-python.svg',
    'rar': 'Icons/mimetypes/application-x-rar.svg',
    'rs': 'Icons/mimetypes/text-rust.svg',
    'rtf': 'Icons/mimetypes/text-richtext.svg',
    'sh': 'Icons/mimetypes/application-x-shellscript.svg',
    'tar': 'Icons/mimetypes/application-x-tar.svg',
    'trash': 'Icons/mimetypes/application-x-trash.svg',
    'txt': 'Icons/mimetypes/text-x-generic.svg',
    'xls': 'Icons/mimetypes/application-vnd.ms-excel.svg',
    'xlsx': 'Icons/mimetypes/application-vnd.ms-excel.template.macroenabled.12.svg',
    'xml': 'Icons/mimetypes/application-xml.svg',
    'xz': 'Icons/mimetypes/image-svg+xml-compressed.svg',
    'zip': 'Icons/mimetypes/application-zip.svg',
    'zoo': 'Icons/mimetypes/application-x-zoo.svg',
}


#: Extensions this tool meets that the original mapping table never covered:
#: disk images, Windows artefacts, mail stores and certificates all fell back
#: to the blank "unknown" icon.
FILE_ICONS.update({
    '001': 'Icons/devices/drive-multidisk.svg',
    'accdb': 'Icons/mimetypes/application-vnd.ms-access.svg',
    'ad1': 'Icons/devices/drive-harddisk.svg',
    'apk': 'Icons/mimetypes/package-x-generic.svg',
    'appimage': 'Icons/mimetypes/application-x-iso9660-appimage.svg',
    'asc': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'bak': 'Icons/mimetypes/application-x-archive.svg',
    'bz2': 'Icons/mimetypes/application-x-bzip.svg',
    'c': 'Icons/mimetypes/text-x-generic.svg',
    'cab': 'Icons/mimetypes/application-x-archive.svg',
    'cer': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'cfg': 'Icons/mimetypes/application-x-desktop.svg',
    'conf': 'Icons/mimetypes/application-x-desktop.svg',
    'cpp': 'Icons/mimetypes/text-x-generic.svg',
    'crdownload': 'Icons/mimetypes/application-x-partial-download.svg',
    'crt': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'csv': 'Icons/mimetypes/text-x-generic.svg',
    'dat': 'Icons/mimetypes/application-octet-stream.svg',
    'db3': 'Icons/mimetypes/application-x-desktop.svg',
    'dd': 'Icons/devices/drive-harddisk.svg',
    'deb': 'Icons/mimetypes/package-x-generic.svg',
    'dmg': 'Icons/devices/drive-optical.svg',
    'e01': 'Icons/devices/drive-harddisk.svg',
    'eml': 'Icons/mimetypes/text-x-generic.svg',
    'evt': 'Icons/mimetypes/text-x-generic.svg',
    'evtx': 'Icons/mimetypes/text-x-generic.svg',
    'ex01': 'Icons/devices/drive-harddisk.svg',
    'gpg': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'h': 'Icons/mimetypes/text-x-generic.svg',
    'heic': 'Icons/mimetypes/image-x-generic.svg',
    'ico': 'Icons/mimetypes/image-x-generic.svg',
    'img': 'Icons/devices/drive-harddisk.svg',
    'ini': 'Icons/mimetypes/application-x-desktop.svg',
    'java': 'Icons/mimetypes/text-x-java.svg',
    'l01': 'Icons/devices/drive-harddisk.svg',
    'lnk': 'Icons/mimetypes/inode-symlink.svg',
    'log': 'Icons/mimetypes/text-x-generic.svg',
    'm4v': 'Icons/mimetypes/video-x-generic.svg',
    'mdb': 'Icons/mimetypes/application-vnd.ms-access.svg',
    'msg': 'Icons/mimetypes/text-x-generic.svg',
    'odp': 'Icons/mimetypes/application-vnd.ms-powerpoint.svg',
    'ods': 'Icons/mimetypes/application-vnd.ms-excel.svg',
    'odt': 'Icons/mimetypes/application-vnd.ms-word.svg',
    'opus': 'Icons/mimetypes/audio-x-generic.svg',
    'ost': 'Icons/mimetypes/application-vnd.ms-access.svg',
    'p12': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'part': 'Icons/mimetypes/application-x-partial-download.svg',
    'pem': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'pf': 'Icons/mimetypes/application-octet-stream.svg',
    'pfx': 'Icons/mimetypes/application-pgp-encrypted.svg',
    'ps1': 'Icons/mimetypes/application-x-shellscript.svg',
    'pst': 'Icons/mimetypes/application-vnd.ms-access.svg',
    'raw': 'Icons/devices/drive-harddisk.svg',
    'reg': 'Icons/mimetypes/application-x-desktop.svg',
    'rpm': 'Icons/mimetypes/package-x-generic.svg',
    's01': 'Icons/devices/drive-harddisk.svg',
    'sqlite': 'Icons/mimetypes/application-x-desktop.svg',
    'sqlite3': 'Icons/mimetypes/application-x-desktop.svg',
    'sys': 'Icons/mimetypes/application-x-sharedlib.svg',
    'tgz': 'Icons/mimetypes/application-x-gzip.svg',
    'tmp': 'Icons/mimetypes/application-x-partial-download.svg',
    'toml': 'Icons/mimetypes/text-x-generic.svg',
    'torrent': 'Icons/mimetypes/application-x-partial-download.svg',
    'ts': 'Icons/mimetypes/application-x-javascript.svg',
    'tsv': 'Icons/mimetypes/text-x-generic.svg',
    'txz': 'Icons/mimetypes/application-x-xz-compressed-tar.svg',
    'vbs': 'Icons/mimetypes/application-x-shellscript.svg',
    'vdi': 'Icons/devices/drive-harddisk.svg',
    'vhd': 'Icons/devices/drive-harddisk.svg',
    'vhdx': 'Icons/devices/drive-harddisk.svg',
    'vmdk': 'Icons/devices/drive-harddisk.svg',
    'webm': 'Icons/mimetypes/video-x-generic.svg',
    'webp': 'Icons/mimetypes/image-x-generic.svg',
    'wmv': 'Icons/mimetypes/video-x-generic.svg',
    'yaml': 'Icons/mimetypes/text-x-generic.svg',
    'yml': 'Icons/mimetypes/text-x-generic.svg',
})

#: Named device icons, used for evidence images and volumes.
DEVICE_ICONS = {
    'camera-photo': 'Icons/devices/camera-photo.svg',
    'computer': 'Icons/devices/computer.svg',
    'computer-laptop': 'Icons/devices/computer-laptop.svg',
    'drive-harddisk': 'Icons/devices/drive-harddisk.svg',
    'drive-multidisk': 'Icons/devices/drive-multidisk.svg',
    'drive-optical': 'Icons/devices/drive-optical.svg',
    'drive-removable-media': 'Icons/devices/drive-removable-media.svg',
    'input-keyboard': 'Icons/devices/input-keyboard.svg',
    'input-mouse': 'Icons/devices/input-mouse.svg',
    'input-tablet': 'Icons/devices/input-tablet.svg',
    'media-memory': 'Icons/devices/media-memory.svg',
    'media-optical': 'Icons/devices/media-optical.svg',
    'phone': 'Icons/devices/phone.svg',
    'printer': 'Icons/devices/printer.svg',
    'scanner': 'Icons/devices/scanner.svg',
    'tablet': 'Icons/devices/tablet.svg',
}


#: Named folder icons. Only FOLDER is used today; the rest are kept so a
#: caller can pick a better-fitting icon for well-known directories.
FOLDER_ICONS = {
    'folder': 'Icons/places/folder.svg',
    'folder-documents': 'Icons/places/folder-documents.svg',
    'folder-download': 'Icons/places/folder-download.svg',
    'folder-music': 'Icons/places/folder-music.svg',
    'folder-network': 'Icons/places/folder-network.svg',
    'folder-onedrive': 'Icons/places/folder-onedrive.svg',
    'folder-pictures': 'Icons/places/folder-pictures.svg',
    'folder-temp': 'Icons/places/folder-temp.svg',
    'folder-template': 'Icons/places/folder-template.svg',
    'folder-text': 'Icons/places/folder-text.svg',
    'folder-videos': 'Icons/places/folder-videos.svg',
    'user-desktop': 'Icons/places/user-desktop.svg',
    'user-home': 'Icons/places/user-home.svg',
}
