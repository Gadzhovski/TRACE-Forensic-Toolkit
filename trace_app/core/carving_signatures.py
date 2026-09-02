"""Signature validation and timestamp extraction for carved data.

Pure functions over a bytes buffer -- no widget, no disk access, no state.
They live in core so this logic can be exercised without starting a GUI.
"""

import datetime
import io
import logging
import struct
import zipfile

from fitz import open as fitz_open
from PIL import Image, UnidentifiedImageError

logger = logging.getLogger('TRACE.Carving')


def is_valid_file(data, file_type):
    try:
        if file_type == 'pdf':
            # Validate by parsing with PyMuPDF; a carved fragment that is
            # not a real PDF raises here.
            with fitz_open(stream=data, filetype='pdf') as doc:
                if doc.page_count < 1:
                    return False
        elif file_type in ['jpg', 'jpeg', 'png', 'gif']:
            # Validate images by attempting to open them with PIL
            image = Image.open(io.BytesIO(data))
            image.verify()  # This will not load the image but only parse it
        elif file_type == 'bmp':
            return True
        elif file_type == 'wav':
            # Basic WAV validation could check for the RIFF header, file size, etc.
            if not data.startswith(b'RIFF') or not b'WAVE' in data[:12]:
                return False
            # Additional WAV format checks could be implemented here
        elif file_type == 'mov':
            return True  # For now, we'll assume all MOV files are valid
        else:
            return True
        return True
    except (IOError, UnidentifiedImageError, ValueError, RuntimeError) as e:
        logger.error(f"Error validating file of type {file_type}: {str(e)}")
        return False


def extract_original_timestamp(file_content, file_type):
    """Extract original file timestamp from file headers/metadata.

    Returns:
        datetime object if timestamp found, None otherwise
    """
    try:
        if file_type.lower() in ['jpg', 'jpeg', 'png']:
            # Extract EXIF DateTimeOriginal from images
            try:
                img = Image.open(io.BytesIO(file_content))
                exif_data = img._getexif()
                if exif_data:
                    # Look for DateTimeOriginal (tag 36867) or DateTime (tag 306)
                    for tag_id, value in exif_data.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        if tag_name in ['DateTimeOriginal', 'DateTime']:
                            # Parse format: "2024:01:15 14:30:00"
                            return datetime.datetime.strptime(str(value), '%Y:%m:%d %H:%M:%S')
            except Exception:
                pass

        elif file_type.lower() == 'pdf':
            # Extract CreationDate from PDF metadata
            try:
                with fitz_open(stream=file_content, filetype='pdf') as doc:
                    date_str = (doc.metadata or {}).get('creationDate', '')
                # PDF date format: "D:20240115143000"
                if date_str and date_str.startswith('D:'):
                    date_str = date_str[2:16]  # Extract YYYYMMDDHHmmss
                    return datetime.datetime.strptime(date_str, '%Y%m%d%H%M%S')
            except Exception:
                pass

        elif file_type.lower() == 'zip':
            # Extract timestamp from ZIP central directory
            try:
                with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                    if zf.namelist():
                        # Get timestamp of first file in archive
                        first_file_info = zf.getinfo(zf.namelist()[0])
                        return datetime.datetime(*first_file_info.date_time)
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Error extracting timestamp for {file_type}: {e}")

    return None
