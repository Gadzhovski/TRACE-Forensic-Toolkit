from PIL import Image
from PIL.ExifTags import TAGS
import io


class ExifViewerManager:
    def __init__(self):
        self.exif_data = None

    def load_exif_data(self, file_content):
        try:
            image = Image.open(io.BytesIO(file_content))

            # Check if the image format supports EXIF
            if image.format != "JPEG":
                return None

            exif_data = image._getexif()
            structured_data = []
            if exif_data is not None:
                for key in exif_data.keys():
                    if key in TAGS and isinstance(exif_data[key], (str, bytes)):
                        try:
                            tag_name = TAGS[key]
                            tag_value = exif_data[key]
                            structured_data.append((tag_name, tag_value))
                        except Exception as e:
                            print(f"Error processing key {key}: {e}")

                return structured_data
            else:
                return None
        except Exception as e:
            print(f"Error extracting EXIF data: {e}")
            return None
