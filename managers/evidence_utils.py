import hashlib
import os
import datetime
import mimetypes

import pyewf
import pytsk3


class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


class ImageHandler:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img_info = None
        self.volume_info = None  # Initialized once
        self.fs_info_cache = {}  # Cache for FS_Info objects, keyed by start offset
        self.load_image()

    def get_image_type(self):
        """Determine the type of the image based on its extension."""
        _, ext = os.path.splitext(self.image_path)
        ext = ext.lower()

        ewf = [".e01", ".s01", ".l01"]
        raw = [".raw", ".img", ".dd"]

        if ext in ewf:
            return "ewf"
        elif ext in raw:
            return "raw"
        else:
            raise ValueError(f"Unsupported image type: {ext}")

    def load_image(self):
        image_type = self.get_image_type()

        if image_type == "ewf":
            filenames = pyewf.glob(self.image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)
            self.img_info = EWFImgInfo(ewf_handle)
        elif image_type == "raw":
            self.img_info = pytsk3.Img_Info(self.image_path)
        else:
            raise ValueError(f"Unsupported image type: {image_type}")

        try:
            self.volume_info = pytsk3.Volume_Info(self.img_info)
        except Exception as e:

            self.volume_info = None

    def get_partitions(self):
        """Retrieve partitions from the loaded image."""
        partitions = []
        if self.volume_info:
            for part in self.volume_info:
                if not part.desc:
                    continue
                partitions.append((part.addr, part.desc, part.start, part.len))
        return partitions

    def has_partitions(self):
        """Check if the image has partitions."""
        return bool(self.get_partitions())

    def get_fs_info(self, start_offset):
        """Retrieve the FS_Info for a partition, initializing it if necessary."""
        if start_offset not in self.fs_info_cache:
            try:
                fs_info = pytsk3.FS_Info(self.img_info, offset=start_offset * 512)
                self.fs_info_cache[start_offset] = fs_info
            except Exception as e:
                return None
        return self.fs_info_cache[start_offset]

    def check_partition_contents(self, partition_start_offset):
        """Check if a partition has any files or folders."""
        fs = self.get_fs_info(partition_start_offset)
        if fs:
            try:
                root_dir = fs.open_dir(path="/")
                for _ in root_dir:
                    return True
                return False
            except:
                return False
        return False

    def get_directory_contents(self, start_offset, inode_number=None):
        fs = self.get_fs_info(start_offset)
        if fs:
            try:
                directory = fs.open_dir(inode=inode_number) if inode_number else fs.open_dir(path="/")
                entries = []
                for entry in directory:
                    if entry.info.name.name not in [b".", b".."]:
                        is_directory = False
                        if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            is_directory = True

                        entries.append({
                            # check before append to list if entry has meta

                            "name": entry.info.name.name.decode('utf-8') if hasattr(entry.info.name, 'name') else None,
                            "is_directory": is_directory,
                            "inode_number": entry.info.meta.addr if entry.info.meta else None,
                            "size": entry.info.meta.size if entry.info.meta else None,



                            "modified": datetime.datetime.fromtimestamp(entry.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S') if hasattr(entry.info.meta,
                                                                'mtime') else None,
                            "accessed": datetime.datetime.fromtimestamp(entry.info.meta.atime).strftime('%Y-%m-%d %H:%M:%S' if hasattr(entry.info.meta,
                                                                'atime') else None),
                            "created": datetime.datetime.fromtimestamp(entry.info.meta.crtime).strftime('%Y-%m-%d %H:%M:%S') if hasattr(entry.info.meta,
                                                                'crtime') else None,
                            "changed": datetime.datetime.fromtimestamp(entry.info.meta.ctime).strftime('%Y-%m-%d %H:%M:%S') if hasattr(entry.info.meta,
                                                                'ctime') else None,
                            "flag(??)": entry.info.meta.flags if entry.info.meta else None,

                        })
                print(entries)
                return entries

            except:
                return []
        return []


    def get_hashes(self, tsk_file):
        # Create hash objects
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        # Define the offset
        offset = 0
        size = tsk_file.info.meta.size

        # Read and update hash string value in blocks of 64K
        while offset < size:
            byte_block = tsk_file.read_random(offset, 65536)
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)
            offset += len(byte_block)

        return md5_hash.hexdigest(), sha256_hash.hexdigest()
