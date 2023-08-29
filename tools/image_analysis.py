import subprocess
import re


def get_partitions(image_path):
    """Return the partitions of the image."""
    result = subprocess.run(
        ["mmls", "-M", image_path],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    partitions = []
    for line in lines:
        parts = line.split()
        # Check if the line starts with a number (partition entry)
        if parts and re.match(r"^\d{3}:", parts[0]):
            partitions.append({
                "start": int(parts[2]),
                "description": " ".join(parts[5:])
            })
    return partitions


def list_files(image_path, offset):
    """List files in a directory using fls."""
    try:
        result = subprocess.run(
            ["fls", "-o", str(offset), "-r", "-p", image_path],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        return lines
    except subprocess.CalledProcessError as e:
        print(f"Error executing fls: {e}")
        return []

