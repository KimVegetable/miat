import os

supported_extensions = {".mp4", ".mkv", ".avi", ".mov", ".mp3", ".wav", ".flac", ".aac", ".jpg", ".png", ".gif", ".docx", ".xlsx", ".pptx", ".pdf"}

def get_file_signature(file_path, num_bytes=8):
    with open(file_path, "rb") as f:
        return f.read(num_bytes)

def get_file_size(file_path):
    return os.path.getsize(file_path)

def file_exists(file_path):
    return os.path.isfile(file_path)

