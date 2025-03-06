import os

from parsers.containers.mp4_parser import MP4Parser
from parsers.images.gif_parser import GIFParser
from parsers.images.jpeg_parser import JPEGParser
from parsers.images.png_parser import PNGParser
from parsers.images.dng_parser import DNGParser
from parsers.images.tiff_parser import TIFFParser


class ImageFile:
    def __init__(self, file_path):
        self.file_path = file_path
        self.image_parser = None
        self.image_data = None
        self.data = {}

    def parse(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()

            extension = os.path.splitext(self.file_path)[1].lower()
            if extension in ['.jpg', '.jpeg']:
                self.image_parser = JPEGParser(data)
            elif extension in ['.png']:
                self.image_parser = PNGParser(data)
            elif extension in ['.gif']:
                self.image_parser = GIFParser(data)
            elif extension in ['.dng']:
                self.image_parser = DNGParser(data)
            elif extension in ['.tiff']:
                self.image_parser = TIFFParser(data)
            else:
                raise ValueError("Unsupported file format")

        self.image_data = self.image_parser.parse()

        self.data = {
            'file_path': self.file_path,
            'image_data': self.image_data
        }