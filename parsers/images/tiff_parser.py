import struct
from bitstring import BitStream

class TIFFParser:
    def __init__(self, data):
        self.data = data
        self.bs = BitStream(data)

    def parse(self):
        pass