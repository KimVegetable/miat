import struct
import zlib

class PNGParser:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.parsed_data = {
            'signature': None,      # PNG signature (8 bytes)
            'header': None,         # IHDR chunk info
            'palette': [],          # PLTE chunk
            'idat_chunks': [],      # Raw IDAT chunks (compressed image data)
            'pixels': [],           # Decompressed and filter-removed pixel data
            'gamma': None,          # gAMA chunk info
            'physical': None,       # pHYs chunk info
            'text': [],             # tEXt, zTXt, iTXt chunks
            'unknown_chunks': [],   # Unknown or unsupported chunks
            'end': False            # True when IEND chunk is encountered
        }

    def parse(self):
        """
        Parse the entire PNG file data. This method orchestrates:
        1) Checking the PNG signature.
        2) Iterating through all chunks (IHDR, PLTE, IDAT, IEND, etc.).
        3) Decompressing and unfiltering IDAT data to build final pixel data.
        4) Storing all parsed information in a dictionary.
        """
        # 1) Parse the PNG signature
        self._parse_signature()

        # 2) Read chunks until IEND or end of data
        while not self.parsed_data['end'] and self.offset < len(self.data):
            chunk_length, chunk_type, chunk_data, chunk_crc = self._read_chunk()

            if chunk_type == b'IHDR':
                self._parse_ihdr(chunk_data)
            elif chunk_type == b'PLTE':
                self._parse_plte(chunk_data)
            elif chunk_type == b'IDAT':
                self._parse_idat(chunk_data)
            elif chunk_type == b'IEND':
                self.parsed_data['end'] = True
            elif chunk_type == b'tEXt':
                self._parse_text(chunk_data)
            elif chunk_type == b'zTXt':
                self._parse_ztxt(chunk_data)
            elif chunk_type == b'iTXt':
                self._parse_itxt(chunk_data)
            elif chunk_type == b'pHYs':
                self._parse_phys(chunk_data)
            elif chunk_type == b'gAMA':
                self._parse_gama(chunk_data)
            else:
                self._parse_unknown(chunk_type, chunk_data, chunk_crc)

        # 3) Decompress and remove filters from IDAT data if present
        if self.parsed_data['idat_chunks'] and self.parsed_data['header']:
            self._unfilter_idat()

        return self.parsed_data

    def _parse_signature(self):
        """
        Parse the 8-byte PNG signature and store it.
        Ideally, check if it matches b'\\x89PNG\\r\\n\\x1a\\n'.
        """
        signature = self.data[:8]
        self.parsed_data['signature'] = signature
        self.offset += 8

    def _read_chunk(self):
        """
        Read a single chunk from the current offset:
        1) 4 bytes chunk length (big-endian)
        2) 4 bytes chunk type
        3) 'chunk_length' bytes of chunk data
        4) 4 bytes CRC (big-endian)
        """
        chunk_length = struct.unpack(">I", self.data[self.offset:self.offset+4])[0]
        self.offset += 4

        chunk_type = self.data[self.offset:self.offset+4]
        self.offset += 4

        chunk_data = self.data[self.offset:self.offset+chunk_length]
        self.offset += chunk_length

        chunk_crc = struct.unpack(">I", self.data[self.offset:self.offset+4])[0]
        self.offset += 4

        return chunk_length, chunk_type, chunk_data, chunk_crc

    def _parse_ihdr(self, chunk_data):
        """
        Parse the IHDR chunk (13 bytes):
        - width (4 bytes)
        - height (4 bytes)
        - bit_depth (1 byte)
        - color_type (1 byte)
        - compression (1 byte)
        - filter_method (1 byte)
        - interlace (1 byte)
        """
        width, height, bit_depth, color_type, comp, f_method, interlace = struct.unpack(">IIBBBBB", chunk_data)
        self.parsed_data['header'] = {
            'width': width,
            'height': height,
            'bit_depth': bit_depth,
            'color_type': color_type,
            'compression': comp,
            'filter_method': f_method,
            'interlace': interlace
        }

    def _parse_plte(self, chunk_data):
        """
        Parse the PLTE chunk. It contains a series of 3-byte RGB entries.
        """
        palette = []
        for i in range(0, len(chunk_data), 3):
            r = chunk_data[i]
            g = chunk_data[i+1]
            b = chunk_data[i+2]
            palette.append((r, g, b))
        self.parsed_data['palette'] = palette

    def _parse_idat(self, chunk_data):
        """
        Collect IDAT chunks (compressed image data).
        We will decompress and unfilter after reading all IDAT chunks.
        """
        self.parsed_data['idat_chunks'].append(chunk_data)

    def _parse_text(self, chunk_data):
        """
        Parse the tEXt chunk: <keyword> + null + <text>.
        Both are typically in ISO-8859-1 encoding.
        """
        try:
            sep_idx = chunk_data.index(b'\x00')
            keyword = chunk_data[:sep_idx].decode('latin-1')
            text = chunk_data[sep_idx+1:].decode('latin-1')
            self.parsed_data['text'].append({
                'type': 'tEXt',
                'keyword': keyword,
                'text': text
            })
        except ValueError:
            pass

    def _parse_ztxt(self, chunk_data):
        """
        Parse the zTXt chunk: <keyword> + null + compression method + compressed text.
        The compression method 0 indicates deflate (zlib).
        """
        try:
            sep_idx = chunk_data.index(b'\x00')
            keyword = chunk_data[:sep_idx].decode('latin-1')
            comp_method = chunk_data[sep_idx+1]
            compressed_text = chunk_data[sep_idx+2:]

            if comp_method == 0:
                try:
                    text = zlib.decompress(compressed_text).decode('latin-1')
                except zlib.error:
                    text = ''
            else:
                text = ''
            self.parsed_data['text'].append({
                'type': 'zTXt',
                'keyword': keyword,
                'text': text
            })
        except ValueError:
            pass

    def _parse_itxt(self, chunk_data):
        """
        Parse the iTXt chunk:
        Format:
          1) keyword (null-terminated)
          2) compression_flag (1 byte)
          3) compression_method (1 byte)
          4) language_tag (null-terminated)
          5) translated_keyword (null-terminated)
          6) text (possibly compressed, depending on compression_flag)
        """
        offset = 0
        null_pos = chunk_data.find(b'\x00', offset)
        if null_pos < 0:
            return
        keyword = chunk_data[offset:null_pos].decode('utf-8', 'replace')
        offset = null_pos + 1

        if offset >= len(chunk_data):
            return
        comp_flag = chunk_data[offset]
        offset += 1

        if offset >= len(chunk_data):
            return
        comp_method = chunk_data[offset]
        offset += 1

        null_pos = chunk_data.find(b'\x00', offset)
        if null_pos < 0:
            return
        language_tag = chunk_data[offset:null_pos].decode('utf-8', 'replace')
        offset = null_pos + 1

        null_pos = chunk_data.find(b'\x00', offset)
        if null_pos < 0:
            return
        translated_keyword = chunk_data[offset:null_pos].decode('utf-8', 'replace')
        offset = null_pos + 1

        text_data = chunk_data[offset:]
        if comp_flag == 1 and comp_method == 0:
            # Deflate compression
            try:
                text_uncompressed = zlib.decompress(text_data).decode('utf-8', 'replace')
            except zlib.error:
                text_uncompressed = ''
        else:
            text_uncompressed = text_data.decode('utf-8', 'replace')

        self.parsed_data['text'].append({
            'type': 'iTXt',
            'keyword': keyword,
            'language': language_tag,
            'translated': translated_keyword,
            'text': text_uncompressed
        })

    def _parse_phys(self, chunk_data):
        """
        Parse the pHYs chunk (9 bytes total):
          - 4 bytes: pixels per unit (X axis)
          - 4 bytes: pixels per unit (Y axis)
          - 1 byte: unit specifier (0: unspecified, 1: meter)
        """
        if len(chunk_data) == 9:
            x_ppu, y_ppu, unit_spec = struct.unpack(">IIB", chunk_data)
            self.parsed_data['physical'] = {
                'x_ppu': x_ppu,
                'y_ppu': y_ppu,
                'unit': unit_spec
            }

    def _parse_gama(self, chunk_data):
        """
        Parse the gAMA chunk (4 bytes).
        The stored integer is gamma * 100000.
        So actual gamma = stored_value / 100000.
        """
        if len(chunk_data) == 4:
            (g_val,) = struct.unpack(">I", chunk_data)
            self.parsed_data['gamma'] = g_val / 100000.0

    def _parse_unknown(self, chunk_type, chunk_data, chunk_crc):
        """
        For unknown or unsupported chunks, store their binary data for later usage.
        """
        self.parsed_data['unknown_chunks'].append({
            'type': chunk_type.decode('ascii', 'replace'),
            'length': len(chunk_data),
            'data': chunk_data,
            'crc': chunk_crc
        })

    def _unfilter_idat(self):
        """
        Combine all IDAT chunks, decompress them using zlib, and then remove
        PNG filters for each scanline to reconstruct the original pixel data.
        """
        all_idat_data = b''.join(self.parsed_data['idat_chunks'])
        try:
            decompressed = zlib.decompress(all_idat_data)
        except zlib.error:
            decompressed = b''

        hdr = self.parsed_data['header']
        width = hdr['width']
        height = hdr['height']
        bit_depth = hdr['bit_depth']
        color_type = hdr['color_type']

        # This code handles only bit_depth = 8 for simplicity
        if bit_depth != 8:
            return

        # Determine bytes per pixel (bpp) based on color_type
        if color_type == 0:
            bpp = 1  # Grayscale
        elif color_type == 2:
            bpp = 3  # RGB
        elif color_type == 3:
            bpp = 1  # Indexed color
        elif color_type == 4:
            bpp = 2  # Grayscale + Alpha
        elif color_type == 6:
            bpp = 4  # RGBA
        else:
            bpp = 1  # Default fallback

        scanline_len = width * bpp
        offset = 0
        rows = []

        # Initialize a prior row filled with zeros
        prior_row = bytearray(scanline_len)

        for _ in range(height):
            # Each row starts with a filter byte
            if offset >= len(decompressed):
                break
            filter_type = decompressed[offset]
            offset += 1

            # Then we read 'scanline_len' bytes of data
            end_line = offset + scanline_len
            if end_line > len(decompressed):
                break
            raw_scanline = bytearray(decompressed[offset:end_line])
            offset += scanline_len

            # Apply the corresponding filter
            if filter_type == 0:
                recon = self._filter_none(raw_scanline)
            elif filter_type == 1:
                recon = self._filter_sub(raw_scanline, bpp)
            elif filter_type == 2:
                recon = self._filter_up(raw_scanline, prior_row)
            elif filter_type == 3:
                recon = self._filter_average(raw_scanline, prior_row, bpp)
            elif filter_type == 4:
                recon = self._filter_paeth(raw_scanline, prior_row, bpp)
            else:
                recon = raw_scanline  # Unknown filter -> no correction

            rows.append(recon)
            prior_row = recon

        # Build a 2D list of pixel tuples
        self._build_pixel_array(rows, bpp)

    def _build_pixel_array(self, rows, bpp):
        """
        Convert each unfiltered row into a list of pixel tuples,
        such as (R, G, B, A) or (R, G, B), etc.
        """
        hdr = self.parsed_data['header']
        width = hdr['width']
        height = hdr['height']

        pixel_matrix = []
        for row_data in rows:
            row_pixels = []
            for x in range(width):
                start = x * bpp
                px_data = row_data[start:start+bpp]
                if bpp == 1:
                    # Grayscale or Indexed
                    row_pixels.append((px_data[0],))
                elif bpp == 2:
                    # Grayscale + Alpha
                    row_pixels.append((px_data[0], px_data[1]))
                elif bpp == 3:
                    # RGB
                    row_pixels.append((px_data[0], px_data[1], px_data[2]))
                elif bpp == 4:
                    # RGBA
                    row_pixels.append((px_data[0], px_data[1], px_data[2], px_data[3]))
            pixel_matrix.append(row_pixels)

        self.parsed_data['pixels'] = pixel_matrix

    def _filter_none(self, scanline):
        """
        Filter type 0: No filter applied, so raw bytes are already correct.
        """
        return scanline

    def _filter_sub(self, scanline, bpp):
        """
        Filter type 1 (Sub): For each byte, add the byte from the previous pixel (same row).
        """
        recon = bytearray(len(scanline))
        for i in range(len(scanline)):
            left = recon[i - bpp] if i - bpp >= 0 else 0
            recon[i] = (scanline[i] + left) & 0xFF
        return recon

    def _filter_up(self, scanline, prior_row):
        """
        Filter type 2 (Up): For each byte, add the byte from the previous row (same column).
        """
        recon = bytearray(len(scanline))
        for i in range(len(scanline)):
            up = prior_row[i] if i < len(prior_row) else 0
            recon[i] = (scanline[i] + up) & 0xFF
        return recon

    def _filter_average(self, scanline, prior_row, bpp):
        """
        Filter type 3 (Average): For each byte, add the average of left byte and upper byte.
        """
        recon = bytearray(len(scanline))
        for i in range(len(scanline)):
            left = recon[i - bpp] if i - bpp >= 0 else 0
            up = prior_row[i] if i < len(prior_row) else 0
            avg = (left + up) >> 1
            recon[i] = (scanline[i] + avg) & 0xFF
        return recon

    def _filter_paeth(self, scanline, prior_row, bpp):
        """
        Filter type 4 (Paeth): Use the Paeth predictor to choose among left, up, and upper-left.
        """
        recon = bytearray(len(scanline))
        for i in range(len(scanline)):
            left = recon[i - bpp] if i - bpp >= 0 else 0
            up = prior_row[i] if i < len(prior_row) else 0
            up_left = prior_row[i - bpp] if i - bpp >= 0 else 0
            p = left + up - up_left

            pa = abs(p - left)
            pb = abs(p - up)
            pc = abs(p - up_left)

            if pa <= pb and pa <= pc:
                base = left
            elif pb <= pc:
                base = up
            else:
                base = up_left

            recon[i] = (scanline[i] + base) & 0xFF
        return recon
