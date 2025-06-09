import struct
import zlib
import io
from PIL import Image

class WEBPParser:
    def __init__(self, data):
        # Store the entire binary data and initialize offset.
        self.data = data
        self.offset = 0

        # Dictionary to hold parsed information.
        self.parsed_data = {
            "file_type": None,       # Usually "WEBP"
            "riff_size": None,       # Size field from RIFF header
            "chunks": [],            # List of chunk info
            "vp8x_header": None,     # Extended header info if present
            "vp8_header": None,      # Lossy (VP8) header info if present
            "vp8l_header": None,     # Lossless (VP8L) header info if present
            "alpha_chunk": None,     # ALPH chunk info if present
            "exif_data": None,       # EXIF metadata (raw bytes)
            "xmp_data": None,        # XMP metadata (raw bytes)
            "icc_data": None,        # ICC profile data (raw bytes)
            "anim_header": None,     # ANIM header info (for animated WebP)
            "frames": [],            # List of frames (if animated)
            "c2pa_data": None,       # C2PA metadata if present
            "width": None,           # Image width
            "height": None,          # Image height
            "has_alpha": False,      # True if alpha channel is present
            "has_animation": False,  # True if animation is present

            # Below are additional fields to hold raw (uncompressed) data
            "decoded_image": None,       # Single-frame image raw RGBA bytes
            "decoded_frames": [],        # List of frame raw data if it's animated
            "decoded_alpha_data": None,  # If ALPH chunk is separately decoded
        }

    def parse(self):
        """
        Parse the entire WebP file structure.
        Return a dictionary containing all parsed fields.
        """
        # 1) Parse the RIFF header and check file signature.
        self._parse_riff_header()

        # 2) Read chunks until end of data or until we've processed all known chunks.
        while self.offset < len(self.data):
            chunk_id, chunk_size, chunk_data = self._read_chunk_header()
            if not chunk_id:
                # No more valid chunks
                break

            # Store chunk info in the chunks list.
            self.parsed_data["chunks"].append({
                "id": chunk_id,
                "size": chunk_size,
                "offset": self.offset - 8,  # The offset at which chunk header started
            })

            # Dispatch parsing based on chunk id.
            if chunk_id == b"VP8X":
                self._parse_vp8x(chunk_data)
            elif chunk_id == b"VP8 ":
                self._parse_vp8(chunk_data)
            elif chunk_id == b"VP8L":
                self._parse_vp8l(chunk_data)
            elif chunk_id == b"ALPH":
                self._parse_alpha(chunk_data)
            elif chunk_id == b"EXIF":
                self._parse_exif(chunk_data)
            elif chunk_id == b"XMP ":
                self._parse_xmp(chunk_data)
            elif chunk_id == b"ICCP":
                self._parse_icc(chunk_data)
            elif chunk_id == b"ANIM":
                self._parse_anim(chunk_data)
            elif chunk_id == b"ANMF":
                self._parse_anmf(chunk_data)
            elif chunk_id == b"C2PA":
                self._parse_c2pa(chunk_data)
            else:
                # Unknown or unhandled chunk, just store the raw data if needed.
                pass

            # Advance offset (note: WebP/RIFF chunk sizes are aligned to 2 bytes).
            # If chunk_size is odd, we skip 1 pad byte.
            pad = chunk_size & 1
            self.offset += chunk_size + pad

        # After parsing, try to infer top-level width/height if not determined by VP8X.
        self._finalize_dimensions()

        # Attempt to decode the entire WebP data using Pillow (if possible).
        self._decode_entire_image()

        return self.parsed_data

    def _parse_riff_header(self):
        """
        Parse RIFF header:
        - 'RIFF' (4 bytes)
        - file_size (4 bytes, little-endian)
        - 'WEBP' (4 bytes)
        """
        if len(self.data) < 12:
            raise ValueError("Invalid WebP file: insufficient data for RIFF header")

        riff_tag = self.data[:4]
        riff_size = struct.unpack("<I", self.data[4:8])[0]
        webp_tag = self.data[8:12]

        if riff_tag != b"RIFF" or webp_tag != b"WEBP":
            raise ValueError("Not a valid WebP file: missing RIFF/WEBP signature")

        self.parsed_data["file_type"] = "WEBP"
        self.parsed_data["riff_size"] = riff_size

        # Move offset past the RIFF header
        self.offset = 12

    def _read_chunk_header(self):
        """
        Read chunk id (4 bytes) and chunk size (4 bytes, little-endian).
        Return (chunk_id, chunk_size, chunk_data).
        If there's not enough data, return (None, 0, None).
        """
        if self.offset + 8 > len(self.data):
            return None, 0, None

        chunk_id = self.data[self.offset : self.offset + 4]
        chunk_size = struct.unpack("<I", self.data[self.offset + 4 : self.offset + 8])[0]

        # Move offset to chunk data (immediately after header).
        self.offset += 8

        if self.offset + chunk_size > len(self.data):
            # Not enough data for this chunk, mark as invalid
            return chunk_id, chunk_size, None

        chunk_data = self.data[self.offset : self.offset + chunk_size]
        return chunk_id, chunk_size, chunk_data

    def _parse_vp8x(self, chunk_data):
        """
        Parse the VP8X chunk (10 bytes):
        -  1 byte: flags
        -  3 bytes: reserved
        -  3 bytes: canvas width - 1 (little-endian)
        -  3 bytes: canvas height - 1 (little-endian)
        """
        if len(chunk_data) < 10:
            return

        flags = chunk_data[0]
        # bits in flags: 
        #  0..1: reserved
        #  2 (bit 2): XMP
        #  3 (bit 3): EXIF
        #  4 (bit 4): Alpha
        #  5 (bit 5): ICC
        #  6 (bit 6): Animation
        #  7 (bit 7): Reserved
        has_icc = True if (flags & 0x20) else False
        has_alpha = True if (flags & 0x10) else False
        has_exif = True if (flags & 0x08) else False
        has_xmp = True if (flags & 0x04) else False
        has_animation = True if (flags & 0x02) else False

        raw_w_minus_1 = chunk_data[4:7]   # 3 bytes
        raw_h_minus_1 = chunk_data[7:10]  # 3 bytes

        w_minus_1 = raw_w_minus_1[0] | (raw_w_minus_1[1] << 8) | (raw_w_minus_1[2] << 16)
        h_minus_1 = raw_h_minus_1[0] | (raw_h_minus_1[1] << 8) | (raw_h_minus_1[2] << 16)

        width = w_minus_1 + 1
        height = h_minus_1 + 1

        self.parsed_data["vp8x_header"] = {
            "flags_byte": flags,
            "icc": has_icc,
            "alpha": has_alpha,
            "exif": has_exif,
            "xmp": has_xmp,
            "animation": has_animation,
            "width": width,
            "height": height,
        }

        # Update top-level info
        self.parsed_data["width"] = width
        self.parsed_data["height"] = height
        self.parsed_data["has_alpha"] = has_alpha
        self.parsed_data["has_animation"] = has_animation

    def _parse_vp8(self, chunk_data):
        """
        Parse VP8 (lossy) bitstream header partially to get width/height.
        A valid keyframe starts with:
          3 bytes: frame tag
          next 3 bytes: signature 0x9D 0x01 0x2A
          then 2 bytes for width (little-endian), 2 bytes for height (little-endian)
        We'll store basic info.
        """
        if len(chunk_data) < 10:
            self.parsed_data["vp8_header"] = {"error": "Insufficient data"}
            return

        signature = chunk_data[3:6]
        if signature == b"\x9D\x01\x2A":
            w_raw = chunk_data[6:8]  # little-endian
            h_raw = chunk_data[8:10] # little-endian
            width = struct.unpack("<H", w_raw)[0] & 0x3FFF  # 14 bits
            height = struct.unpack("<H", h_raw)[0] & 0x3FFF # 14 bits
            self.parsed_data["vp8_header"] = {
                "keyframe": True,
                "width": width,
                "height": height
            }

            if not self.parsed_data["width"]:
                self.parsed_data["width"] = width
            if not self.parsed_data["height"]:
                self.parsed_data["height"] = height
        else:
            self.parsed_data["vp8_header"] = {
                "keyframe": False,
                "note": "Non-keyframe or invalid signature"
            }

    def _parse_vp8l(self, chunk_data):
        """
        Parse VP8L (lossless) header:
        - First byte should be 0x2F if valid
        - Next 4 bytes contain size and alpha info in bit fields
        """
        if len(chunk_data) < 5:
            self.parsed_data["vp8l_header"] = {"error": "Insufficient data"}
            return

        signature = chunk_data[0]
        if signature != 0x2F:
            self.parsed_data["vp8l_header"] = {"error": "Invalid signature"}
            return

        bits_val = struct.unpack("<I", chunk_data[1:5])[0]
        w_minus_1 = bits_val & 0x3FFF
        h_minus_1 = (bits_val >> 14) & 0x3FFF
        alpha_bit = (bits_val >> 28) & 0x1
        version = (bits_val >> 29) & 0x7

        width = w_minus_1 + 1
        height = h_minus_1 + 1
        has_alpha = (alpha_bit == 1)

        self.parsed_data["vp8l_header"] = {
            "width_minus_1": w_minus_1,
            "height_minus_1": h_minus_1,
            "width": width,
            "height": height,
            "alpha_used": has_alpha,
            "version": version
        }

        if not self.parsed_data["width"]:
            self.parsed_data["width"] = width
        if not self.parsed_data["height"]:
            self.parsed_data["height"] = height
        if has_alpha:
            self.parsed_data["has_alpha"] = True

    def _parse_alpha(self, chunk_data):
        """
        Parse ALPH chunk:
        - 1 byte: compression method (0=uncompressed, 1=compressed)
        - the rest is alpha data
        """
        if len(chunk_data) < 1:
            self.parsed_data["alpha_chunk"] = {"error": "No data"}
            return

        comp_method = chunk_data[0]
        alpha_body = chunk_data[1:]

        self.parsed_data["alpha_chunk"] = {
            "compression": comp_method,
            "raw_data": alpha_body
        }
        self.parsed_data["has_alpha"] = True

        # If compression=1, it's VP8L-like compression for alpha.
        # We do NOT implement direct manual decode here, but we could if needed.

    def _parse_exif(self, chunk_data):
        """
        Store EXIF metadata as raw bytes.
        """
        self.parsed_data["exif_data"] = chunk_data

    def _parse_xmp(self, chunk_data):
        """
        Store XMP metadata as raw bytes.
        """
        self.parsed_data["xmp_data"] = chunk_data

    def _parse_icc(self, chunk_data):
        """
        Store ICC profile as raw bytes.
        """
        self.parsed_data["icc_data"] = chunk_data

    def _parse_anim(self, chunk_data):
        """
        Parse ANIM chunk:
        - 4 bytes: Background color (B,G,R,A)
        - 2 bytes: Loop count (little-endian)
        """
        if len(chunk_data) < 6:
            return

        bg_color = struct.unpack("<I", chunk_data[0:4])[0]  # B G R A order
        loop_count = struct.unpack("<H", chunk_data[4:6])[0]

        self.parsed_data["anim_header"] = {
            "bg_color": bg_color,
            "loop_count": loop_count
        }
        self.parsed_data["has_animation"] = True

    def _parse_anmf(self, chunk_data):
        """
        Parse ANMF chunk (animation frame):
        - 12 bits for x_offset
        - 12 bits for y_offset
        - 12 bits for width minus 1
        - 12 bits for height minus 1
        - Then duration (24 bits) + flags (8 bits)
        - The rest may contain sub-chunks (VP8/VP8L/ALPH)
        """
        if len(chunk_data) < 16:
            frame_info = {"error": "ANMF chunk too short"}
            self.parsed_data["frames"].append(frame_info)
            return

        x_bits = struct.unpack("<H", chunk_data[0:2])[0] & 0xFFF
        y_bits = struct.unpack("<H", chunk_data[2:4])[0] & 0xFFF
        w_bits = struct.unpack("<H", chunk_data[4:6])[0] & 0xFFF
        h_bits = struct.unpack("<H", chunk_data[6:8])[0] & 0xFFF

        duration = struct.unpack("<I", chunk_data[8:12])[0] & 0xFFFFFF
        flags = chunk_data[11]
        blend = (flags & 2) != 0
        dispose = (flags & 1) != 0

        frame_data = {
            "x_offset": x_bits,
            "y_offset": y_bits,
            "width": w_bits + 1,
            "height": h_bits + 1,
            "duration_ms": duration,
            "dispose": dispose,
            "blend": blend,
            "sub_chunk_data": chunk_data[12:]
        }

        self.parsed_data["frames"].append(frame_data)
        self.parsed_data["has_animation"] = True

    def _parse_c2pa(self, chunk_data):
        """
        Store C2PA (Content Credentials or similar) as raw bytes.
        """
        self.parsed_data["c2pa_data"] = chunk_data

    def _finalize_dimensions(self):
        """
        If there's no VP8X chunk, we might rely on VP8/VP8L headers 
        to determine final width/height. If dimensions are already set, do nothing.
        """
        if not self.parsed_data["width"]:
            if (self.parsed_data["vp8_header"] and
                "width" in self.parsed_data["vp8_header"]):
                self.parsed_data["width"] = self.parsed_data["vp8_header"]["width"]
            elif (self.parsed_data["vp8l_header"] and
                  "width" in self.parsed_data["vp8l_header"]):
                self.parsed_data["width"] = self.parsed_data["vp8l_header"]["width"]

        if not self.parsed_data["height"]:
            if (self.parsed_data["vp8_header"] and
                "height" in self.parsed_data["vp8_header"]):
                self.parsed_data["height"] = self.parsed_data["vp8_header"]["height"]
            elif (self.parsed_data["vp8l_header"] and
                  "height" in self.parsed_data["vp8l_header"]):
                self.parsed_data["height"] = self.parsed_data["vp8l_header"]["height"]

    def _decode_entire_image(self):
        """
        Attempt to decode the entire WebP image (including all frames if animated)
        using the Pillow library. Store the raw (uncompressed) pixel data in memory.
        """
        try:
            # Wrap the binary data with BytesIO so Pillow can open it.
            img_file = io.BytesIO(self.data)
            with Image.open(img_file) as im:
                # If it's an animated WebP, we can iterate frames.
                # If not animated, there's only one frame.
                if getattr(im, "n_frames", 1) > 1:
                    # Animated WebP
                    self.parsed_data["decoded_frames"] = []
                    for frame_idx in range(im.n_frames):
                        im.seek(frame_idx)
                        frame_rgba = im.convert("RGBA")
                        raw_bytes = frame_rgba.tobytes()  # raw RGBA data
                        frame_info = {
                            "frame_index": frame_idx,
                            "width": frame_rgba.width,
                            "height": frame_rgba.height,
                            "raw_rgba_data": raw_bytes
                        }
                        self.parsed_data["decoded_frames"].append(frame_info)
                else:
                    # Single-frame WebP
                    rgba_img = im.convert("RGBA")
                    self.parsed_data["decoded_image"] = rgba_img.tobytes()
        except Exception as e:
            # If decoding fails, we simply won't have decoded_image data.
            self.parsed_data["decode_error"] = str(e)
