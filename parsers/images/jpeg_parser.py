import struct

class JPEGParser:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.parsed_data = {
            'SOI': None,
            'APP0': [],
            'APP1': [],
            'DQT': [],
            'SOF': None,
            'DHT': [],
            'SOS': None,
            'EOI': None,
            'COM': [],
            'DRI': None,
            'APP2': [],
            'APP3': [],
            'APP4': [],
            'APP5': [],
            'APP6': [],
            'APP7': [],
            'APP8': [],
            'APP9': [],
            'APP10': [],
            'APP11': [],
            'APP12': [],
            'APP13': [],
            'APP14': [],
            'APP15': []
        }

    def parse(self):
        while self.offset < len(self.data):
            marker, = struct.unpack_from(">H", self.data, self.offset)
            self.offset += 2

            if marker == 0xFFD8:  # SOI
                self.parsed_data['SOI'] = marker
            elif 0xFFE0 <= marker <= 0xFFEF:  # APP0 - APP15
                self.parsed_data[f'APP{marker - 0xFFE0}'].append(self.parse_app(marker))
            elif marker == 0xFFDB:  # DQT
                self.parsed_data['DQT'].append(self.parse_dqt())
            elif marker in (0xFFC0, 0xFFC2):  # SOF
                self.parsed_data['SOF'] = self.parse_sof(marker)
            elif marker == 0xFFC4:  # DHT
                self.parsed_data['DHT'].append(self.parse_dht())
            elif marker == 0xFFDA:  # SOS
                self.parsed_data['SOS'] = self.parse_sos()
            elif marker == 0xFFD9:  # EOI
                self.parsed_data['EOI'] = marker
                break
            elif marker == 0xFFFE:  # COM
                self.parsed_data['COM'].append(self.parse_com())
            elif marker == 0xFFDD:  # DRI
                self.parsed_data['DRI'] = self.parse_dri()
            else:
                # Skip unknown or unsupported markers
                length, = struct.unpack_from(">H", self.data, self.offset)
                self.offset += length - 2

        return self.parsed_data

    def parse_app(self, marker):
        length, = struct.unpack_from(">H", self.data, self.offset)
        identifier = self.data[self.offset + 2:self.offset + 6]
        app_data = {
            'marker': marker,
            'length': length,
            'identifier': identifier,
            'data': self.data[self.offset + 6:self.offset + length]
        }
        self.offset += length

        if marker == 0xFFE0:  # APP0 (JFIF)
            app_data['jfif'] = self.parse_jfif(app_data['data'])
        elif marker == 0xFFE1 and identifier == b'Exif':  # EXIF
            app_data['exif'] = self.parse_exif(app_data['data'][2:])
        elif marker == 0xFFED:  # APP13 (IPTC)
            app_data['iptc'] = self.parse_iptc(app_data['data'])
        elif marker == 0xFFEE:  # APP14 (Adobe)
            app_data['adobe'] = self.parse_adobe(app_data['data'])
        elif marker == 0xFFE2 and identifier.startswith(b'ICC_PROFILE'):  # ICC Profile
            app_data['icc_profile'] = self.parse_icc_profile(app_data['data'])
        elif marker == 0xFFE2 and identifier.startswith(b'MPF'):  # MPF
            app_data['mpf'] = self.parse_mpf(app_data['data'])
        elif marker == 0xFFE3:  # APP3 (Meta)
            app_data['meta'] = self.parse_meta(app_data['data'])
        elif marker == 0xFFE4:  # APP4
            app_data['app4'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFE5:  # APP5
            app_data['app5'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFE6:  # APP6
            app_data['app6'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFE7:  # APP7
            app_data['app7'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFE8:  # APP8
            app_data['app8'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFE9:  # APP9
            app_data['app9'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFEA:  # APP10
            app_data['app10'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFEB:  # APP11
            app_data['app11'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFEC:  # APP12
            app_data['app12'] = self.parse_app_generic(app_data['data'])
        elif marker == 0xFFEF:  # APP15
            app_data['app15'] = self.parse_app_generic(app_data['data'])

        return app_data

    def parse_jfif(self, data):
        version = struct.unpack_from(">H", data, 0)[0]
        units = data[2]
        x_density, y_density = struct.unpack_from(">HH", data, 3)
        x_thumbnail, y_thumbnail = struct.unpack_from(">BB", data, 7)
        return {
            'version': version,
            'units': units,
            'x_density': x_density,
            'y_density': y_density,
            'x_thumbnail': x_thumbnail,
            'y_thumbnail': y_thumbnail,
            'thumbnail': data[9:]
        }

    def parse_exif(self, data):
        endianness = data[:2]
        if endianness == b'II':  # Little endian
            endian_format = '<'
        elif endianness == b'MM':  # Big endian
            endian_format = '>'
        else:
            raise ValueError('Invalid EXIF endianness')

        # Check TIFF header
        tiff_header = struct.unpack_from(f"{endian_format}H", data, 2)[0]
        if tiff_header != 42:
            raise ValueError('Invalid TIFF header')

        # Offset to IFD0
        ifd0_offset = struct.unpack_from(f"{endian_format}I", data, 4)[0]

        # Parse IFD0
        exif_data = {}
        exif_data['IFD0'] = self.parse_ifd(data, ifd0_offset, endian_format)

        # Check for Exif IFD pointer
        exif_offset = exif_data['IFD0'].get(0x8769, {}).get('value', None)
        if exif_offset:
            exif_data['ExifIFD'] = self.parse_ifd(data, exif_offset, endian_format)

        # Check for GPS IFD pointer
        gps_offset = exif_data['IFD0'].get(0x8825, {}).get('value', None)
        if gps_offset:
            exif_data['GPSIFD'] = self.parse_ifd(data, gps_offset, endian_format)

        # Check for IFD1 (thumbnail IFD)
        ifd1_offset = struct.unpack_from(f"{endian_format}I", data, ifd0_offset + 2 + 12 * len(exif_data['IFD0']))[0]
        if ifd1_offset:
            exif_data['IFD1'] = self.parse_ifd(data, ifd1_offset, endian_format)

        return exif_data

    def parse_ifd(self, data, offset, endian_format):
        num_entries = struct.unpack_from(f"{endian_format}H", data, offset)[0]
        offset += 2
        entries = {}

        for _ in range(num_entries):
            tag, type_, count, value = struct.unpack_from(f"{endian_format}HHII", data, offset)
            if type_ == 2:  # ASCII strings
                value_offset = value if count > 4 else offset + 8
                value = data[value_offset:value_offset + count].decode('ascii', 'replace').strip('\x00')
            entries[tag] = {
                'type': type_,
                'count': count,
                'value': value
            }
            offset += 12

        return entries

    def parse_iptc(self, data):
        iptc_data = {}
        offset = 0
        while offset < len(data):
            if data[offset:offset + 2] == b'\x1C\x02':
                tag = data[offset + 2]
                size = struct.unpack_from(">H", data, offset + 3)[0]
                value = data[offset + 5:offset + 5 + size]
                iptc_data[tag] = value
                offset += 5 + size
            else:
                offset += 1
        return iptc_data

    def parse_adobe(self, data):
        version, flags0, flags1, transform = struct.unpack_from(">HHHB", data, 0)
        return {
            'version': version,
            'flags0': flags0,
            'flags1': flags1,
            'transform': transform
        }

    def parse_icc_profile(self, data):
        profile = {}
        offset = 0
        profile['identifier'] = data[offset:offset + 12].decode('ascii')
        offset += 12
        profile['sequence_number'] = data[offset]
        offset += 1
        profile['total_sequences'] = data[offset]
        offset += 1
        profile['data'] = data[offset:]
        return profile

    def parse_mpf(self, data):
        mpf_data = {}
        offset = 0
        mpf_data['identifier'] = data[offset:offset + 4].decode('ascii')
        offset += 4
        mpf_data['version'] = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        mpf_data['number_of_images'] = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        mpf_data['mp_entry'] = []
        for _ in range(mpf_data['number_of_images']):
            entry = struct.unpack_from(">IIIIH", data, offset)
            mpf_data['mp_entry'].append({
                'image_size': entry[0],
                'data_offset': entry[1],
                'image_data_length': entry[2],
                'dependent_image_1_entry_number': entry[3],
                'dependent_image_2_entry_number': entry[4]
            })
            offset += 16
        return mpf_data


    def parse_meta(self, data):
        return {
            'meta_data': data
        }

    def parse_app_generic(self, data):
        return {
            'app_data': data
        }

    def parse_dqt(self):
        length, = struct.unpack_from(">H", self.data, self.offset)
        offset = self.offset + 2
        dqt_data = []

        # Parse all DQT entries within this segment
        while offset < self.offset + length:
            pq_tq = self.data[offset]
            pq = (pq_tq >> 4) & 0x0F
            tq = pq_tq & 0x0F
            qt_length = 64 if pq == 0 else 128
            qt = self.data[offset + 1:offset + 1 + qt_length]
            dqt_data.append({
                'pq': pq,
                'tq': tq,
                'qt': qt
            })
            offset += 1 + qt_length

        self.offset += length
        return dqt_data

    def parse_sof(self, marker):
        length, = struct.unpack_from(">H", self.data, self.offset)
        offset = self.offset + 2
        sof_data = {
            'marker': marker,
            'length': length,
            'precision': self.data[offset],
            'height': struct.unpack_from(">H", self.data, offset + 1)[0],
            'width': struct.unpack_from(">H", self.data, offset + 3)[0],
            'components': []
        }
        num_components = self.data[offset + 5]
        offset += 6

        # Parse component specifications
        for _ in range(num_components):
            component_id = self.data[offset]
            sampling_factors = self.data[offset + 1]
            quantization_table_id = self.data[offset + 2]
            sof_data['components'].append({
                'component_id': component_id,
                'sampling_factors': sampling_factors,
                'quantization_table_id': quantization_table_id
            })
            offset += 3

        self.offset += length
        return sof_data

    def parse_dht(self):
        length, = struct.unpack_from(">H", self.data, self.offset)
        offset = self.offset + 2
        dht_data = []

        # Parse all DHT entries within this segment
        while offset < self.offset + length:
            ht_info = self.data[offset]
            ht_type = (ht_info >> 4) & 0x0F
            ht_number = ht_info & 0x0F
            num_codes = self.data[offset + 1:offset + 17]
            num_symbols = sum(num_codes)
            symbols = self.data[offset + 17:offset + 17 + num_symbols]
            dht_data.append({
                'ht_type': ht_type,
                'ht_number': ht_number,
                'num_codes': num_codes,
                'symbols': symbols
            })
            offset += 17 + num_symbols

        self.offset += length
        return dht_data

    def parse_sos(self):
        length, = struct.unpack_from(">H", self.data, self.offset)
        offset = self.offset + 2
        sos_data = {
            'length': length,
            'num_components': self.data[offset],
            'components': []
        }
        offset += 1

        # Parse component selectors
        for _ in range(sos_data['num_components']):
            component_id = self.data[offset]
            dc_ac = self.data[offset + 1]
            sos_data['components'].append({
                'component_id': component_id,
                'dc_table_selector': (dc_ac >> 4) & 0x0F,
                'ac_table_selector': dc_ac & 0x0F
            })
            offset += 2

        # Parse spectral selection and successive approximation
        sos_data['spectral_selection_start'] = self.data[offset]
        sos_data['spectral_selection_end'] = self.data[offset + 1]
        sos_data['successive_approximation'] = self.data[offset + 2]
        offset += 3

        self.offset = offset

        # Skip image data until EOI marker
        while self.offset < len(self.data):
            if self.data[self.offset:self.offset + 2] == b'\xFF\xD9':  # EOI
                break
            self.offset += 1

        return sos_data

    def parse_com(self):
        length, = struct.unpack_from(">H", self.data, self.offset)
        comment = self.data[self.offset + 2:self.offset + length].decode('utf-8', 'replace')
        self.offset += length
        return comment

    def parse_dri(self):
        length, = struct.unpack_from(">H", self.data, self.offset)
        dri_data = struct.unpack_from(">H", self.data, self.offset + 2)[0]
        self.offset += length
        return dri_data
