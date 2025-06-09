import os
import struct

class MP4Parser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.atoms = {}

    def parse(self):
        with open(self.file_path, 'rb') as f:
            file_size = os.path.getsize(self.file_path)
            file_data = f.read(file_size)
            self.atoms = self.parse_container(file_data, file_size)

    def parse_container(self, data, size):
        container = {}
        offset = 0

        while offset < size:
            atom_start = offset
            atom = self._read_atom(data, atom_start)
            if not atom:
                break

            if atom['size'] == 0:
                break

            atom_type = atom['type']
            atom_data = atom['data']

            parsed_atom = self.parse_atom(atom_type, atom_data)

            if atom_type in container:
                if not isinstance(container[atom_type], list):
                    container[atom_type] = [container[atom_type]]
                container[atom_type].append(parsed_atom)
            else:
                container[atom_type] = parsed_atom

            offset += atom['size']

        return container

    def fp16_to_float(self, fp16):
        return fp16 / 0x100

    def fp32_to_float(self, fp32):
        return fp32 / 0x10000

    def read_bits(self, array: bytes, bit_pos: int, num_bits: int):
        """
        Reads 'num_bits' bits from 'array' starting at 'bit_pos' (bit-level),
        returns a tuple (value, new_bit_pos).
        """
        value = 0
        for _ in range(num_bits):
            byte_index = bit_pos // 8
            bit_index = 7 - (bit_pos % 8)
            bit_val = (array[byte_index] >> bit_index) & 0x01
            value = (value << 1) | bit_val
            bit_pos += 1
        return value, bit_pos

    def _read_atom(self, data, atom_start):
        header = data[atom_start:atom_start + 8]
        if len(header) < 8:
            return None
        size, atom_type = struct.unpack('>I4s', header)
        try:
            atom_type = atom_type.decode('utf-8')
        except UnicodeDecodeError:
            atom_type = atom_type.decode('iso-8859-1')
        if size == 1:
            size = struct.unpack('>Q', data[atom_start + 8:atom_start + 16])[0]
            atom_data = data[atom_start + 16:atom_start + size]
        else:
            atom_data = data[atom_start + 8:atom_start + size]
        return {'type': atom_type, 'size': size, 'data': atom_data, 'position': atom_start}

    def parse_sample_description(self, entry_type, data):
        if entry_type in ['avc1', 'hvc1', 'mp4v', 'encv']:  # Video sample descriptions
            return self.parse_video_sample_description(entry_type, data)
        elif entry_type in ['mp4a', 'enca']:  # Audio sample descriptions
            return self.parse_audio_sample_description(entry_type, data)
        else:
            return {
                'type': entry_type,
                'data': data  # Raw data for unsupported types
            }
    def parse_video_sample_description(self, entry_type, data):
        (reserved, data_reference_index, pre_defined, width, height,
         horiz_resolution, vert_resolution, reserved3, frame_count, compressor_name, depth,
         pre_defined3) = struct.unpack(
            '>6sH16s2H2I4sH32s2H', data[:78])

        remaining_data = data[78:]
        extensions = []
        while remaining_data:
            try:
                size, atom_type = struct.unpack('>I4s', remaining_data[:8])
            except struct.error as e:
                # print(f"[Warning] entry: {entry_type}, {str(e)}")
                break
            try:
                atom_type = atom_type.decode('utf-8')
            except UnicodeDecodeError:
                atom_type = atom_type.decode('iso-8859-1')
            atom_data = remaining_data[8:size]
            extensions.append(self.parse_video_extensions(atom_type, atom_data))
            remaining_data = remaining_data[size:]

        return {
            'reserved': reserved,
            'data_reference_index': data_reference_index,
            'pre_defined': pre_defined,
            'width': width,
            'height': height,
            'horiz_resolution': self.fp32_to_float(horiz_resolution),
            'vert_resolution': self.fp32_to_float(vert_resolution),
            'reserved3': reserved3,
            'frame_count': frame_count,
            'compressor_name': compressor_name.decode('utf-8').strip('\x00'),
            'depth': depth,
            'pre_defined3': pre_defined3,
            'extensions': extensions
        }

    def parse_video_extensions(self, atom_type, data):
        if atom_type == 'avcC':
            return self.parse_avcC(data)
        elif atom_type == 'hvcC':
            return self.parse_hvcC(data)
        elif atom_type == 'esds':
            return self.parse_esds(data)
        elif atom_type == 'vpcC':
            return self.parse_vpcC(data)
        elif atom_type == 'av1C':
            return self.parse_av1C(data)
        elif atom_type == 'pasp':
            return self.parse_pasp(data)
        elif atom_type == 'btrt':
            return self.parse_btrt(data)
        elif atom_type == 'clap':
            return self.parse_clap(data)
        elif atom_type == 'colr':
            return self.parse_colr(data)
        else:
            return {'type': atom_type, 'data': data}

    def parse_audio_sample_description(self, entry_type, data):
        (reserved, data_reference_index, reserved_2, channel_count,
         sample_size, pre_defined, reserved_3, sample_rate) = struct.unpack('>6sHQHHHHI', data[:28])

        remaining_data = data[28:]
        extensions = []
        while remaining_data:
            size, atom_type = struct.unpack('>I4s', remaining_data[:8])
            try:
                atom_type = atom_type.decode('utf-8')
            except UnicodeDecodeError:
                atom_type = atom_type.decode('iso-8859-1')
            atom_data = remaining_data[8:size]
            extensions.append(self.parse_audio_extensions(atom_type, atom_data))
            remaining_data = remaining_data[size:]

        return {
            'reserved': reserved,
            'data_reference_index': data_reference_index,
            'reserved_2': reserved_2,
            'channel_count': channel_count,
            'sample_size': sample_size,
            'pre_defined': pre_defined,
            'reserved_3': reserved_3,
            'sample_rate': self.fp32_to_float(sample_rate),
            'extensions': extensions
        }

    def parse_audio_extensions(self, atom_type, data):
        if atom_type == 'esds':
            return self.parse_esds(data)
        elif atom_type == 'dOps':
            return self.parse_dOps(data)
        elif atom_type == 'dac3':
            return self.parse_dac3(data)
        elif atom_type == 'dec3':
            return self.parse_dec3(data)
        else:
            return {'type': atom_type, 'data': data}

    # Example parsing functions for codec-specific data
    def parse_avcC(self, data):
        # Parse avcC box (AVC configuration)
        configuration_version, avc_profile_indication, profile_compatibility, avc_level_indication = struct.unpack(
            '>BBBB', data[:4])
        length_size_minus_one = data[4] & 0x03
        num_of_sps = data[5] & 0x1F
        offset = 6
        sps = []

        for _ in range(num_of_sps):
            sps_length = struct.unpack('>H', data[offset:offset + 2])[0]
            sps_data = data[offset + 2:offset + 2 + sps_length]
            sps.append(sps_data)
            offset += 2 + sps_length

        num_of_pps = data[offset]
        offset += 1
        pps = []

        for _ in range(num_of_pps):
            pps_length = struct.unpack('>H', data[offset:offset + 2])[0]
            pps_data = data[offset + 2:offset + 2 + pps_length]
            pps.append(pps_data)
            offset += 2 + pps_length

        return {
            'type'
            'configuration_version': configuration_version,
            'avc_profile_indication': avc_profile_indication,
            'profile_compatibility': profile_compatibility,
            'avc_level_indication': avc_level_indication,
            'length_size_minus_one': length_size_minus_one,
            'sps': sps,
            'pps': pps
        }

    def parse_hvcC(self, data):

        (configuration_version, general_profile_space_tier_idc, general_profile_compatibility_flags, general_constraint_indicator_flags1, general_constraint_indicator_flags2, general_level_idc,
         min_spatial_segmentation_idc, parallelism_type, chroma_format_idc, bit_depth_luma_minus8, bit_depth_chroma_minus8, avg_frame_rate, constant_frame_rate_num_temporal_layers,
         num_of_arrays) = struct.unpack('>BBIHIBHBBBBHBB', data[:23])

        general_profile_space = (general_profile_space_tier_idc >> 6) & 0x03
        general_tier_flag = (general_profile_space_tier_idc >> 5) & 0x01
        general_profile_idc = general_profile_space_tier_idc & 0x1F

        general_constraint_indicator_flags = (general_constraint_indicator_flags1 | general_constraint_indicator_flags2 << 16)

        min_spatial_segmentation_idc &= 0x0FFF

        constant_frame_rate = (constant_frame_rate_num_temporal_layers >> 6) & 0x03
        num_temporal_layers = (constant_frame_rate_num_temporal_layers >> 3) & 0x07
        temporal_id_nested = (constant_frame_rate_num_temporal_layers >> 2) & 0x01
        length_size_minus_one = constant_frame_rate_num_temporal_layers & 0x03

        arrays = []
        offset = 23

        for _ in range(num_of_arrays):
            array_completeness_nal_unit_type = struct.unpack('>B', data[offset:offset + 1])[0]
            array_completeness = (array_completeness_nal_unit_type >> 7) & 0x01
            nal_unit_type = array_completeness_nal_unit_type & 0x3F
            num_nalus = struct.unpack('>H', data[offset + 1:offset + 3])[0]
            offset += 3

            nalus = []
            for _ in range(num_nalus):
                nal_unit_length = struct.unpack('>H', data[offset:offset + 2])[0]
                nal_unit = data[offset + 2:offset + 2 + nal_unit_length]
                nalus.append(nal_unit)
                offset += 2 + nal_unit_length

            arrays.append({
                'array_completeness': array_completeness,
                'nal_unit_type': nal_unit_type,
                'nalus': nalus
            })

        # Organize NAL units by type
        vps = [nal for array in arrays if array['nal_unit_type'] == 32 for nal in
               array['nalus']]  # VPS NAL unit type is 32
        sps = [nal for array in arrays if array['nal_unit_type'] == 33 for nal in
               array['nalus']]  # SPS NAL unit type is 33
        pps = [nal for array in arrays if array['nal_unit_type'] == 34 for nal in
               array['nalus']]  # PPS NAL unit type is 34
        sei = [nal for array in arrays if array['nal_unit_type'] == 39 for nal in
               array['nalus']]  # PPS NAL unit type is 34

        return {
            'configuration_version': configuration_version,
            'general_profile_space': general_profile_space,
            'general_tier_flag': general_tier_flag,
            'general_profile_idc': general_profile_idc,
            'general_profile_compatibility_flags': general_profile_compatibility_flags,
            'general_constraint_indicator_flags': general_constraint_indicator_flags,
            'general_level_idc': general_level_idc,
            'min_spatial_segmentation_idc': min_spatial_segmentation_idc,
            'parallelism_type': parallelism_type,
            'chroma_format_idc': chroma_format_idc,
            'bit_depth_luma_minus8': bit_depth_luma_minus8,
            'bit_depth_chroma_minus8': bit_depth_chroma_minus8,
            'avg_frame_rate': avg_frame_rate,
            'constant_frame_rate': constant_frame_rate,
            'num_temporal_layers': num_temporal_layers,
            'temporal_id_nested': temporal_id_nested,
            'length_size_minus_one': length_size_minus_one,
            'arrays': arrays,
            'vps': vps,
            'sps': sps,
            'pps': pps,
            'sei': sei,
            'type': 'hvcC'
        }

    def parse_esds(self, data):
        """
        Parses the 'esds' (Elementary Stream Descriptor) box according to
        ISO/IEC 14496-1 and ISO/IEC 14496-3. Handles nested structures in ES_DescrTag.
        """
        esds_version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        
        # Container for parsed descriptors
        descriptors = []

        start_offset = offset
        end_offset = len(data)

        local_descriptors = []
        local_offset = start_offset

        while local_offset < end_offset:
            if local_offset + 1 > end_offset:
                break

            # Read the descriptor tag
            tag = data[local_offset]
            local_offset += 1

            # Read the descriptor size (variable length)
            size = 0
            while True:
                if local_offset >= end_offset:
                    break
                b = data[local_offset]
                local_offset += 1
                size = (size << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break

            descriptor_start = local_offset
            descriptor_end = descriptor_start + size

            # Check boundary
            if descriptor_end > end_offset:
                break

            # ES_DescrTag (0x03)
            if tag == 0x03:
                # ES_ID (16 bits) + flag byte
                es_id = struct.unpack('>H', data[descriptor_start:descriptor_start + 2])[0]
                flag_byte = data[descriptor_start + 2]
                stream_dependence_flag = (flag_byte >> 7) & 0x01
                url_flag = (flag_byte >> 6) & 0x01
                ocr_stream_flag = (flag_byte >> 5) & 0x01
                stream_priority = flag_byte & 0x1F

                parse_offset = descriptor_start + 3
                depends_on_es_id = None
                url_string = None
                ocr_es_id = None

                # If stream_dependence_flag == 1, read dependsOnES_ID (2 bytes)
                if stream_dependence_flag == 1:
                    depends_on_es_id = struct.unpack('>H', data[parse_offset:parse_offset + 2])[0]
                    parse_offset += 2

                # If url_flag == 1, read url length + url string
                if url_flag == 1:
                    url_length = data[parse_offset]
                    parse_offset += 1
                    url_string = data[parse_offset:parse_offset + url_length].decode('utf-8', errors='replace')
                    parse_offset += url_length

                # If ocr_stream_flag == 1, read OCR_ES_ID (2 bytes)
                if ocr_stream_flag == 1:
                    ocr_es_id = struct.unpack('>H', data[parse_offset:parse_offset + 2])[0]
                    parse_offset += 2

                # There can be sub-descriptors (DecoderConfig, etc.) inside ES_DescrTag
                sub_descriptors = []
                sub_offset = parse_offset
                while sub_offset < descriptor_end:
                    if sub_offset + 1 > descriptor_end:
                        break
                    sub_tag = data[sub_offset]
                    sub_offset += 1

                    sub_size = 0
                    while True:
                        if sub_offset >= descriptor_end:
                            break
                        sb = data[sub_offset]
                        sub_offset += 1
                        sub_size = (sub_size << 7) | (sb & 0x7F)
                        if not (sb & 0x80):
                            break

                    sub_start = sub_offset
                    sub_end = sub_start + sub_size
                    if sub_end > descriptor_end:
                        break

                    if sub_tag == 0x04:  # DecoderConfigDescrTag
                        if sub_size >= 13:
                            object_type_id = data[sub_start]
                            stream_type_byte = data[sub_start + 1]
                            buffer_size_db = struct.unpack(
                                '>I', b'\x00' + data[sub_start + 2:sub_start + 5]
                            )[0]
                            max_bitrate = struct.unpack('>I', data[sub_start + 5:sub_start + 9])[0]
                            avg_bitrate = struct.unpack('>I', data[sub_start + 9:sub_start + 13])[0]

                            stream_type = (stream_type_byte >> 2) & 0x3F
                            up_stream = (stream_type_byte >> 1) & 0x01
                            reserved = stream_type_byte & 0x01

                            sub_descriptors.append({
                                'tag': 'DecoderConfigDescrTag',
                                'object_type_id': object_type_id,
                                'stream_type': stream_type,
                                'up_stream': up_stream,
                                'reserved': reserved,
                                'buffer_size_db': buffer_size_db,
                                'max_bitrate': max_bitrate,
                                'avg_bitrate': avg_bitrate
                            })

                            sub_offset = sub_start + 13
                            if sub_offset + 1 > descriptor_end:
                                break
                            sub_tag = data[sub_offset]
                            sub_offset += 1

                            sub_size = 0
                            while True:
                                if sub_offset >= descriptor_end:
                                    break
                                sb = data[sub_offset]
                                sub_offset += 1
                                sub_size = (sub_size << 7) | (sb & 0x7F)
                                if not (sb & 0x80):
                                    break

                            sub_start = sub_offset
                            sub_end = sub_start + sub_size
                            if sub_end > descriptor_end:
                                break

                            # sub_tag == 0x05:  # DecSpecificInfoTag
                            if sub_tag == 0x05:
                                dec_specific_info = data[sub_start:sub_end]
                                bit_pos = 0

                                audio_object_type, bit_pos = self.read_bits(dec_specific_info, bit_pos, 5)
                                if audio_object_type == 31:
                                    ext_aot, bit_pos = self.read_bits(dec_specific_info, bit_pos, 6)
                                    audio_object_type = 32 + ext_aot

                                sampling_freq_index, bit_pos = self.read_bits(dec_specific_info, bit_pos, 4)
                                sampling_freq = None
                                if sampling_freq_index == 0x0F:
                                    sampling_freq, bit_pos = self.read_bits(dec_specific_info, bit_pos, 24)

                                channel_config, bit_pos = self.read_bits(dec_specific_info, bit_pos, 4)

                                sbrPresentFlag = -1
                                if audio_object_type == 5:
                                    extensionAudioObjectType = audio_object_type
                                    sbrPresentFlag = 1
                                    extensionSamplingFrequencyIndex, bit_pos = self.read_bits(dec_specific_info, bit_pos, 4)
                                    if extensionSamplingFrequencyIndex == 0x0F:
                                        extensionSamplingFrequency, bit_pos = self.read_bits(dec_specific_info, bit_pos, 24)
                                    audio_object_type, bit_pos = self.read_bits(dec_specific_info, bit_pos, 5)
                                    if audio_object_type == 31:
                                        ext_aot, bit_pos = self.read_bits(dec_specific_info, bit_pos, 6)
                                        audio_object_type = 32 + ext_aot
                                else:
                                    extensionAudioObjectType = 0

                                # GA Specific Config
                                frame_length_flag = 0
                                depends_on_core_coder = 0
                                extension_flag = 0
                                if audio_object_type in [1, 2, 3, 4, 6, 7, 17, 23, 29, 39]:
                                    frame_length_flag, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                                    depends_on_core_coder, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                                    extension_flag, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                                    if depends_on_core_coder == 1:
                                        bit_pos += 14  # skip coreCoderDelay

                                if extensionAudioObjectType == 5:
                                    audio_object_type = extensionAudioObjectType

                                audio_specific_config = {
                                    'audio_object_type': audio_object_type,
                                    'sampling_frequency_index': sampling_freq_index,
                                    'sampling_frequency': sampling_freq,
                                    'channel_configuration': channel_config,
                                    'frame_length_flag': frame_length_flag,
                                    'depends_on_core_coder': depends_on_core_coder,
                                    'extension_flag': extension_flag
                                }

                                sub_descriptors.append({
                                    'tag': 'DecSpecificInfoTag',
                                    'dec_specific_info_raw': dec_specific_info,
                                    'audio_specific_config': audio_specific_config
                                })

                    elif sub_tag == 0x06:  # SLConfigDescrTag
                        sl_data = data[sub_start:sub_end]
                        predefined = sl_data[0] if len(sl_data) > 0 else None
                        sub_descriptors.append({
                            'tag': 'SLConfigDescrTag',
                            'predefined': predefined,
                            'sl_data': sl_data
                        })

                    # If there are more sub-tags, handle them similarly
                    sub_offset = sub_end

                local_descriptors.append({
                    'tag': 'ES_DescrTag',
                    'es_id': es_id,
                    'stream_dependence_flag': stream_dependence_flag,
                    'url_flag': url_flag,
                    'ocr_stream_flag': ocr_stream_flag,
                    'stream_priority': stream_priority,
                    'depends_on_es_id': depends_on_es_id,
                    'url_string': url_string,
                    'ocr_es_id': ocr_es_id,
                    'sub_descriptors': sub_descriptors
                })

            elif tag == 0x04:  # Top-level DecoderConfigDescrTag
                if size >= 13:
                    object_type_id = data[descriptor_start]
                    stream_type_byte = data[descriptor_start + 1]
                    buffer_size_db = struct.unpack(
                        '>I', b'\x00' + data[descriptor_start + 2:descriptor_start + 5]
                    )[0]
                    max_bitrate = struct.unpack('>I', data[descriptor_start + 5:descriptor_start + 9])[0]
                    avg_bitrate = struct.unpack('>I', data[descriptor_start + 9:descriptor_start + 13])[0]

                    stream_type = (stream_type_byte >> 2) & 0x3F
                    up_stream = (stream_type_byte >> 1) & 0x01
                    reserved = stream_type_byte & 0x01

                    local_descriptors.append({
                        'tag': 'DecoderConfigDescrTag',
                        'object_type_id': object_type_id,
                        'stream_type': stream_type,
                        'up_stream': up_stream,
                        'reserved': reserved,
                        'buffer_size_db': buffer_size_db,
                        'max_bitrate': max_bitrate,
                        'avg_bitrate': avg_bitrate
                    })

            elif tag == 0x05:  # Top-level DecSpecificInfoTag
                dec_specific_info = data[descriptor_start:descriptor_end]
                bit_pos = 0
                audio_object_type, bit_pos = self.read_bits(dec_specific_info, bit_pos, 5)
                if audio_object_type == 31:
                    ext_aot, bit_pos = self.read_bits(dec_specific_info, bit_pos, 6)
                    audio_object_type = 32 + ext_aot

                sampling_freq_index, bit_pos = self.read_bits(dec_specific_info, bit_pos, 4)
                sampling_freq = None
                if sampling_freq_index == 0x0F:
                    sampling_freq, bit_pos = self.read_bits(dec_specific_info, bit_pos, 24)

                channel_config, bit_pos = self.read_bits(dec_specific_info, bit_pos, 4)

                frame_length_flag = 0
                depends_on_core_coder = 0
                extension_flag = 0
                if audio_object_type in [1, 2, 3, 4, 6, 7, 17, 23, 29, 39]:
                    frame_length_flag, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                    depends_on_core_coder, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                    extension_flag, bit_pos = self.read_bits(dec_specific_info, bit_pos, 1)
                    if depends_on_core_coder == 1:
                        bit_pos += 14

                audio_specific_config = {
                    'audio_object_type': audio_object_type,
                    'sampling_frequency_index': sampling_freq_index,
                    'sampling_frequency': sampling_freq,
                    'channel_configuration': channel_config,
                    'frame_length_flag': frame_length_flag,
                    'depends_on_core_coder': depends_on_core_coder,
                    'extension_flag': extension_flag
                }

                local_descriptors.append({
                    'tag': 'DecSpecificInfoTag',
                    'dec_specific_info_raw': dec_specific_info,
                    'audio_specific_config': audio_specific_config
                })

            elif tag == 0x06:  # Top-level SLConfigDescrTag
                sl_data = data[descriptor_start:descriptor_end]
                predefined = sl_data[0] if len(sl_data) > 0 else None
                local_descriptors.append({
                    'tag': 'SLConfigDescrTag',
                    'predefined': predefined,
                    'sl_data': sl_data
                })

            # Move on to the next descriptor
            local_offset = descriptor_end

        descriptors = local_descriptors

        return {
            'esds_version': esds_version,
            'flags': flags,
            'descriptors': descriptors
        }

    def parse_vpcC(self, data):
        # Parse vpcC box (VP9 codec configuration)
        (profile, level, bit_depth, chroma_subsampling, video_full_range_flag) = struct.unpack('>BBBBB', data[:5])
        return {
            'profile': profile,
            'level': level,
            'bit_depth': bit_depth,
            'chroma_subsampling': chroma_subsampling,
            'video_full_range_flag': video_full_range_flag
        }

    def parse_pasp(self, data):
        h_spacing, v_spacing = struct.unpack('>II', data[:8])
        return {
            'h_spacing': h_spacing,
            'v_spacing': v_spacing
        }

    def parse_btrt(self, data):
        buffer_size_db, max_bitrate, avg_bitrate = struct.unpack('>III', data[:12])
        return {
            'buffer_size_db': buffer_size_db,
            'max_bitrate': max_bitrate,
            'avg_bitrate': avg_bitrate
        }

    def parse_clap(self, data):
        clean_aperture_width_n, clean_aperture_width_d, clean_aperture_height_n, clean_aperture_height_d, horiz_offset_n, horiz_offset_d, vert_offset_n, vert_offset_d = struct.unpack(
            '>IIIIIIII', data[:32])
        return {
            'clean_aperture_width_n': clean_aperture_width_n,
            'clean_aperture_width_d': clean_aperture_width_d,
            'clean_aperture_height_n': clean_aperture_height_n,
            'clean_aperture_height_d': clean_aperture_height_d,
            'horiz_offset_n': horiz_offset_n,
            'horiz_offset_d': horiz_offset_d,
            'vert_offset_n': vert_offset_n,
            'vert_offset_d': vert_offset_d
        }

    def parse_colr(self, data):
        color_type = data[:4].decode('utf-8')
        if color_type == 'nclc':
            primary, transfer, matrix = struct.unpack('>HHH', data[4:10])
            return {
                'color_type': color_type,
                'primary': primary,
                'transfer': transfer,
                'matrix': matrix,
                'type': 'colr'
            }
        elif color_type == 'rICC' or color_type == 'prof':
            icc_profile = data[4:]
            return {
                'color_type': color_type,
                'icc_profile': icc_profile,
                'type': 'colr'
            }
        else:
            return {'color_type': color_type, 'data': data[4:], 'type': 'colr'}

    def parse_av1C(self, data):
        # Parse av1C box (AV1 codec configuration)
        (marker, version, seq_profile, seq_level_idx_0, seq_tier_0, high_bitdepth, twelve_bit, monochrome,
         chroma_subsampling_x, chroma_subsampling_y, chroma_sample_position) = struct.unpack('>BBBBBBBBBBB', data[:11])
        return {
            'marker': marker,
            'version': version,
            'seq_profile': seq_profile,
            'seq_level_idx_0': seq_level_idx_0,
            'seq_tier_0': seq_tier_0,
            'high_bitdepth': high_bitdepth,
            'twelve_bit': twelve_bit,
            'monochrome': monochrome,
            'chroma_subsampling_x': chroma_subsampling_x,
            'chroma_subsampling_y': chroma_subsampling_y,
            'chroma_sample_position': chroma_sample_position
        }

    def parse_dOps(self, data):
        # Parse dOps box (Opus decoder configuration)
        version, channel_count, pre_skip, input_sample_rate, output_gain, channel_mapping_family = struct.unpack(
            '>BBHIHB', data[:10])
        return {
            'version': version,
            'channel_count': channel_count,
            'pre_skip': pre_skip,
            'input_sample_rate': input_sample_rate,
            'output_gain': output_gain,
            'channel_mapping_family': channel_mapping_family
        }

    def parse_dac3(self, data):
        # Parse dac3 box (AC-3 specific)
        fscod, bsid, bsmod, acmod, lfeon, bit_rate_code = struct.unpack('>BBBBBB', data[:6])
        return {
            'fscod': fscod,
            'bsid': bsid,
            'bsmod': bsmod,
            'acmod': acmod,
            'lfeon': lfeon,
            'bit_rate_code': bit_rate_code
        }

    def parse_dec3(self, data):
        # Parse dec3 box (E-AC-3 specific)
        data_rate, num_ind_sub = struct.unpack('>HB', data[:3])
        offset = 3
        substreams = []

        for _ in range(num_ind_sub):
            fscod, bsid, bsmod, acmod, lfeon, num_dep_sub = struct.unpack('>BBBBBB', data[offset:offset + 6])
            offset += 6
            chan_loc = 0
            if num_dep_sub > 0:
                chan_loc = struct.unpack('>H', data[offset:offset + 2])[0]
                offset += 2

            substreams.append({
                'fscod': fscod,
                'bsid': bsid,
                'bsmod': bsmod,
                'acmod': acmod,
                'lfeon': lfeon,
                'num_dep_sub': num_dep_sub,
                'chan_loc': chan_loc
            })

        return {
            'data_rate': data_rate,
            'num_ind_sub': num_ind_sub,
            'substreams': substreams
        }

    def parse_atom(self, atom_type, data):
        if atom_type == 'ftyp':
            return self.parse_ftyp(data)
        elif atom_type == 'moov':
            return self.parse_container(data, len(data))
        elif atom_type == 'moof':
            return self.parse_container(data, len(data))
        elif atom_type == 'mvhd':
            return self.parse_mvhd(data)
        elif atom_type == 'trak':
            return self.parse_container(data, len(data))
        elif atom_type == 'tkhd':
            return self.parse_tkhd(data)
        elif atom_type == 'edts':
            return self.parse_container(data, len(data))
        elif atom_type == 'mdia':
            return self.parse_container(data, len(data))
        elif atom_type == 'mdhd':
            return self.parse_mdhd(data)
        elif atom_type == 'hdlr':
            return self.parse_hdlr(data)
        elif atom_type == 'minf':
            return self.parse_container(data, len(data))
        elif atom_type == 'vmhd':
            return self.parse_vmhd(data)
        elif atom_type == 'smhd':
            return self.parse_smhd(data)
        elif atom_type == 'stbl':
            return self.parse_container(data, len(data))
        elif atom_type == 'stsd':
            return self.parse_stsd(data)
        elif atom_type == 'stsc':
            return self.parse_stsc(data)
        elif atom_type == 'stsz':
            return self.parse_stsz(data)
        elif atom_type == 'stco':
            return self.parse_stco(data)
        elif atom_type == 'ctts':
            return self.parse_ctts(data)
        elif atom_type == 'elst':
            return self.parse_elst(data)
        elif atom_type == 'udta':
            return self.parse_container(data, len(data))
        elif atom_type == 'mehd':
            return self.parse_mehd(data)
        elif atom_type == 'trex':
            return self.parse_trex(data)
        elif atom_type == 'mfhd':
            return self.parse_mfhd(data)
        elif atom_type == 'trun':
            return self.parse_trun(data)
        elif atom_type == 'mdat':
            return self.parse_mdat(data)
        elif atom_type == 'free':
            return self.parse_free(data)
        elif atom_type == 'skip':
            return self.parse_skip(data)
        elif atom_type == 'sidx':
            return self.parse_sidx(data)
        elif atom_type == 'saiz':
            return self.parse_saiz(data)
        elif atom_type == 'saio':
            return self.parse_saio(data)
        elif atom_type == 'senc':
            return self.parse_senc(data)
        elif atom_type == 'pssh':
            return self.parse_pssh(data)
        elif atom_type == 'stss':
            return self.parse_stss(data)
        elif atom_type == 'stts':
            return self.parse_stts(data)
        elif atom_type == 'co64':
            return self.parse_co64(data)
        elif atom_type == 'sgpd':
            return self.parse_sgpd(data)
        elif atom_type == 'sbgp':
            return self.parse_sbgp(data)
        elif atom_type == 'meta':
            if data[0:4] == b'\x00\x00\x00\x00':
                data = data[4:]
            return self.parse_container(data, len(data))
        elif atom_type == 'exvr':
            return self.parse_container(data, len(data))
        elif atom_type == 'traf':
            return self.parse_container(data, len(data))
        elif atom_type == 'mvex':
            return self.parse_container(data, len(data))
        elif atom_type == 'tapt':
            return self.parse_container(data, len(data))
        elif atom_type == 'clef':
            return self.parse_clef(data)
        elif atom_type == 'prof':
            return self.parse_prof(data)
        elif atom_type == 'enof':
            return self.parse_enof(data)
        elif atom_type == 'ilst':
            return self.parse_ilst(data)
        elif atom_type == 'dinf':
            return self.parse_dinf(data)
        elif atom_type == 'pitm':
            return self.parse_pitm(data)
        elif atom_type == 'iinf':
            return self.parse_iinf(data)
        elif atom_type == 'iref':
            return self.parse_iref(data)
        elif atom_type == 'iprp':
            return self.parse_iprp(data)
        elif atom_type == 'ipco':
            return self.parse_ipco(data)
        elif atom_type == 'ipma':
            return self.parse_ipma(data)
        elif atom_type == 'iloc':
            return self.parse_iloc(data)
        elif atom_type == 'idat':
            return self.parse_idat(data)
        elif atom_type == 'keys':
            return self.parse_keys(data)
        elif atom_type == 'mdta':
            return self.parse_mdta(data)
        elif atom_type == 'SDLN':
            return self.parse_SDLN(data)
        elif atom_type == 'smrd':
            return self.parse_smrd(data)
        elif atom_type == 'auth':
            return self.parse_auth(data)
        elif atom_type == 'smta':
            return self.parse_smta(data)
        else:
            return {'type': atom_type, 'data': data}


    def parse_ftyp(self, data):
        major_brand, minor_version = struct.unpack('>4sI', data[:8])
        brands = [data[i:i+4].decode('utf-8') for i in range(8, len(data), 4)]
        return {
            'major_brand': major_brand.decode('utf-8'),
            'minor_version': minor_version,
            'brands': brands
        }
    def parse_moov(self, data):
        offset = 0
        while offset < len(data):
            size, atom_type = struct.unpack('>I4s', data[offset:offset+8])
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset+8:offset+size]
            if atom_type == 'mvhd':
                self.parse_mvhd(atom_data)
            elif atom_type == 'trak':
                self.parse_trak(atom_data)
            offset += size

    def parse_mvhd(self, data):
        version = data[0]
        if version == 0:
            if len(data) < 100:
                raise ValueError("Insufficient data for mvhd version 0")
            (version, flags, creation_time, modification_time, timescale, duration, rate, volume, reserved, *matrix,
             preview_time, preview_duration, poster_time, selection_time, selection_duration, current_time,
             next_track_id) = struct.unpack(
                '>B3sIIIIIH10s9iIIIIIII', data[:100])
            rate = self.fp32_to_float(rate)
            volume = self.fp16_to_float(volume)

        elif version == 1:
            if len(data) < 112:
                raise ValueError("Insufficient data for mvhd version 1")
            (version, flags, creation_time, modification_time, timescale, duration, rate, volume, reserved, *matrix,
             preview_time, preview_duration, poster_time, selection_time, selection_duration, current_time,
             next_track_id) = struct.unpack(
                '>B3sQQIQIH10s9iIIIIIII', data[:112])
            rate = self.fp32_to_float(rate)
            volume = self.fp16_to_float(volume)
        else:
            raise ValueError(f"Unsupported mvhd version: {version}")
        
        matrix = [int(matrix[0]/65536), int(matrix[1]/65536), int(matrix[2]/65536), int(matrix[3]/65536), int(matrix[4]/65536), int(matrix[5]/65536), int(matrix[6]/65536), int(matrix[7]/65536), int(matrix[8]/(65536*16384))]

        return {
            'version': version,
            'flags': flags,
            'creation_time': creation_time,
            'modification_time': modification_time,
            'timescale': timescale,
            'duration': duration,
            'rate': rate,
            'volume': volume,
            'reserved': reserved,
            'matrix': matrix,
            'preview_time': preview_time,
            'preview_duration': preview_duration,
            'poster_time': poster_time,
            'selection_time': selection_time,
            'selection_duration': selection_duration,
            'current_time': current_time,
            'next_track_id': next_track_id
        }

    def parse_trak(self, data):
        offset = 0
        while offset < len(data):
            size, atom_type = struct.unpack('>I4s', data[offset:offset + 8])
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset + 8:offset + size]
            if atom_type == 'tkhd':
                self.parse_tkhd(atom_data)
            elif atom_type == 'mdia':
                self.parse_container(atom_data, len(atom_data))
            elif atom_type == 'edts':
                self.parse_container(atom_data, len(atom_data))
            offset += size

    def parse_tkhd(self, data):
        version = data[0]
        if version == 0:
            if len(data) < 84:
                raise ValueError("Insufficient data for tkhd version 0")
            (version, flags, create_time, modify_time, track_id, reserved, duration,
             reserved2, layer, alt_group, volume, reserved3, *matrix, width, height) = struct.unpack(
                '>B3sIIIIIQHHHH9iII', data[:84])

            volume = self.fp16_to_float(volume)
            width = self.fp32_to_float(width)
            height = self.fp32_to_float(height)
        elif version == 1:
            if len(data) < 96:
                raise ValueError("Insufficient data for tkhd version 1")
            (version, flags, create_time, modify_time, track_id, reserved, duration,
             reserved2, layer, alt_group, volume, reserved3, *matrix, width, height) = struct.unpack(
                '>B3sQQIIQQHHHH9iII', data[:96])

            volume = self.fp16_to_float(volume)
            width = self.fp32_to_float(width)
            height = self.fp32_to_float(height)
        else:
            raise ValueError(f"Unsupported tkhd version: {version}")

        matrix = [int(matrix[0]/65536), int(matrix[1]/65536), int(matrix[2]/65536), int(matrix[3]/65536), int(matrix[4]/65536), int(matrix[5]/65536), int(matrix[6]/65536), int(matrix[7]/65536), int(matrix[8]/(65536*16384))]

        return {
            'version': version,
            'flags': flags,
            'create_time': create_time,
            'modify_time': modify_time,
            'track_id': track_id,
            'reserved': reserved,
            'duration': duration,
            'reserved2': reserved2,
            'layer': layer,
            'alt_group': alt_group,
            'volume': volume,
            'reserved3': reserved3,
            'matrix': matrix,
            'width': width,
            'height': height
        }

    def parse_mdhd(self, data):
        version = data[0]
        if version == 0:
            if len(data) < 24:
                raise ValueError("Insufficient data for mdhd version 0")
            (version, flags, creation_time, modification_time, time_scale, duration, language, quality) = struct.unpack(
                '>B3sIIIIHH', data[:24])
        elif version == 1:
            if len(data) < 36:
                raise ValueError("Insufficient data for mdhd version 1")
            (version, flags, creation_time, modification_time, time_scale, duration, language, quality) = struct.unpack(
                '>B3sQQIQHH', data[:36])
        else:
            raise ValueError(f"Unsupported mdhd version: {version}")

        # Convert language and quality values
        quality = self.fp16_to_float(quality)

        return {
            'version': version,
            'flags': flags,
            'creation_time': creation_time,
            'modification_time': modification_time,
            'time_scale': time_scale,
            'duration': duration,
            'language': language,
            'quality': quality
        }

    def parse_hdlr(self, data):
        version, flags, pre_defined, handler_type, reserved = struct.unpack('>B3s4s4s12s', data[:24])
        name = data[24:].decode('utf-8').strip('\x00')
        return {
            'version': version,
            'flags': flags,
            'pre_defined': pre_defined,
            'handler_type': handler_type.decode('utf-8'),
            'reserved': reserved.decode('utf-8'),
            'name': name
        }

    def parse_idat(self, data):
        return {
            'data': data
        }

    def parse_ilst(self, data):
        """
        Parse the 'ilst' box, which is an iTunes-style metadata container.
        It contains multiple sub-items, each representing a specific metadata entry.
        """
        ilst_info = []
        offset = 0
        
        while offset + 8 <= len(data):
            # Each metadata item (sub-box) has: [size: 4 bytes], [type: 4 bytes]
            size, raw_type = struct.unpack_from('>I4s', data, offset)
            if size < 8:
                # Invalid size; break to avoid infinite loops
                break
            
            item_data = data[offset + 8 : offset + size]
            offset += size
            
            # Decode the box type
            try:
                item_type = raw_type.decode('utf-8')
            except UnicodeDecodeError:
                item_type = f"0x{int.from_bytes(raw_type, 'big'):08X}"
            
            # Parse subatoms (like 'data', 'mean', 'name', etc.) inside this item
            subatoms = self.parse_ilst_subatoms(item_data)
            
            ilst_info.append({
                'type': item_type,
                'subatoms': subatoms
            })
        
        return ilst_info

    def parse_ilst_subatoms(self, data):
        """
        Parse subatoms inside each iTunes metadata item.
        Common subatoms are 'data', 'mean', 'name', etc.
        Each has its own structure, but typically:
          [size: 4 bytes], [type: 4 bytes], [content...]
        """
        results = []
        offset = 0
        
        while offset + 8 <= len(data):
            sub_size, sub_type = struct.unpack_from('>I4s', data, offset)
            if sub_size < 8:
                break
            
            sub_data = data[offset + 8 : offset + sub_size]
            offset += sub_size
            
            # Decode the subatom type
            try:
                sub_type_str = sub_type.decode('utf-8')
            except UnicodeDecodeError:
                sub_type_str = f"0x{int.from_bytes(sub_type, 'big'):08X}"
            
            # 'data' sub-box usually contains the actual payload (text, binary, etc.)
            if sub_type_str == 'data':
                parsed = self.parse_data_box(sub_data)
                results.append(parsed)
            # 'mean' and 'name' sub-boxes often contain text strings describing metadata
            elif sub_type_str == 'mean':
                parsed = self.parse_mean_name_box(sub_data, box_label='mean')
                results.append(parsed)
            elif sub_type_str == 'name':
                parsed = self.parse_mean_name_box(sub_data, box_label='name')
                results.append(parsed)
            else:
                # If it's not one of the known sub-box types, store it as raw
                results.append({
                    'size': sub_size,
                    'type': sub_type_str,
                    'raw_data': sub_data
                })
        
        return results

    def parse_mean_name_box(self, data, box_label='mean'):
        """
        Parse 'mean' or 'name' sub-boxes used in iTunes metadata.
        Typically the structure is:
          [version: 1 byte] [flags: 3 bytes] [text data...]
        """
        if len(data) < 4:
            return {
                'type': box_label,
                'error': 'Insufficient data for mean/name header',
                'raw_data': data
            }
        
        version = data[0]
        flags = data[1:4]
        text_payload = data[4:]
        
        # Attempt to decode the text payload as UTF-8, fallback to ISO-8859-1
        try:
            text_value = text_payload.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            text_value = text_payload.decode('iso-8859-1', errors='replace').rstrip('\x00')
        
        return {
            'type': box_label,
            'version': version,
            'flags': flags,
            'value': text_value
        }

    def parse_data_box(self, data):
        """
        Parse the 'data' sub-box which holds the actual metadata content.
        Common structure:
          [data_type: 4 bytes], [locale: 4 bytes], [payload...]
        
        Known data_type values (commonly used in iTunes metadata):
          0x0  => Unknown/Reserved
          0x1  => UTF-8 text
          0x2  => UTF-16 text (some references)
          0xD  => JPEG image
          0xE  => PNG image
          0x15 => Signed integer (BE)
          ...   and there are more variants depending on usage
        """
        if len(data) < 8:
            return {
                'type': 'data',
                'error': 'Insufficient data for data box header',
                'raw_data': data
            }
        
        data_type_int = struct.unpack('>I', data[0:4])[0]
        data_locale_int = struct.unpack('>I', data[4:8])[0]
        payload = data[8:]
        
        # Handle known data types
        if data_type_int == 1:
            # UTF-8 text
            try:
                text_value = payload.decode('utf-8').rstrip('\x00')
            except UnicodeDecodeError:
                text_value = payload.decode('iso-8859-1', errors='replace').rstrip('\x00')
            
            return {
                'type': 'data',
                'data_type': data_type_int,
                'locale': data_locale_int,
                'value': text_value
            }
        elif data_type_int == 0xD:
            # 0xD (13) might represent JPEG image data in some iTunes tags
            return {
                'type': 'data',
                'data_type': data_type_int,
                'locale': data_locale_int,
                'format': 'JPEG',
                'binary_length': len(payload)
            }
        elif data_type_int == 0xE:
            # 0xE (14) might represent PNG image data
            return {
                'type': 'data',
                'data_type': data_type_int,
                'locale': data_locale_int,
                'format': 'PNG',
                'binary_length': len(payload)
            }
        elif data_type_int == 0x15:
            # 0x15 (21) could represent a signed integer (big-endian)
            # For example, if the payload is 1~8 bytes, we can parse it as an integer
            int_val = None
            if 1 <= len(payload) <= 8:
                # Convert big-endian payload to int
                int_val = int.from_bytes(payload, byteorder='big', signed=True)
            
            return {
                'type': 'data',
                'data_type': data_type_int,
                'locale': data_locale_int,
                'signed_int_value': int_val,
                'raw_bytes': payload
            }
        else:
            # If the data_type is not recognized, return raw payload
            return {
                'type': 'data',
                'data_type': data_type_int,
                'locale': data_locale_int,
                'payload': payload
            }

    def parse_dinf(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        dref_size, dref_type = struct.unpack_from('>I4s', data, offset)
        dref_data = data[offset + 8:offset + dref_size]
        dref = self.parse_dref(dref_data)

        return {
            'version': version,
            'flags': flags,
            'dref': dref
        }

    def parse_dref(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            size, type = struct.unpack_from('>I4s', data, offset)
            entry_data = data[offset + 8:offset + size]
            entry = {
                'size': size,
                'type': type.decode('utf-8'),
                'data': entry_data
            }
            entries.append(entry)
            offset += size

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_url(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        location = data[4:].decode('utf-8') if flags == b'\x00\x00\x01' else None

        return {
            'version': version,
            'flags': flags,
            'location': location
        }

    def parse_pitm(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4

        if version == 0:
            item_id = struct.unpack_from('>H', data, offset)[0]
            offset += 2
        else:
            item_id = struct.unpack_from('>I', data, offset)[0]
            offset += 4

        return {
            'version': version,
            'flags': flags,
            'item_id': item_id
        }

    def parse_iinf(self, data):
        version, flags, entry_count = struct.unpack('>B3sH', data[:6])
        offset = 6
        items = []

        for _ in range(entry_count):
            infe_size, infe_type = struct.unpack_from('>I4s', data, offset)
            infe_data = data[offset + 8:offset + infe_size]
            infe = self.parse_infe(infe_data)
            items.append(infe)
            offset += infe_size

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'items': items
        }

    def parse_infe(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        infe = {
            'version': version,
            'flags': flags
        }

        if version == 0:
            item_id, item_protection_index = struct.unpack_from('>HH', data, offset)
            offset += 4
            infe['item_id'] = item_id
            infe['item_protection_index'] = item_protection_index

        elif version in [1, 2]:
            item_id, item_protection_index, item_type = struct.unpack_from('>H2s4s', data, offset)
            offset += 8
            infe['item_id'] = item_id
            infe['item_protection_index'] = item_protection_index
            infe['item_type'] = item_type.decode('utf-8')

        elif version >= 2:
            item_id, item_protection_index, item_type = struct.unpack_from('>I2H4s', data, offset)
            offset += 12
            infe['item_id'] = item_id
            infe['item_protection_index'] = item_protection_index
            infe['item_type'] = item_type.decode('utf-8')

        # is there remainder?
        if offset < len(data):
            item_name_end = data.find(b'\x00', offset)
            if item_name_end != -1:
                infe['item_name'] = data[offset:item_name_end].decode('utf-8')
                offset = item_name_end + 1
            content_type_end = data.find(b'\x00', offset)
            if content_type_end != -1:
                infe['content_type'] = data[offset:content_type_end].decode('utf-8')
                offset = content_type_end + 1
            content_encoding_end = data.find(b'\x00', offset)
            if content_encoding_end != -1:
                infe['content_encoding'] = data[offset:content_encoding_end].decode('utf-8')

        return infe

    def parse_iref(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        iref = {
            'version': version,
            'flags': flags,
            'references': []
        }

        while offset < len(data):
            size, atom_type = struct.unpack_from('>I4s', data, offset)
            atom_type = atom_type.decode('utf-8')
            offset += 8

            reference_list = []
            if version == 0:
                from_item_id, reference_count = struct.unpack_from('>HH', data, offset)
                offset += 4
                for _ in range(reference_count):
                    to_item_id, = struct.unpack_from('>H', data, offset)
                    offset += 2
                    reference_list.append(to_item_id)
            elif version == 1:
                from_item_id, reference_count = struct.unpack_from('>I4s', data, offset)
                offset += 8
                for _ in range(reference_count):
                    to_item_id, = struct.unpack_from('>I', data, offset)
                    offset += 4
                    reference_list.append(to_item_id)

            iref['references'].append({
                'type': atom_type,
                'from_item_id': from_item_id,
                'reference_list': reference_list
            })

        return iref

    def parse_dimg(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        dimg = {
            'version': version,
            'flags': flags,
            'item_references': []
        }

        item_id, reference_count = struct.unpack_from('>H2s', data, offset)
        offset += 4
        dimg['item_id'] = item_id

        for _ in range(reference_count):
            ref_item_id, = struct.unpack_from('>H', data, offset)
            offset += 2
            dimg['item_references'].append(ref_item_id)

        return dimg

    def parse_ipco(self, data):
        offset = 0
        ipco = {
            'properties': []
        }

        while offset < len(data):
            size, atom_type = struct.unpack_from('>I4s', data, offset)
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset + 8:offset + size]
            offset += size

            if atom_type == 'colr':
                ipco['properties'].append(self.parse_colr(atom_data))
            elif atom_type == 'hvcC':
                ipco['properties'].append(self.parse_hvcC(atom_data))
            elif atom_type == 'ispe':
                ipco['properties'].append(self.parse_ispe(atom_data))
            elif atom_type == 'irot':
                ipco['properties'].append(self.parse_irot(atom_data))
            elif atom_type == 'pixi':
                ipco['properties'].append(self.parse_pixi(atom_data))
            elif atom_type == 'auxC':
                ipco['properties'].append(self.parse_auxC(atom_data))
            else:
                ipco['properties'].append({
                    'type': atom_type,
                    'data': atom_data
                })

        return ipco

    def parse_iloc(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        offset_size_field, reserved = struct.unpack_from('>BB', data, offset)
        offset += 2

        offset_size = (offset_size_field >> 4) & 0xF
        length_size = offset_size_field & 0xF
        base_offset_size = (reserved >> 4) & 0xF  # Typically not used, just for clarity
        index_size = reserved & 0xF  # Typically not used, just for clarity

        item_count_size = 2 if version < 2 else 4
        item_count = struct.unpack_from(f'>{item_count_size}s', data, offset)[0]
        item_count = int.from_bytes(item_count, 'big')
        offset += item_count_size

        items = []

        for _ in range(item_count):
            item_id_size = 2 if version < 2 else 4
            item_id = struct.unpack_from(f'>{item_id_size}s', data, offset)[0]
            item_id = int.from_bytes(item_id, 'big')
            offset += item_id_size

            if version == 1 or version == 2:
                construction_method = struct.unpack_from('>H', data, offset)[0]
                offset += 2
            else:
                construction_method = 0

            data_reference_index = struct.unpack_from('>H', data, offset)[0]
            offset += 2

            base_offset = struct.unpack_from(f'>{base_offset_size}s', data, offset)[0]
            base_offset = int.from_bytes(base_offset, 'big')
            offset += base_offset_size

            extent_count = struct.unpack_from('>H', data, offset)[0]
            offset += 2

            extents = {}

            for _ in range(extent_count):
                extent_index = 0
                if version == 1 or version == 2:
                    extent_index = struct.unpack_from(f'>{index_size}s', data, offset)[0]
                    extent_index = int.from_bytes(extent_index, 'big')
                    offset += index_size

                extent_offset = struct.unpack_from(f'>{offset_size}s', data, offset)[0]
                extent_offset = int.from_bytes(extent_offset, 'big')
                offset += offset_size

                extent_length = struct.unpack_from(f'>{length_size}s', data, offset)[0]
                extent_length = int.from_bytes(extent_length, 'big')
                offset += length_size

                extents['extent_index'] = extent_index
                extents['extent_offset'] = extent_offset
                extents['extent_length'] = extent_length

            items.append({
                'item_id': item_id,
                'construction_method': construction_method,
                'data_reference_index': data_reference_index,
                'base_offset': base_offset,
                'extents': extents
            })

        return {
            'version': version,
            'flags': flags,
            'length_size': length_size,
            'offset_size': offset_size,
            'item_count': item_count,
            'items': items
        }

    def parse_tfhd(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        track_id = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        tfhd = {
            'version': version,
            'flags': flags,
            'track_id': track_id
        }

        if flags & 0x01:
            tfhd['base_data_offset'] = struct.unpack_from('>Q', data, offset)[0]
            offset += 8
        if flags & 0x02:
            tfhd['sample_description_index'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        if flags & 0x08:
            tfhd['default_sample_duration'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        if flags & 0x10:
            tfhd['default_sample_size'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        if flags & 0x20:
            tfhd['default_sample_flags'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4

        return tfhd

    def parse_tfdt(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        base_media_decode_time = struct.unpack_from('>Q', data, offset)[0] if version == 1 else struct.unpack_from('>I', data, offset)[0]
        offset += 8 if version == 1 else 4

        return {
            'version': version,
            'flags': flags,
            'base_media_decode_time': base_media_decode_time
        }

    def parse_trun(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        sample_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        trun = {
            'version': version,
            'flags': flags,
            'sample_count': sample_count,
            'samples': []
        }

        if flags & 0x01:
            trun['data_offset'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        if flags & 0x04:
            trun['first_sample_flags'] = struct.unpack_from('>I', data, offset)[0]
            offset += 4

        for _ in range(sample_count):
            sample = {}
            if flags & 0x100:
                sample['sample_duration'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4
            if flags & 0x200:
                sample['sample_size'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4
            if flags & 0x400:
                sample['sample_flags'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4
            if flags & 0x800:
                sample['sample_composition_time_offset'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4

            trun['samples'].append(sample)

        return trun

    def parse_sbgp(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        grouping_type = struct.unpack_from('>4s', data, offset)[0].decode('utf-8')
        offset += 4

        if version == 1:
            grouping_type_parameter = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        else:
            grouping_type_parameter = None

        entry_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        entries = []
        for _ in range(entry_count):
            sample_count = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            group_description_index = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            entries.append({
                'sample_count': sample_count,
                'group_description_index': group_description_index
            })

        return {
            'version': version,
            'flags': flags,
            'grouping_type': grouping_type,
            'grouping_type_parameter': grouping_type_parameter,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_sgpd(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        grouping_type = struct.unpack_from('>4s', data, offset)[0].decode('utf-8')
        offset += 4

        if version == 1 or version == 2:
            default_length = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        else:
            default_length = None

        if version == 2:
            default_sample_description_index = struct.unpack_from('>I', data, offset)[0]
            offset += 4
        else:
            default_sample_description_index = None

        entry_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        entries = []
        for _ in range(entry_count):
            if version == 1 or version == 2:
                description_length = struct.unpack_from('>I', data, offset)[0] if default_length is None else default_length
                offset += 4 if default_length is None else 0
            else:
                description_length = None

            entry = {
                'description_length': description_length,
                'description_data': data[offset:offset + description_length] if description_length else None
            }
            offset += description_length if description_length else 0

            entries.append(entry)

        return {
            'version': version,
            'flags': flags,
            'grouping_type': grouping_type,
            'default_length': default_length,
            'default_sample_description_index': default_sample_description_index,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_subs(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        entry_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        entries = []
        for _ in range(entry_count):
            sample_delta = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            subsample_count = struct.unpack_from('>H', data, offset)[0]
            offset += 2

            subsamples = []
            for _ in range(subsample_count):
                subsample_size = struct.unpack_from('>H', data, offset)[0]
                offset += 2
                subsample_priority = struct.unpack_from('>B', data, offset)[0]
                offset += 1
                discardable = struct.unpack_from('>B', data, offset)[0]
                offset += 1
                reserved = struct.unpack_from('>I', data, offset)[0]
                offset += 4
                subsamples.append({
                    'subsample_size': subsample_size,
                    'subsample_priority': subsample_priority,
                    'discardable': discardable,
                    'reserved': reserved
                })

            entries.append({
                'sample_delta': sample_delta,
                'subsample_count': subsample_count,
                'subsamples': subsamples
            })

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_saiz(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        aux_info_type = struct.unpack_from('>4s', data, offset)[0] if version == 1 else None
        aux_info_type_parameter = struct.unpack_from('>I', data, offset + 4)[0] if version == 1 else None
        offset += 8 if version == 1 else 0

        default_sample_info_size = struct.unpack_from('>B', data, offset)[0]
        offset += 1

        sample_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        sample_info_sizes = []
        if default_sample_info_size == 0:
            for _ in range(sample_count):
                sample_info_size = struct.unpack_from('>B', data, offset)[0]
                offset += 1
                sample_info_sizes.append(sample_info_size)

        return {
            'version': version,
            'flags': flags,
            'aux_info_type': aux_info_type,
            'aux_info_type_parameter': aux_info_type_parameter,
            'default_sample_info_size': default_sample_info_size,
            'sample_count': sample_count,
            'sample_info_sizes': sample_info_sizes
        }

    def parse_saio(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        aux_info_type = struct.unpack_from('>4s', data, offset)[0] if version == 1 else None
        aux_info_type_parameter = struct.unpack_from('>I', data, offset + 4)[0] if version == 1 else None
        offset += 8 if version == 1 else 0

        entry_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        offsets = []
        for _ in range(entry_count):
            if version == 0:
                offset_value = struct.unpack_from('>I', data, offset)[0]
                offset += 4
            else:
                offset_value = struct.unpack_from('>Q', data, offset)[0]
                offset += 8
            offsets.append(offset_value)

        return {
            'version': version,
            'flags': flags,
            'aux_info_type': aux_info_type,
            'aux_info_type_parameter': aux_info_type_parameter,
            'entry_count': entry_count,
            'offsets': offsets
        }

    def parse_uuid(self, data):
        offset = 0
        user_type = struct.unpack_from('>16s', data, offset)[0]
        offset += 16

        uuid_data = data[offset:]

        return {
            'user_type': user_type,
            'data': uuid_data
        }

    def parse_ispe(self, data):
        ispe = {}
        ispe['image_width'], ispe['image_height'] = struct.unpack_from('>II', data)
        ispe['type'] = 'ispe'
        return ispe

    def parse_irot(self, data):
        irot = {}
        irot['rotation'] = struct.unpack_from('>B', data)[0] & 0x03
        irot['type'] = 'irot'
        return irot

    def parse_pixi(self, data):
        pixi = {}
        num_channels = struct.unpack_from('>B', data)[0]
        pixi['num_channels'] = num_channels
        pixi['bits_per_channel'] = struct.unpack_from(f'>{num_channels}B', data, 1)
        pixi['type'] = 'pixi'
        return pixi

    def parse_auxC(self, data):
        auxc = {}
        auxc['aux_type'] = data.decode('utf-8').rstrip('\x00')
        auxc['type'] = 'auxc'
        return auxc

    def parse_iprp(self, data):
        offset = 0
        iprp = {
            'boxes': []
        }

        while offset < len(data):
            size, atom_type = struct.unpack_from('>I4s', data, offset)
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset + 8:offset + size]
            offset += size

            if atom_type == 'ipco':
                iprp['boxes'].append(self.parse_ipco(atom_data))
            elif atom_type == 'ipma':
                iprp['boxes'].append(self.parse_ipma(atom_data))
            else:
                iprp['boxes'].append({
                    'type': atom_type,
                    'data': atom_data
                })

        return iprp

    def parse_ipma(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        offset = 4
        ipma = {
            'version': version,
            'flags': flags,
            'entries': []
        }

        entry_count, = struct.unpack_from('>H', data, offset)
        offset += 2

        for _ in range(entry_count):
            item_id, association_count = struct.unpack_from('>HH', data, offset)
            offset += 4

            associations = []
            for _ in range(association_count):
                if version == 0 or version == 1:
                    property_index = struct.unpack_from('>H', data, offset)[0]
                    essential = (property_index & 0x8000) >> 15
                    property_index &= 0x7FFF
                    offset += 2
                elif version == 2:
                    property_index = struct.unpack_from('>I', data, offset)[0]
                    essential = (property_index & 0x80000000) >> 31
                    property_index &= 0x7FFFFFFF
                    offset += 4

                associations.append({
                    'essential': essential,
                    'property_index': property_index
                })

            ipma['entries'].append({
                'item_id': item_id,
                'associations': associations
            })

        ipma['type'] = 'ipma'

        return ipma


    def parse_vmhd(self, data):

        if len(data) < 12:
            raise ValueError("Insufficient data for vmhd")

        (version, flags, graphics_mode, red, green, blue) = struct.unpack('>B3sHHHH', data[:12])
        opcolor = [red, green, blue]

        return {
            'version': version,
            'flags': flags,
            'graphics_mode': graphics_mode,
            'opcolor': opcolor
        }

    def parse_smhd(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        balance = struct.unpack('>h', data[4:6])[0]
        reserved = struct.unpack('>H', data[6:8])[0]

        return {
            'version': version,
            'flags': flags,
            'balance': self.fp16_to_float(balance),
            'reserved': reserved
        }
    def parse_dinf(self, data):
        offset = 0
        dref = None
        while offset < len(data):
            size, atom_type = struct.unpack('>I4s', data[offset:offset+8])
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset+8:offset+size]
            if atom_type == 'dref':
               dref = self.parse_dref(atom_data)
            offset += size
        return {
            'dref': dref
        }

    def parse_stbl(self, data):
        offset = 0
        while offset < len(data):
            size, atom_type = struct.unpack('>I4s', data[offset:offset+8])
            atom_type = atom_type.decode('utf-8')
            atom_data = data[offset+8:offset+size]
            if atom_type == 'stsd':
                self.parse_stsd(atom_data)
            elif atom_type == 'stts':
                self.parse_stts(atom_data)
            elif atom_type == 'stss':
                self.parse_stss(atom_data)
            elif atom_type == 'ctts':
                self.parse_ctts(atom_data)
            elif atom_type == 'stsc':
                self.parse_stsc(atom_data)
            elif atom_type == 'stsz':
                self.parse_stsz(atom_data)
            elif atom_type == 'stco':
                self.parse_stco(atom_data)
            offset += size

    def parse_stsd(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            entry_size, entry_type = struct.unpack('>I4s', data[offset:offset + 8])
            entry_data = data[offset + 8:offset + entry_size]
            parsed_entry = self.parse_sample_description(entry_type.decode('utf-8'), entry_data)
            parsed_entry['type'] = entry_type.decode('utf-8')
            entries.append(parsed_entry)
            offset += entry_size

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }
    def parse_stsc(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            first_chunk, samples_per_chunk, sample_description_index = struct.unpack('>III', data[offset:offset + 12])
            entries.append({
                'first_chunk': first_chunk,
                'samples_per_chunk': samples_per_chunk,
                'sample_description_index': sample_description_index
            })
            offset += 12

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_stsz(self, data):
        version, flags, sample_size, sample_count = struct.unpack('>B3sII', data[:12])
        offset = 12
        entries = []

        if sample_size == 0:
            for _ in range(sample_count):
                entry_size = struct.unpack('>I', data[offset:offset + 4])[0]
                entries.append(entry_size)
                offset += 4

        return {
            'version': version,
            'flags': flags,
            'sample_size': sample_size,
            'sample_count': sample_count,
            'entries': entries if sample_size == 0 else []
        }

    def parse_stco(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            chunk_offset = struct.unpack('>I', data[offset:offset + 4])[0]
            entries.append(chunk_offset)
            offset += 4

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_ctts(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            sample_count, sample_offset = struct.unpack('>II', data[offset:offset + 8])
            entries.append({
                'sample_count': sample_count,
                'sample_offset': sample_offset
            })
            offset += 8

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_sgpd(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        grouping_type = struct.unpack('>4s', data[4:8])[0].decode('utf-8')
        if version == 1:
            default_length = struct.unpack('>I', data[8:12])[0]
            description_count = struct.unpack('>I', data[12:16])[0]
            offset = 16
        else:
            default_length = None
            description_count = struct.unpack('>I', data[8:12])[0]
            offset = 12

        descriptions = []
        for _ in range(description_count):
            if default_length:
                description_length = default_length
            else:
                description_length = struct.unpack('>I', data[offset:offset + 4])[0]
                offset += 4
            description_data = data[offset:offset + description_length]
            descriptions.append(description_data)
            offset += description_length

        return {
            'version': version,
            'flags': flags,
            'grouping_type': grouping_type,
            'default_length': default_length,
            'description_count': description_count,
            'descriptions': descriptions
        }

    def parse_sbgp(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        grouping_type = struct.unpack('>4s', data[4:8])[0].decode('utf-8')
        entry_count = struct.unpack('>I', data[8:12])[0]

        entries = []
        offset = 12
        for _ in range(entry_count):
            sample_count, group_description_index = struct.unpack('>II', data[offset:offset + 8])
            entries.append({
                'sample_count': sample_count,
                'group_description_index': group_description_index
            })
            offset += 8

        return {
            'version': version,
            'flags': flags,
            'grouping_type': grouping_type,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_elst(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        entries = []
        offset = 8
        if version == 0:
            for _ in range(entry_count):
                segment_duration, media_time, media_rate = struct.unpack('>III', data[offset:offset+12])
                entries.append({
                    'segment_duration': segment_duration,
                    'media_time': media_time,
                    'media_rate': self.fp32_to_float(media_rate)
                })
                offset += 12
        if version == 1:
            for _ in range(entry_count):
                segment_duration, media_time, media_rate = struct.unpack('>QQI', data[offset:offset+22])
                entries.append({
                    'segment_duration': segment_duration,
                    'media_time': media_time,
                    'media_rate': self.fp32_to_float(media_rate)
                })
                offset += 22
        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }


    def parse_mehd(self, data):
        version, flags = struct.unpack_from('>B3s', data, 0)
        offset = 4

        if version == 1:
            fragment_duration = struct.unpack_from('>Q', data, offset)[0]
        else:
            fragment_duration = struct.unpack_from('>I', data, offset)[0]

        return {
            'version': version,
            'flags': flags,
            'fragment_duration': fragment_duration
        }

    def parse_trex(self, data):
        version, flags, track_id, default_sample_description_index, default_sample_duration, default_sample_size, default_sample_flags = struct.unpack('>B3sIIIII', data)
        return {
            'version': version,
            'flags': flags,
            'track_id': track_id,
            'default_sample_description_index': default_sample_description_index,
            'default_sample_duration': default_sample_duration,
            'default_sample_size': default_sample_size,
            'default_sample_flags': default_sample_flags
        }

    def parse_leva(self, data):
        (version, flags, event_count) = struct.unpack_from('>B3sI', data, 0)
        offset = 8

        events = []
        for _ in range(event_count):
            segment_duration, media_time, media_rate_integer, media_rate_fraction = struct.unpack_from('>Iiqh', data, offset)
            offset += 14
            events.append({
                'segment_duration': segment_duration,
                'media_time': media_time,
                'media_rate_integer': media_rate_integer,
                'media_rate_fraction': media_rate_fraction
            })

        return {
            'version': version,
            'flags': flags,
            'event_count': event_count,
            'events': events
        }


    def parse_mfhd(self, data):
        version, flags, sequence_number = struct.unpack('>B3sI', data)
        return {
            'version': version,
            'flags': flags,
            'sequence_number': sequence_number
        }

    def parse_trun(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        flags = int.from_bytes(flags, byteorder='big')
        offset += 4

        sample_count = struct.unpack_from('>I', data, offset)[0]
        offset += 4

        trun_box = {
            'version': version,
            'flags': flags,
            'sample_count': sample_count,
            'samples': []
        }

        if flags & 0x000001:  # data-offset-present flag
            data_offset = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            trun_box['data_offset'] = data_offset

        if flags & 0x000004:  # first-sample-flags-present flag
            first_sample_flags = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            trun_box['first_sample_flags'] = first_sample_flags

        for _ in range(sample_count):
            sample = {}

            if flags & 0x000100:  # sample-duration-present flag
                sample['sample_duration'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4

            if flags & 0x000200:  # sample-size-present flag
                sample['sample_size'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4

            if flags & 0x000400:  # sample-flags-present flag
                sample['sample_flags'] = struct.unpack_from('>I', data, offset)[0]
                offset += 4

            if flags & 0x000800:  # sample-composition-time-offset-present flag
                sample['sample_composition_time_offset'] = struct.unpack_from('>i', data, offset)[0]
                offset += 4

            trun_box['samples'].append(sample)

        return trun_box

    def parse_mdat(self, data):
        return {
            'data': data
        }

    def parse_edts(self, data):
        offset = 0
        while offset < len(data):
            size, atom_type = struct.unpack('>I4s', data[offset:offset + 8])
            try:
                atom_type = atom_type.decode('utf-8')
            except UnicodeDecodeError:
                atom_type = atom_type.decode('iso-8859-1')
            atom_data = data[offset + 8:offset + size]
            if atom_type == 'elst':
                self.parse_elst(atom_data)
            offset += size

    def parse_iods(self, data):
        version, flags, OD_profile, scene_profile, audio_profile, visual_profile, graphics_profile = struct.unpack(
            '>B3sBBBBB', data[:8])
        return {
            'version': version,
            'flags': flags,
            'OD_profile': OD_profile,
            'scene_profile': scene_profile,
            'audio_profile': audio_profile,
            'visual_profile': visual_profile,
            'graphics_profile': graphics_profile
        }

    def parse_pasp(self, data):
        h_spacing, v_spacing = struct.unpack('>II', data)
        return {
            'h_spacing': h_spacing,
            'v_spacing': v_spacing
        }

    def parse_frma(self, data):
        data_format = data[:4].decode('utf-8')
        return {
            'data_format': data_format
        }

    def parse_mfhd(self, data):
        version, flags, sequence_number = struct.unpack('>B3sI', data[:8])
        return {
            'version': version,
            'flags': flags,
            'sequence_number': sequence_number
        }


    def parse_sidx(self, data):
        offset = 0
        version, flags = struct.unpack_from('>B3s', data, offset)
        offset += 4

        reference_ID, timescale = struct.unpack_from('>II', data, offset)
        offset += 8

        if version == 1:
            earliest_presentation_time = struct.unpack_from('>Q', data, offset)[0]
            offset += 8
            first_offset = struct.unpack_from('>Q', data, offset)[0]
            offset += 8
        else:
            earliest_presentation_time = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            first_offset = struct.unpack_from('>I', data, offset)[0]
            offset += 4

        reserved = data[offset:offset + 2]
        offset += 2

        reference_count = struct.unpack_from('>H', data, offset)[0]
        offset += 2

        entries = []

        for _ in range(reference_count):
            reference_info = struct.unpack_from('>I', data, offset)[0]
            reference_type = reference_info >> 31
            referenced_size = reference_info & 0x7FFFFFFF
            offset += 4

            subsegment_duration = struct.unpack_from('>I', data, offset)[0]
            offset += 4

            sap_info = struct.unpack_from('>I', data, offset)[0]
            starts_with_SAP = sap_info >> 31
            SAP_type = (sap_info >> 28) & 0x7
            SAP_delta_time = sap_info & 0x0FFFFFFF
            offset += 4

            entries.append({
                'reference_type': reference_type,
                'referenced_size': referenced_size,
                'subsegment_duration': subsegment_duration,
                'starts_with_SAP': starts_with_SAP,
                'SAP_type': SAP_type,
                'SAP_delta_time': SAP_delta_time
            })

        return {
            'version': version,
            'flags': flags,
            'reference_ID': reference_ID,
            'timescale': timescale,
            'earliest_presentation_time': earliest_presentation_time,
            'first_offset': first_offset,
            'reference_count': reference_count,
            'entries': entries
        }
    def parse_saiz(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        aux_info_type, aux_info_type_parameter = struct.unpack('>II', data[4:12]) if version == 1 else (None, None)
        default_sample_info_size, sample_count = struct.unpack('>BH', data[12:15])
        entries = [struct.unpack('>B', data[i:i + 1])[0] for i in range(15, 15 + sample_count)]
        return {
            'version': version,
            'flags': flags,
            'aux_info_type': aux_info_type,
            'aux_info_type_parameter': aux_info_type_parameter,
            'default_sample_info_size': default_sample_info_size,
            'sample_count': sample_count,
            'entries': entries
        }

    def parse_saio(self, data):
        version, flags = struct.unpack('>B3s', data[:4])
        aux_info_type, aux_info_type_parameter = struct.unpack('>II', data[4:12]) if version == 1 else (None, None)
        entry_count = struct.unpack('>I', data[12:16])[0]
        entries = [struct.unpack('>Q', data[i:i + 8])[0] if version == 1 else struct.unpack('>I', data[i:i + 4])[0] for
                   i in range(16, 16 + entry_count * (8 if version == 1 else 4))]
        return {
            'version': version,
            'flags': flags,
            'aux_info_type': aux_info_type,
            'aux_info_type_parameter': aux_info_type_parameter,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_senc(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        entries = []
        offset = 8
        for _ in range(entry_count):
            initialization_vector = data[offset:offset + 8]
            subsample_count = struct.unpack('>H', data[offset + 8:offset + 10])[0] if flags & 0x2 else 0
            subsamples = []
            offset += 10
            for _ in range(subsample_count):
                clear_bytes, encrypted_bytes = struct.unpack('>HH', data[offset:offset + 4])
                subsamples.append({'clear_bytes': clear_bytes, 'encrypted_bytes': encrypted_bytes})
                offset += 4
            entries.append({
                'initialization_vector': initialization_vector,
                'subsample_count': subsample_count,
                'subsamples': subsamples
            })
        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_pssh(self, data):
        version, flags, system_id = struct.unpack('>B3s16s', data[:20])
        data_size = struct.unpack('>I', data[20:24])[0]
        pssh_data = data[24:24 + data_size]
        return {
            'version': version,
            'flags': flags,
            'system_id': system_id,
            'data_size': data_size,
            'pssh_data': pssh_data
        }

    def parse_stss(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            sample_number = struct.unpack('>I', data[offset:offset + 4])[0]
            entries.append(sample_number)
            offset += 4

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_stts(self, data):
        version, flags, entry_count = struct.unpack('>B3sI', data[:8])
        offset = 8
        entries = []

        for _ in range(entry_count):
            sample_count, sample_delta = struct.unpack('>II', data[offset:offset + 8])
            entries.append({
                'sample_count': sample_count,
                'sample_delta': sample_delta
            })
            offset += 8

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_co64(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        entry_count = struct.unpack('>I', data[4:8])[0]
        offsets = struct.unpack(f'>{entry_count}Q', data[8:8 + entry_count * 8])

        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'offsets': offsets
        }

    def parse_clef(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        width, height = struct.unpack('>II', data[4:12])
        return {
            'version': version,
            'flags': flags,
            'width': width,
            'height': height
        }

    def parse_prof(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        width, height = struct.unpack('>II', data[4:12])
        return {
            'version': version,
            'flags': flags,
            'width': width,
            'height': height
        }

    def parse_enof(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        width, height = struct.unpack('>II', data[4:12])
        return {
            'version': version,
            'flags': flags,
            'width': width,
            'height': height
        }

    def parse_keys(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        entry_count = struct.unpack('>I', data[4:8])[0]
        offset = 8
        
        entries = []
        
        for _ in range(entry_count):
            if offset + 8 > len(data):
                break
            
            box_size, box_type = struct.unpack('>I4s', data[offset:offset+8])
            offset += 8
            
            try:
                box_type = box_type.decode('utf-8')
            except UnicodeDecodeError:
                box_type = box_type.decode('iso-8859-1', errors='replace')
            
            if box_size < 8 or offset + (box_size - 8) > len(data):
                break
            
            box_data = data[offset:offset + (box_size - 8)]
            offset += (box_size - 8)
            
            if box_type == 'mdta':
                parsed_mdta = self.parse_mdta(box_data)
                entries.append(parsed_mdta)
            else:
                entries.append({
                    'type': box_type,
                    'data': box_data
                })
        
        return {
            'version': version,
            'flags': flags,
            'entry_count': entry_count,
            'entries': entries
        }

    def parse_mdta(self, data):
        try:
            text = data.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            text = data.decode('iso-8859-1', errors='replace').rstrip('\x00')
        except Exception:
            text = data
        
        return {
            'value': text
        }

    def parse_SDLN(self, data):

        text = data.decode('utf-8', errors='replace').rstrip('\x00')
        return {
            'value': text
        }

    def parse_smrd(self, data):
        text = data.decode('utf-8', errors='replace').rstrip('\x00')
        return {
            'value': text
        }

    def parse_auth(self, data):
        text = data.decode('utf-8', errors='replace').rstrip('\x00')
        return {
            'value': text
        }

    def parse_smta(self, data):
        version = data[0]
        flags = struct.unpack('>3s', data[1:4])[0]
        try:
            saut_size = struct.unpack('>I', data[4:8])[0] - 8
            saut = self.parse_saut(data[8+4:8+4+saut_size])
        except Exception:
            saut = None
        try:
            mdln_size = struct.unpack('>I', data[8+4+saut_size: 8+4+saut_size+4])[0] - 8
            mdln = self.parse_mdln(data[8+4+saut_size+4+4: 8+4+saut_size+4+4+mdln_size])
        except Exception:
            mdln = None
        return {
            'version': version,
            'flags': flags,
            'saut': saut,
            'mdln': mdln
        }

    def parse_saut(self, data):
        text = data.decode('utf-8', errors='replace').rstrip('\x00')
        return {
            'value': text
        }

    def parse_mdln(self, data):
        text = data.decode('utf-8', errors='replace').rstrip('\x00')
        return {
            'value': text
        }


    def parse_free(self, data):
        return {
            'data': data
        }

    def parse_skip(self, data):
        return {
            'data': data
        }

    def parse_audio(self, data):
        pass