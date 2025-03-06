import re
import math
import struct
import numpy as np
from bitstring import BitStream, ReadError

NAL_UNIT_TYPES = {
    0: "Trail_N",
    1: "Trail_R",
    2: "TSA_N",
    3: "TSA_R",
    4: "STSA_N",
    5: "STSA_R",
    6: "RADL_N",
    7: "RADL_R",
    8: "RASL_N",
    9: "RASL_R",
    16: "BLA_W_LP",
    17: "BLA_W_RADL",
    18: "BLA_N_LP",
    19: "IDR_W_RADL",
    20: "IDR_N_LP",
    21: "CRA_NUT",
    22: "RSV_IRAP_VCL22",
    23: "RSV_IRAP_VCL23",
    24: "RSV_VCL24",
    25: "RSV_VCL25",
    26: "RSV_VCL26",
    27: "RSV_VCL27",
    28: "RSV_VCL28",
    29: "RSV_VCL29",
    30: "RSV_VCL30",
    31: "RSV_VCL31",
    32: "VPS_NUT",
    33: "SPS_NUT",
    34: "PPS_NUT",
    35: "AUD_NUT",
    36: "EOS_NUT",
    37: "EOB_NUT",
    38: "FD_NUT",
    39: "SEI_PREFIX_NUT",
    40: "SEI_SUFFIX_NUT",
    41: "RSV_NVCL41",
    42: "RSV_NVCL42",
    43: "RSV_NVCL43",
    44: "RSV_NVCL44",
    45: "RSV_NVCL45",
    46: "RSV_NVCL46",
    47: "RSV_NVCL47",
    48: "UNSPEC48",
    49: "UNSPEC49",
    50: "UNSPEC50",
    51: "UNSPEC51",
    52: "UNSPEC52",
    53: "UNSPEC53",
    54: "UNSPEC54",
    55: "UNSPEC55",
    56: "UNSPEC56",
    57: "UNSPEC57",
    58: "UNSPEC58",
    59: "UNSPEC59",
    60: "UNSPEC60",
    61: "UNSPEC61",
    62: "UNSPEC62",
    63: "UNSPEC63"
}

def remove_emulation_prevention_bytes(data):
    # 0x000003 is the emulation prevention sequence
    i = 0
    output = bytearray()
    while i < len(data):
        # Look for the sequence 0x000003
        if i < len(data) - 2 and data[i] == 0x00 and data[i+1] == 0x00 and data[i+2] == 0x03:
            output.extend(data[i:i+2])
            i += 3  # Skip the 0x03 byte
        else:
            output.append(data[i])
            i += 1
    return bytes(output)

def read_f_safe(bs, bits=1):
    """Safely read fixed bits from the bitstream."""
    if bs.pos + bits <= bs.len:
        try:
            return bs.read(f'bits:{bits}')
        except ReadError:
            print(f'[Read Error] read_f_safe - position {bs.pos}')
            return None
    return None

def read_ue_safe(bs):
    if bs.pos < bs.len:
        try:
            return bs.read('ue')
        except ReadError:
            print(f'[Read Error] read_ue_safe - position {bs.pos}')
            return None
    return None

def read_se_safe(bs):
    if bs.pos < bs.len:
        try:
            return bs.read('se')
        except ReadError:
            print(f'[Read Error] read_se_safe - position {bs.pos}')
            return None
    return None

def read_bool_safe(bs):
    if bs.pos < bs.len:
        try:
            return bs.read('bool')
        except ReadError:
            print(f'[Read Error] read_bool_safe - position {bs.pos}')
            return None
    return None

def read_uint_safe(bs, bits):
    if bs.pos + bits <= bs.len:
        try:
            return bs.read(f'uint:{bits}')
        except ReadError:
            print(f'[Read Error] read_uint_safe - position {bs.pos}')
            return None
    return None

def parse_hevc_nal_units(video_stream_data, sps, pps, vps):
    nal_units = []
    vps_list, sps_list, pps_list = [], [], []
    parsed_vps, parsed_sps, parsed_pps = [], [], []
    parsed_sei_prefix, parsed_sei_suffix, parsed_slice_segments = [], [], []
    
    # For abnormal video files
    if sps is not None:
        sps_list = [{'raw_data': remove_emulation_prevention_bytes(sps[2:]), 'data': b'\x00\x00\x00\x01' + sps}, None, None]
    if pps is not None:
        pps_list = [{'raw_data': remove_emulation_prevention_bytes(pps[2:]), 'data': b'\x00\x00\x00\x01' + pps}, None, None]
    if vps is not None: 
        vps_list = [{'raw_data': remove_emulation_prevention_bytes(vps[2:]), 'data': b'\x00\x00\x00\x01' + vps}, None, None]

    nal_start_codes = [(m.start(), m.end()) for m in re.finditer(b'\x00\x00\x01|\x00\x00\x00\x01', video_stream_data)]

    for i, (nal_start, nal_end) in enumerate(nal_start_codes):
        start_code_len = nal_end - nal_start
        nal_start = nal_end
        
        if i + 1 < len(nal_start_codes):
            next_start = nal_start_codes[i + 1][0]
            nal_unit = video_stream_data[nal_start - start_code_len:next_start]
        else:
            nal_unit = video_stream_data[nal_start - start_code_len:]

        tmp_nal_start_offset = nal_start - start_code_len
        tmp_nal_length = len(nal_unit)

        if len(nal_unit) <= 8:
            continue

        nal_unit_header = nal_unit[start_code_len]
        nal_type = (nal_unit_header & 0x7E) >> 1

        parsed_nal = parse_nal_unit(nal_unit, True, tmp_nal_start_offset, tmp_nal_length)
        nal_units.append(parsed_nal)

        if nal_type == 32:  # VPS
            parsed_nal['parsed_data'] = (parse_vps(parsed_nal['raw_data'], parsed_nal['data']), parsed_nal['nal_start_offset'], parsed_nal['nal_length'])
            vps_list.append(parsed_nal)
            parsed_vps.append(parsed_nal)
        elif nal_type == 33:  # SPS
            parsed_nal['parsed_data'] = (parse_sps(parsed_nal['raw_data'], parsed_nal['data']), parsed_nal['nal_start_offset'], parsed_nal['nal_length'])
            sps_list.append(parsed_nal)
            parsed_sps.append(parsed_nal)
        elif nal_type == 34:  # PPS
            parsed_nal['parsed_data'] = (parse_pps(parsed_nal['raw_data'], parsed_nal['data']), parsed_nal['nal_start_offset'], parsed_nal['nal_length'])
            pps_list.append(parsed_nal)
            parsed_pps.append(parsed_nal)
        elif nal_type == 39:  # SEI Prefix
            latest_sps = parsed_sps[-1]['parsed_data'][0] if parsed_sps else None
            sei_data = parse_sei_prefix(parsed_nal['raw_data'], latest_sps)
            parsed_sei_prefix.extend(sei_data)
            parsed_nal['parsed_data'] = sei_data
        elif nal_type == 40:  # SEI Suffix
            latest_sps = parsed_sps[-1]['parsed_data'][0] if parsed_sps else None
            sei_data = parse_sei_suffix(parsed_nal['raw_data'], latest_sps)
            parsed_sei_suffix.extend(sei_data)
            parsed_nal['parsed_data'] = sei_data
        elif nal_type in range(0, 32):  # Slice types
            if parsed_sps and parsed_pps:
                latest_sps = parsed_sps[-1]['parsed_data'][0]
                latest_pps = parsed_pps[-1]['parsed_data'][0]
                slice_segment = parse_slice_segment(parsed_nal['raw_data'], nal_type, latest_sps, latest_pps)
                slice_segment['data'] = parsed_nal['data']
                parsed_slice_segments.append(slice_segment)
                parsed_nal['parsed_data'] = slice_segment
            else:
                parsed_nal['parsed_data'] = None
        else:
            parsed_nal['parsed_data'] = parsed_nal['raw_data']

    return {
        'nal_units': nal_units,
        'vps': parsed_vps,
        'sps': parsed_sps,
        'pps': parsed_pps,
        'sei_prefix': parsed_sei_prefix,
        'sei_suffix': parsed_sei_suffix,
        'slice_segments': parsed_slice_segments
    }

def parse_nal_unit(nal_unit, has_start_code=False, nal_start_offset=None, nal_length=None):
    if has_start_code:
        start_code_len = 3 if nal_unit[:3] == b'\x00\x00\x01' else 4
        nal_data = nal_unit[start_code_len:]
    else:
        nal_data = nal_unit

    # H.265 NAL unit header is 2 bytes
    nal_header = (nal_data[0] << 8) | nal_data[1]
    nal_data = remove_emulation_prevention_bytes(nal_data[2:])  # Start from the third byte

    return {
        'forbidden_zero_bit': (nal_header >> 15) & 0x01,
        'nal_type': (nal_header >> 9) & 0x3F,
        'nuh_layer_id': (nal_header >> 3) & 0x3F,
        'nuh_temporal_id_plus1': nal_header & 0x07,
        'data': nal_unit if has_start_code else b'\x00\x00\x00\x01' + nal_unit,
        'raw_data': nal_data,  # Raw data without NAL header
        'nal_start_offset': nal_start_offset,
        'nal_length': nal_length
    }

def parse_profile_tier_level(bs, profile_present_flag, max_num_sub_layers_minus1):
    profile_tier_level = {}

    if profile_present_flag:
        profile_tier_level['general_profile_space'] = read_uint_safe(bs, 2)
        profile_tier_level['general_tier_flag'] = read_bool_safe(bs)
        profile_tier_level['general_profile_idc'] = read_uint_safe(bs, 5)
        profile_tier_level['general_profile_compatibility_flag'] = [read_bool_safe(bs) for _ in range(32)]
        profile_tier_level['general_progressive_source_flag'] = read_bool_safe(bs)
        profile_tier_level['general_interlaced_source_flag'] = read_bool_safe(bs)
        profile_tier_level['general_non_packed_constraint_flag'] = read_bool_safe(bs)
        profile_tier_level['general_frame_only_constraint_flag'] = read_bool_safe(bs)

        if any(profile_tier_level['general_profile_idc'] == condition or
               profile_tier_level['general_profile_compatibility_flag'][condition] for condition in [4, 5, 6, 7, 8, 9, 10, 11]):
            profile_tier_level['general_max_12bit_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_max_10bit_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_max_8bit_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_max_422chroma_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_max_420chroma_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_max_monochrome_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_intra_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_one_picture_only_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_lower_bit_rate_constraint_flag'] = read_bool_safe(bs)

            if any(profile_tier_level['general_profile_idc'] == condition or
                   profile_tier_level['general_profile_compatibility_flag'][condition] for condition in [5, 9, 10, 11]):
                profile_tier_level['general_max_14bit_constraint_flag'] = read_bool_safe(bs)
                profile_tier_level['general_reserved_zero_33bits'] = read_uint_safe(bs, 33)
            else:
                profile_tier_level['general_reserved_zero_34bits'] = read_uint_safe(bs, 34)
        elif profile_tier_level['general_profile_idc'] == 2 or profile_tier_level['general_profile_compatibility_flag'][2]:
            profile_tier_level['general_reserved_zero_7bits'] = read_uint_safe(bs, 7)
            profile_tier_level['general_one_picture_only_constraint_flag'] = read_bool_safe(bs)
            profile_tier_level['general_reserved_zero_35bits'] = read_uint_safe(bs, 35)
        else:
            profile_tier_level['general_reserved_zero_43bits'] = read_uint_safe(bs, 43)

        if any(profile_tier_level['general_profile_idc'] == condition or
               profile_tier_level['general_profile_compatibility_flag'][condition] for condition in [1, 2, 3, 4, 5, 9, 11]):
            profile_tier_level['general_inbld_flag'] = read_bool_safe(bs)
        else:
            profile_tier_level['general_reserved_zero_bit'] = read_bool_safe(bs)

    profile_tier_level['general_level_idc'] = read_uint_safe(bs, 8)

    profile_tier_level['sub_layer_profile_present_flag'] = [read_bool_safe(bs) for _ in range(max_num_sub_layers_minus1)]
    profile_tier_level['sub_layer_level_present_flag'] = [read_bool_safe(bs) for _ in range(max_num_sub_layers_minus1)]

    profile_tier_level['reserved_zero_2bits'] = []
    if max_num_sub_layers_minus1 > 0:
        for i in range(max_num_sub_layers_minus1, 8):
            profile_tier_level['reserved_zero_2bits'].append(read_uint_safe(bs, 2))

    profile_tier_level['sub_layer_profile_space'] = []
    profile_tier_level['sub_layer_tier_flag'] = []
    profile_tier_level['sub_layer_profile_idc'] = []
    profile_tier_level['sub_layer_profile_compatibility_flag'] = []
    profile_tier_level['sub_layer_progressive_source_flag'] = []
    profile_tier_level['sub_layer_interlaced_source_flag'] = []
    profile_tier_level['sub_layer_non_packed_constraint_flag'] = []
    profile_tier_level['sub_layer_frame_only_constraint_flag'] = []
    profile_tier_level['sub_layer_max_12bit_constraint_flag'] = []
    profile_tier_level['sub_layer_max_10bit_constraint_flag'] = []
    profile_tier_level['sub_layer_max_8bit_constraint_flag'] = []
    profile_tier_level['sub_layer_max_422chroma_constraint_flag'] = []
    profile_tier_level['sub_layer_max_420chroma_constraint_flag'] = []
    profile_tier_level['sub_layer_max_monochrome_constraint_flag'] = []
    profile_tier_level['sub_layer_intra_constraint_flag'] = []
    profile_tier_level['sub_layer_one_picture_only_constraint_flag'] = []
    profile_tier_level['sub_layer_lower_bit_rate_constraint_flag'] = []
    profile_tier_level['sub_layer_max_14bit_constraint_flag'] = []
    profile_tier_level['sub_layer_reserved_zero_33bits'] = []
    profile_tier_level['sub_layer_reserved_zero_34bits'] = []
    profile_tier_level['sub_layer_reserved_zero_35bits'] = []
    profile_tier_level['sub_layer_reserved_zero_7bits'] = []
    profile_tier_level['sub_layer_reserved_zero_43bits'] = []
    profile_tier_level['sub_layer_inbld_flag'] = []
    profile_tier_level['sub_layer_reserved_zero_bit'] = []
    profile_tier_level['sub_layer_level_idc'] = []

    for i in range(max_num_sub_layers_minus1):
        if profile_tier_level['sub_layer_profile_present_flag'][i]:
            profile_tier_level['sub_layer_profile_space'].append(read_uint_safe(bs, 2))
            profile_tier_level['sub_layer_tier_flag'].append(read_bool_safe(bs))
            profile_tier_level['sub_layer_profile_idc'].append(read_uint_safe(bs, 5))
            profile_tier_level['sub_layer_profile_compatibility_flag'].append([read_bool_safe(bs) for _ in range(32)])
            profile_tier_level['sub_layer_progressive_source_flag'].append(read_bool_safe(bs))
            profile_tier_level['sub_layer_interlaced_source_flag'].append(read_bool_safe(bs))
            profile_tier_level['sub_layer_non_packed_constraint_flag'].append(read_bool_safe(bs))
            profile_tier_level['sub_layer_frame_only_constraint_flag'].append(read_bool_safe(bs))

            if any(profile_tier_level['sub_layer_profile_idc'][i] == condition or
                   (profile_tier_level['sub_layer_profile_compatibility_flag'][i][condition] if profile_tier_level['sub_layer_profile_compatibility_flag'][i] else False)
                   for condition in [4, 5, 6, 7, 8, 9, 10, 11]):
                profile_tier_level['sub_layer_max_12bit_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_max_10bit_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_max_8bit_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_max_422chroma_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_max_420chroma_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_max_monochrome_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_intra_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_one_picture_only_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_lower_bit_rate_constraint_flag'].append(read_bool_safe(bs))
                if any(profile_tier_level['sub_layer_profile_idc'][i] == condition or
                       profile_tier_level['sub_layer_profile_compatibility_flag'][i][condition] for condition in
                       [5, 9, 10, 11]):
                    profile_tier_level['sub_layer_max_14bit_constraint_flag'].append(read_bool_safe(bs))
                    profile_tier_level['sub_layer_reserved_zero_33bits'].append(read_uint_safe(bs, 33))
                else:
                    profile_tier_level['sub_layer_reserved_zero_34bits'].append(read_uint_safe(bs, 34))
            elif profile_tier_level['sub_layer_profile_idc'][i] == 2 or profile_tier_level['sub_layer_profile_compatibility_flag'][i][2]:
                profile_tier_level['sub_layer_reserved_zero_7bits'].append(read_uint_safe(bs, 7))
                profile_tier_level['sub_layer_one_picture_only_constraint_flag'].append(read_bool_safe(bs))
                profile_tier_level['sub_layer_reserved_zero_35bits'].append(read_uint_safe(bs, 35))
            else:
                profile_tier_level['sub_layer_reserved_zero_43bits'].append(read_uint_safe(bs, 43))

            if any(profile_tier_level['sub_layer_profile_idc'][i] == condition or
                   (profile_tier_level['sub_layer_profile_compatibility_flag'][i][condition] if
                   profile_tier_level['sub_layer_profile_compatibility_flag'][i] else False)
                   for condition in [1, 2, 3, 4, 5, 9, 11]):
                profile_tier_level['sub_layer_inbld_flag'].append(read_bool_safe(bs))
            else:
                profile_tier_level['sub_layer_reserved_zero_bit'].append(read_bool_safe(bs))
        else:
            profile_tier_level['sub_layer_profile_space'].append(None)
            profile_tier_level['sub_layer_tier_flag'].append(None)
            profile_tier_level['sub_layer_profile_idc'].append(None)
            profile_tier_level['sub_layer_profile_compatibility_flag'].append([None] * 32)
            profile_tier_level['sub_layer_progressive_source_flag'].append(None)
            profile_tier_level['sub_layer_interlaced_source_flag'].append(None)
            profile_tier_level['sub_layer_non_packed_constraint_flag'].append(None)
            profile_tier_level['sub_layer_frame_only_constraint_flag'].append(None)
            profile_tier_level['sub_layer_inbld_flag'].append(None)

        if profile_tier_level['sub_layer_level_present_flag'][i]:
            profile_tier_level['sub_layer_level_idc'].append(read_uint_safe(bs, 8))
        else:
            profile_tier_level['sub_layer_level_idc'].append(None)

    return profile_tier_level


def parse_vps(raw_data, data):
    bs = BitStream(raw_data)
    vps = {}
    vps['data'] = data

    # Parse VPS
    vps['vps_video_parameter_set_id'] = read_uint_safe(bs, 4)
    vps['vps_base_layer_internal_flag'] = read_bool_safe(bs)
    vps['vps_base_layer_avaliable_flag'] = read_bool_safe(bs)
    vps['vps_max_layers_minus1'] = read_uint_safe(bs, 6)
    vps['vps_max_sub_layers_minus1'] = read_uint_safe(bs, 3)
    vps['vps_temporal_id_nesting_flag'] = read_bool_safe(bs)
    vps['vps_reserved_0xffff_16bits'] = read_uint_safe(bs, 16)

    vps['profile_tier_level'] = parse_profile_tier_level(bs, 1, vps['vps_max_sub_layers_minus1'])
    vps['vps_sub_layer_ordering_info_present_flag'] = read_bool_safe(bs)

    vps['vps_max_dec_pic_buffering_minus1'] = []
    vps['vps_max_num_reorder_pics'] = []
    vps['vps_max_latency_increase_plus1'] = []

    num_layers = vps['vps_max_sub_layers_minus1'] + 1 if vps['vps_sub_layer_ordering_info_present_flag'] else 1
    for i in range(num_layers):
        vps['vps_max_dec_pic_buffering_minus1'].append(read_ue_safe(bs))
        vps['vps_max_num_reorder_pics'].append(read_ue_safe(bs))
        vps['vps_max_latency_increase_plus1'].append(read_ue_safe(bs))

    vps['vps_max_layer_id'] = read_uint_safe(bs, 6)
    vps['vps_num_layer_sets_minus1'] = read_ue_safe(bs)

    vps['layer_id_included_flag'] = []
    if vps['vps_num_layer_sets_minus1'] is not None:
        for i in range(vps['vps_num_layer_sets_minus1'] + 1):
            vps['layer_id_included_flag'].append([read_bool_safe(bs) for _ in range(vps['vps_max_layer_id'] + 1)])

    vps['vps_timing_info_present_flag'] = read_bool_safe(bs)
    if vps['vps_timing_info_present_flag']:
        vps['vps_num_units_in_tick'] = read_uint_safe(bs, 32)
        vps['vps_time_scale'] = read_uint_safe(bs, 32)
        vps['vps_poc_proportional_to_timing_flag'] = read_bool_safe(bs)
        if vps['vps_poc_proportional_to_timing_flag']:
            vps['vps_num_ticks_poc_diff_one_minus1'] = read_ue_safe(bs)
        vps['vps_num_hrd_parameters'] = read_ue_safe(bs)

        vps['hrd_layer_set_idx'] = []
        vps['cprms_present_flag'] = []

        for i in range(vps['vps_num_hrd_parameters'] + 1):
            vps['hrd_layer_set_idx'].append(read_ue_safe(bs))
            if i > 0:
                vps['cprms_present_flag'].append(read_bool_safe(bs))
            else:
                vps['cprms_present_flag'].append(None)
            if vps['cprms_present_flag'] is not False and vps['cprms_present_flag'] is not None:
                parse_hrd_parameters(bs, vps['cprms_present_flag'][i], vps['vps_max_sub_layers_minus1'])

    vps['vps_extension_flag'] = read_bool_safe(bs)
    if vps['vps_extension_flag']:
        while more_rbsp_data(bs):
            vps['vps_extension_data_flag'] = read_bool_safe(bs)

    return vps


def parse_sps(raw_data, data):
    bs = BitStream(raw_data)
    sps = {}
    sps['data'] = data

    sps['sps_video_parameter_set_id'] = read_uint_safe(bs, 4)
    sps['sps_max_sub_layers_minus1'] = read_uint_safe(bs, 3)
    sps['sps_temporal_id_nesting_flag'] = read_bool_safe(bs)

    # Parse profile_tier_level
    sps['profile_tier_level'] = parse_profile_tier_level(bs, 1, sps['sps_max_sub_layers_minus1'])

    sps['sps_seq_parameter_set_id'] = read_ue_safe(bs)
    sps['chroma_format_idc'] = read_ue_safe(bs)
    if sps['chroma_format_idc'] == 3:
        sps['separate_colour_plane_flag'] = read_bool_safe(bs)
    else:
        sps['separate_colour_plane_flag'] = 0  # Implicitly 0 when chroma_format_idc is not 3

    sps['pic_width_in_luma_samples'] = read_ue_safe(bs)
    sps['pic_height_in_luma_samples'] = read_ue_safe(bs)
    sps['conformance_window_flag'] = read_bool_safe(bs)
    if sps['conformance_window_flag']:
        sps['conf_win_left_offset'] = read_ue_safe(bs)
        sps['conf_win_right_offset'] = read_ue_safe(bs)
        sps['conf_win_top_offset'] = read_ue_safe(bs)
        sps['conf_win_bottom_offset'] = read_ue_safe(bs)

    sps['bit_depth_luma_minus8'] = read_ue_safe(bs)
    sps['bit_depth_chroma_minus8'] = read_ue_safe(bs)
    sps['log2_max_pic_order_cnt_lsb_minus4'] = read_ue_safe(bs)

    sps['sps_sub_layer_ordering_info_present_flag'] = read_bool_safe(bs)
    sps['max_dec_pic_buffering_minus1'] = []
    sps['max_num_reorder_pics'] = []
    sps['max_latency_increase_plus1'] = []
    start_layer = 0 if sps['sps_sub_layer_ordering_info_present_flag'] else sps['sps_max_sub_layers_minus1']
    for i in range(start_layer, sps['sps_max_sub_layers_minus1'] + 1):
        sps['max_dec_pic_buffering_minus1'].append(read_ue_safe(bs))
        sps['max_num_reorder_pics'].append(read_ue_safe(bs))
        sps['max_latency_increase_plus1'].append(read_ue_safe(bs))

    sps['log2_min_luma_coding_block_size_minus3'] = read_ue_safe(bs)
    sps['log2_diff_max_min_luma_coding_block_size'] = read_ue_safe(bs)
    sps['log2_min_luma_transform_block_size_minus2'] = read_ue_safe(bs)
    sps['log2_diff_max_min_luma_transform_block_size'] = read_ue_safe(bs)
    sps['max_transform_hierarchy_depth_inter'] = read_ue_safe(bs)
    sps['max_transform_hierarchy_depth_intra'] = read_ue_safe(bs)

    sps['scaling_list_enabled_flag'] = read_bool_safe(bs)
    if sps['scaling_list_enabled_flag']:
        sps['sps_scaling_list_data_present_flag'] = read_bool_safe(bs)
        if sps['sps_scaling_list_data_present_flag']:
            sps['scaling_list_data'] = parse_scaling_list_data(bs)

    sps['amp_enabled_flag'] = read_bool_safe(bs)
    sps['sample_adaptive_offset_enabled_flag'] = read_bool_safe(bs)

    sps['pcm_enabled_flag'] = read_bool_safe(bs)
    if sps['pcm_enabled_flag']:
        sps['pcm_sample_bit_depth_luma_minus1'] = read_uint_safe(bs, 4)
        sps['pcm_sample_bit_depth_chroma_minus1'] = read_uint_safe(bs, 4)
        sps['log2_min_pcm_luma_coding_block_size_minus3'] = read_ue_safe(bs)
        sps['log2_diff_max_min_pcm_luma_coding_block_size'] = read_ue_safe(bs)
        sps['pcm_loop_filter_disabled_flag'] = read_bool_safe(bs)

    sps['num_short_term_ref_pic_sets'] = read_ue_safe(bs)
    if sps.get('num_short_term_ref_pic_sets', 0):
        sps['short_term_ref_pic_set'] = [parse_short_term_ref_pic_set(bs, i, sps['num_short_term_ref_pic_sets']) for i in range(sps['num_short_term_ref_pic_sets'])]

    sps['long_term_ref_pics_present_flag'] = read_bool_safe(bs)
    if sps.get('long_term_ref_pics_present_flag'):
        sps['num_long_term_ref_pics_sps'] = read_ue_safe(bs)
        sps['lt_ref_pic_poc_lsb_sps'] = []
        sps['used_by_curr_pic_lt_sps_flag'] = []
        for i in range(sps['num_long_term_ref_pics_sps']):
            sps['lt_ref_pic_poc_lsb_sps'].append(read_uint_safe(bs, sps.get('log2_max_pic_order_cnt_lsb_minus4', 0) + 4))
            sps['used_by_curr_pic_lt_sps_flag'].append(read_bool_safe(bs))

    sps['sps_temporal_mvp_enabled_flag'] = read_bool_safe(bs)
    sps['strong_intra_smoothing_enabled_flag'] = read_bool_safe(bs)

    sps['vui_parameters_present_flag'] = read_bool_safe(bs)
    if sps['vui_parameters_present_flag']:
        sps['vui_parameters'] = parse_vui_parameters(bs, sps)

    sps['sps_extension_present_flag'] = read_bool_safe(bs)
    if sps['sps_extension_present_flag']:
        sps['sps_range_extension_flag'] = read_bool_safe(bs)
        sps['sps_multilayer_extension_flag'] = read_bool_safe(bs)
        sps['sps_3d_extension_flag'] = read_bool_safe(bs)
        sps['sps_scc_extension_flag'] = read_bool_safe(bs)

        if sps['sps_range_extension_flag']:
            sps['sps_range_extension'] = parse_sps_range_extension(bs)
        if sps['sps_multilayer_extension_flag']:
            sps['sps_multilayer_extension'] = parse_sps_multilayer_extension(bs)
        if sps['sps_3d_extension_flag']:
            sps['sps_3d_extension'] = parse_sps_3d_extension(bs)
        if sps['sps_scc_extension_flag']:
            sps['sps_scc_extension'] = parse_sps_scc_extension(bs, sps['chroma_format_idc'])

    return sps

def parse_sps_range_extension(bs):
    sps_range_extension = {}
    sps_range_extension['transform_skip_rotation_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['transform_skip_context_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['implicit_rdpcm_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['explicit_rdpcm_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['extended_precision_processing_flag'] = read_bool_safe(bs)
    sps_range_extension['intra_smoothing_disabled_flag'] = read_bool_safe(bs)
    sps_range_extension['high_precision_offsets_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['persistent_rice_adaptation_enabled_flag'] = read_bool_safe(bs)
    sps_range_extension['cabac_bypass_alignment_enabled_flag'] = read_bool_safe(bs)
    return sps_range_extension

def parse_sps_multilayer_extension(bs):
    inter_view_mv_vert_constraint_flag = read_bool_safe(bs)

    return inter_view_mv_vert_constraint_flag


def parse_sps_3d_extension(bs):
    sps_3d_ext = {
        'iv_di_mc_enabled_flag': [None, None],
        'iv_mv_scal_enabled_flag': [None, None],
        'log2_ivmc_sub_pb_size_minus3': [None, None],
        'iv_res_pred_enabled_flag': [None, None],
        'depth_ref_enabled_flag': [None, None],
        'vsp_mc_enabled_flag': [None, None],
        'dbbp_enabled_flag': [None, None],
        'tex_mc_enabled_flag': [None, None],
        'log2_texmc_sub_pb_size_minus3': [None, None],
        'intra_contour_enabled_flag': [None, None],
        'intra_dc_only_wedge_enabled_flag': [None, None],
        'cqt_cu_part_pred_enabled_flag': [None, None],
        'inter_dc_only_enabled_flag': [None, None],
        'skip_intra_enabled_flag': [None, None]
    }

    for d in range(2):  # for d = 0; d <= 1; d++
        sps_3d_ext['iv_di_mc_enabled_flag'][d] = read_bool_safe(bs)
        sps_3d_ext['iv_mv_scal_enabled_flag'][d] = read_bool_safe(bs)
        if d == 0:
            sps_3d_ext['log2_ivmc_sub_pb_size_minus3'][d] = read_ue_safe(bs)
            sps_3d_ext['iv_res_pred_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['depth_ref_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['vsp_mc_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['dbbp_enabled_flag'][d] = read_bool_safe(bs)
        else:
            sps_3d_ext['tex_mc_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['log2_texmc_sub_pb_size_minus3'][d] = read_ue_safe(bs)
            sps_3d_ext['intra_contour_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['intra_dc_only_wedge_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['cqt_cu_part_pred_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['inter_dc_only_enabled_flag'][d] = read_bool_safe(bs)
            sps_3d_ext['skip_intra_enabled_flag'][d] = read_bool_safe(bs)

    return sps_3d_ext

def parse_sps_scc_extension(bs, chroma_format_idc):
    scc_extension = {}
    scc_extension['sps_curr_pic_ref_enabled_flag'] = read_bool_safe(bs)
    scc_extension['palette_mode_enabled_flag'] = read_bool_safe(bs)
    if scc_extension['palette_mode_enabled_flag']:
        scc_extension['palette_max_size'] = read_ue_safe(bs)
        scc_extension['delta_palette_max_predictor_size'] = read_ue_safe(bs)
        scc_extension['sps_palette_predictor_initializers_present_flag'] = read_bool_safe(bs)

        if scc_extension['sps_palette_predictor_initializers_present_flag']:
            scc_extension['sps_num_palette_predictor_initializers_minus1'] = read_ue_safe(bs)
            num_comps = 1 if chroma_format_idc == 0 else 3
            scc_extension['sps_palette_predictor_initializer'] = []

            for comp in range(num_comps):
                predictor_initializer = []
                for i in range(scc_extension['sps_num_palette_predictor_initializers_minus1'] + 1):
                    predictor_initializer.append(read_uint_safe(bs, 8))
                scc_extension['sps_palette_predictor_initializer'].append(predictor_initializer)

    scc_extension['motion_vector_resolution_control_idc'] = read_uint_safe(bs, 2)
    scc_extension['intra_boundary_filtering_disabled_flag'] = read_bool_safe(bs)

    return scc_extension


def parse_pps(raw_data, data):
    bs = BitStream(raw_data)
    pps = {}
    pps['data'] = data

    pps['pps_pic_parameter_set_id'] = read_ue_safe(bs)
    pps['pps_seq_parameter_set_id'] = read_ue_safe(bs)
    pps['dependent_slice_segments_enabled_flag'] = read_bool_safe(bs)
    pps['output_flag_present_flag'] = read_bool_safe(bs)
    pps['num_extra_slice_header_bits'] = read_uint_safe(bs, 3)
    pps['sign_data_hiding_enabled_flag'] = read_bool_safe(bs)
    pps['cabac_init_present_flag'] = read_bool_safe(bs)
    pps['num_ref_idx_l0_default_active_minus1'] = read_ue_safe(bs)
    pps['num_ref_idx_l1_default_active_minus1'] = read_ue_safe(bs)
    pps['init_qp_minus26'] = read_se_safe(bs)
    pps['constrained_intra_pred_flag'] = read_bool_safe(bs)
    pps['transform_skip_enabled_flag'] = read_bool_safe(bs)
    pps['cu_qp_delta_enabled_flag'] = read_bool_safe(bs)

    if pps.get('cu_qp_delta_enabled_flag'):
        pps['diff_cu_qp_delta_depth'] = read_ue_safe(bs)

    pps['pps_cb_qp_offset'] = read_se_safe(bs)
    pps['pps_cr_qp_offset'] = read_se_safe(bs)
    pps['pps_slice_chroma_qp_offsets_present_flag'] = read_bool_safe(bs)
    pps['weighted_pred_flag'] = read_bool_safe(bs)
    pps['weighted_bipred_flag'] = read_bool_safe(bs)
    pps['transquant_bypass_enabled_flag'] = read_bool_safe(bs)
    pps['tiles_enabled_flag'] = read_bool_safe(bs)
    pps['entropy_coding_sync_enabled_flag'] = read_bool_safe(bs)

    if pps.get('tiles_enabled_flag', False):
        pps['num_tile_columns_minus1'] = read_ue_safe(bs)
        pps['num_tile_rows_minus1'] = read_ue_safe(bs)
        pps['uniform_spacing_flag'] = read_bool_safe(bs)
        if not pps.get('uniform_spacing_flag'):
            if pps.get('num_tile_columns_minus1') is not None:
                pps['column_width_minus1'] = [read_ue_safe(bs) for _ in range(pps['num_tile_columns_minus1'])]
            if pps.get('num_tile_rows_minus1') is not None:
                pps['row_height_minus1'] = [read_ue_safe(bs) for _ in range(pps['num_tile_rows_minus1'])]

        pps['loop_filter_across_tiles_enabled_flag'] = read_bool_safe(bs)
    else: # for initialize
        pps['num_tile_columns_minus1'] = 0
        pps['num_tile_rows_minus1'] = 0

    pps['pps_loop_filter_across_slices_enabled_flag'] = read_bool_safe(bs)
    pps['deblocking_filter_control_present_flag'] = read_bool_safe(bs)

    if pps.get('deblocking_filter_control_present_flag'):
        pps['deblocking_filter_override_enabled_flag'] = read_bool_safe(bs)
        pps['pps_deblocking_filter_disabled_flag'] = read_bool_safe(bs)
        if not pps['pps_deblocking_filter_disabled_flag']:
            pps['pps_beta_offset_div2'] = read_se_safe(bs)
            pps['pps_tc_offset_div2'] = read_se_safe(bs)

    pps['pps_scaling_list_data_present_flag'] = read_bool_safe(bs)
    if pps.get('pps_scaling_list_data_present_flag'):
        pps['scaling_list_data'] = parse_scaling_list_data(bs)

    pps['lists_modification_present_flag'] = read_bool_safe(bs)
    pps['log2_parallel_merge_level_minus2'] = read_ue_safe(bs)
    pps['slice_segment_header_extension_present_flag'] = read_bool_safe(bs)

    pps['pps_extension_present_flag'] = read_bool_safe(bs)
    if pps.get('pps_extension_present_flag'):
        pps['pps_range_extension_flag'] = read_bool_safe(bs)
        pps['pps_multilayer_extension_flag'] = read_bool_safe(bs)
        pps['pps_3d_extension_flag'] = read_bool_safe(bs)
        pps['pps_scc_extension_flag'] = read_bool_safe(bs)
        pps['pps_extension_4bits'] = read_uint_safe(bs, 4)

        if pps.get('pps_range_extension_flag'):
            pps['pps_range_extension'] = parse_pps_range_extension(bs)
        if pps.get('pps_multilayer_extension_flag'):
            pps['pps_multilayer_extension'] = parse_pps_multilayer_extension(bs)
        if pps.get('pps_3d_extension_flag'):
            pps['pps_3d_extension'] = parse_pps_3d_extension(bs)
        if pps.get('pps_scc_extension_flag'):
            pps['pps_scc_extension'] = parse_pps_scc_extension(bs)

    return pps


def parse_pps_range_extension(bs):
    pps_range_extension = {}

    pps_range_extension['transform_skip_enabled_flag'] = read_bool_safe(bs)
    if pps_range_extension['transform_skip_enabled_flag']:
        pps_range_extension['log2_max_transform_skip_block_size_minus2'] = read_ue_safe(bs)

    pps_range_extension['cross_component_prediction_enabled_flag'] = read_bool_safe(bs)
    pps_range_extension['chroma_qp_offset_list_enabled_flag'] = read_bool_safe(bs)

    if pps_range_extension['chroma_qp_offset_list_enabled_flag']:
        pps_range_extension['diff_cu_chroma_qp_offset_depth'] = read_ue_safe(bs)
        pps_range_extension['chroma_qp_offset_list_len_minus1'] = read_ue_safe(bs)

        pps_range_extension['cb_qp_offset_list'] = []
        pps_range_extension['cr_qp_offset_list'] = []

        for i in range(pps_range_extension['chroma_qp_offset_list_len_minus1'] + 1):
            cb_qp_offset = read_se_safe(bs)
            cr_qp_offset = read_se_safe(bs)
            pps_range_extension['cb_qp_offset_list'].append(cb_qp_offset)
            pps_range_extension['cr_qp_offset_list'].append(cr_qp_offset)

    pps_range_extension['log2_sao_offset_scale_luma'] = read_ue_safe(bs)
    pps_range_extension['log2_sao_offset_scale_chroma'] = read_ue_safe(bs)

    return pps_range_extension

def parse_pps_multilayer_extension(bs):
    pps_multilayer_extension = {}

    pps_multilayer_extension['poc_reset_info_present_flag'] = read_bool_safe(bs)
    pps_multilayer_extension['pps_infer_scaling_list_flag'] = read_bool_safe(bs)
    if pps_multilayer_extension['pps_infer_scaling_list_flag']:
        pps_multilayer_extension['pps_scaling_list_ref_layer_id'] = read_uint_safe(bs, 6)

    pps_multilayer_extension['num_ref_loc_offsets'] = read_ue_safe(bs)
    pps_multilayer_extension['ref_loc_offset_layer_id'] = []
    pps_multilayer_extension['scaled_ref_layer_offset_present_flag'] = []
    pps_multilayer_extension['scaled_ref_layer_left_offset'] = []
    pps_multilayer_extension['scaled_ref_layer_top_offset'] = []
    pps_multilayer_extension['scaled_ref_layer_right_offset'] = []
    pps_multilayer_extension['scaled_ref_layer_bottom_offset'] = []
    pps_multilayer_extension['ref_region_offset_present_flag'] = []
    pps_multilayer_extension['ref_region_left_offset'] = []
    pps_multilayer_extension['ref_region_top_offset'] = []
    pps_multilayer_extension['ref_region_right_offset'] = []
    pps_multilayer_extension['ref_region_bottom_offset'] = []
    pps_multilayer_extension['resample_phase_set_present_flag'] = []
    pps_multilayer_extension['phase_hor_luma'] = []
    pps_multilayer_extension['phase_ver_luma'] = []
    pps_multilayer_extension['phase_hor_chroma_plus8'] = []
    pps_multilayer_extension['phase_ver_chroma_plus8'] = []

    for i in range(pps_multilayer_extension['num_ref_loc_offsets']):
        pps_multilayer_extension['ref_loc_offset_layer_id'].append(read_uint_safe(bs, 6))

        pps_multilayer_extension['scaled_ref_layer_offset_present_flag'].append(read_bool_safe(bs))
        if pps_multilayer_extension['scaled_ref_layer_offset_present_flag'][i]:
            pps_multilayer_extension['scaled_ref_layer_left_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['scaled_ref_layer_top_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['scaled_ref_layer_right_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['scaled_ref_layer_bottom_offset'].append(read_se_safe(bs))

        pps_multilayer_extension['ref_region_offset_present_flag'].append(read_bool_safe(bs))
        if pps_multilayer_extension['ref_region_offset_present_flag'][i]:
            pps_multilayer_extension['ref_region_left_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['ref_region_top_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['ref_region_right_offset'].append(read_se_safe(bs))
            pps_multilayer_extension['ref_region_bottom_offset'].append(read_se_safe(bs))

        pps_multilayer_extension['resample_phase_set_present_flag'].append(read_bool_safe(bs))
        if pps_multilayer_extension['resample_phase_set_present_flag'][i]:
            pps_multilayer_extension['phase_hor_luma'].append(read_ue_safe(bs))
            pps_multilayer_extension['phase_ver_luma'].append(read_ue_safe(bs))
            pps_multilayer_extension['phase_hor_chroma_plus8'].append(read_ue_safe(bs))
            pps_multilayer_extension['phase_ver_chroma_plus8'].append(read_ue_safe(bs))

    pps_multilayer_extension['colour_mapping_enabled_flag'] = read_bool_safe(bs)
    if pps_multilayer_extension['colour_mapping_enabled_flag']:
        pps_multilayer_extension['colour_mapping_table'] = parse_colour_mapping_table(bs)

    return pps_multilayer_extension


def parse_colour_mapping_table(bs):
    colour_mapping_table = {}

    colour_mapping_table['num_cm_ref_layers_minus1'] = read_ue_safe(bs)
    colour_mapping_table['cm_ref_layer_id'] = [read_uint_safe(bs, 6) for _ in
                                               range(colour_mapping_table['num_cm_ref_layers_minus1'] + 1)]

    colour_mapping_table['cm_octant_depth'] = read_uint_safe(bs, 2)
    colour_mapping_table['cm_y_part_num_log2'] = read_uint_safe(bs, 2)

    colour_mapping_table['luma_bit_depth_cm_input_minus8'] = read_ue_safe(bs)
    colour_mapping_table['chroma_bit_depth_cm_input_minus8'] = read_ue_safe(bs)
    colour_mapping_table['luma_bit_depth_cm_output_minus8'] = read_ue_safe(bs)
    colour_mapping_table['chroma_bit_depth_cm_output_minus8'] = read_ue_safe(bs)

    colour_mapping_table['cm_res_quant_bits'] = read_uint_safe(bs, 2)
    colour_mapping_table['cm_delta_flc_bits_minus1'] = read_uint_safe(bs, 2)

    if colour_mapping_table['cm_octant_depth'] == 1:
        colour_mapping_table['cm_adapt_threshold_u_delta'] = read_se_safe(bs)
        colour_mapping_table['cm_adapt_threshold_v_delta'] = read_se_safe(bs)

    colour_mapping_table['colour_mapping_octants'] = parse_colour_mapping_octants(
        bs, 0, 0, 0, 0, 1 << colour_mapping_table['cm_octant_depth']
    )

    return colour_mapping_table

def parse_colour_mapping_octants(bs, inp_depth, idx_y, idx_cb, idx_cr, inp_length):
    octants = {}

    if inp_depth < read_uint_safe(bs, 2):
        octants['split_octant_flag'] = read_bool_safe(bs)
        if octants['split_octant_flag']:
            for k in range(2):
                for m in range(2):
                    for n in range(2):
                        parse_colour_mapping_octants(bs, inp_depth + 1,
                                                     idx_y + (1 << inp_length) * k,
                                                     idx_cb + (1 << inp_length) * m,
                                                     idx_cr + (1 << inp_length) * n,
                                                     inp_length // 2)
        else:
            octants['coded_res_flag'] = []
            for i in range(1 << inp_length):
                octants['coded_res_flag'].append(read_bool_safe(bs))
                if octants['coded_res_flag'][i]:
                    octants['res_coeff'] = []
                    for c in range(3):
                        res_coeff = {}
                        res_coeff['res_coeff_q'] = read_ue_safe(bs)
                        res_coeff['res_coeff_sign_flag'] = read_bool_safe(bs)
                        if res_coeff['res_coeff_sign_flag']:
                            res_coeff['res_coeff_abs_minus1'] = read_ue_safe(bs)
                        octants['res_coeff'].append(res_coeff)
    return octants

def parse_pps_3d_extension(bs):
    pps_3d_extension = {}

    pps_3d_extension['dlts_present_flag'] = read_bool_safe(bs)
    if pps_3d_extension['dlts_present_flag']:
        pps_3d_extension['pps_depth_layers_minus1'] = read_uint_safe(bs, 6)
        pps_3d_extension['pps_bit_depth_for_depth_layers_minus8'] = read_uint_safe(bs, 4)

        pps_3d_extension['dlt_flag'] = []
        pps_3d_extension['dlt_pred_flag'] = []
        pps_3d_extension['dlt_val_flags_present_flag'] = []
        pps_3d_extension['dlt_value_flag'] = []
        pps_3d_extension['delta_dlt'] = []

        for i in range(pps_3d_extension['pps_depth_layers_minus1'] + 1):
            dlt_flag = read_bool_safe(bs)
            pps_3d_extension['dlt_flag'].append(dlt_flag)
            if dlt_flag:
                dlt_pred_flag = read_bool_safe(bs)
                pps_3d_extension['dlt_pred_flag'].append(dlt_pred_flag)
                if not dlt_pred_flag:
                    dlt_val_flags_present_flag = read_bool_safe(bs)
                    pps_3d_extension['dlt_val_flags_present_flag'].append(dlt_val_flags_present_flag)
                    if dlt_val_flags_present_flag:
                        dlt_value_flag = [read_bool_safe(bs) for _ in range(depthMaxValue)]
                        pps_3d_extension['dlt_value_flag'].append(dlt_value_flag)
                    else:
                        pps_3d_extension['delta_dlt'].append(parse_delta_dlt(bs))
    return pps_3d_extension


def parse_delta_dlt(bs):
    delta_dlt = {}

    delta_dlt['num_val_delta_dlt'] = read_ue_safe(bs)
    if delta_dlt['num_val_delta_dlt'] > 0:
        if delta_dlt['num_val_delta_dlt'] > 1:
            delta_dlt['max_diff'] = read_ue_safe(bs)
        if delta_dlt['num_val_delta_dlt'] > 2 and delta_dlt['max_diff'] > 0:
            delta_dlt['min_diff_minus1'] = read_ue_safe(bs)

        delta_dlt['delta_dlt_val0'] = read_se_safe(bs)
        if delta_dlt['max_diff'] > (delta_dlt['min_diff_minus1'] + 1):
            delta_dlt['delta_val_diff_minus_min'] = [
                read_se_safe(bs) for _ in range(1, delta_dlt['num_val_delta_dlt'])
            ]

    return delta_dlt


def parse_pps_scc_extension(bs):
    pps_scc_extension = {}

    pps_scc_extension['pps_curr_pic_ref_enabled_flag'] = read_bool_safe(bs)
    pps_scc_extension['residual_adaptive_colour_transform_enabled_flag'] = read_bool_safe(bs)
    if pps_scc_extension['residual_adaptive_colour_transform_enabled_flag']:
        pps_scc_extension['pps_slice_act_qp_offsets_present_flag'] = read_bool_safe(bs)
        pps_scc_extension['pps_act_y_qp_offset_plus5'] = read_se_safe(bs)
        pps_scc_extension['pps_act_cb_qp_offset_plus5'] = read_se_safe(bs)
        pps_scc_extension['pps_act_cr_qp_offset_plus5'] = read_se_safe(bs)

    pps_scc_extension['pps_palette_predictor_initializers_present_flag'] = read_bool_safe(bs)
    if pps_scc_extension['pps_palette_predictor_initializers_present_flag']:
        pps_scc_extension['pps_num_palette_predictor_initializers'] = read_ue_safe(bs)
        if pps_scc_extension['pps_num_palette_predictor_initializers'] > 0:
            pps_scc_extension['monochrome_palette_flag'] = read_bool_safe(bs)
            pps_scc_extension['luma_bit_depth_entry_minus8'] = read_ue_safe(bs)
            if not pps_scc_extension['monochrome_palette_flag']:
                pps_scc_extension['chroma_bit_depth_entry_minus8'] = read_ue_safe(bs)

            num_comps = 1 if pps_scc_extension['monochrome_palette_flag'] else 3
            pps_scc_extension['pps_palette_predictor_initializer'] = []
            for comp in range(num_comps):
                pps_scc_extension['pps_palette_predictor_initializer'].append(
                    [read_uint_safe(bs, pps_scc_extension['luma_bit_depth_entry_minus8'] + 8) for _ in
                     range(pps_scc_extension['pps_num_palette_predictor_initializers'])]
                )

    pps_scc_extension['motion_vector_resolution_control_idc'] = read_uint_safe(bs, 2)
    pps_scc_extension['intra_boundary_filtering_disabled_flag'] = read_bool_safe(bs)

    return pps_scc_extension

def parse_scaling_list_data(bs):
    scaling_list_data = {}

    scaling_list_data['scaling_list_pred_mode_flag'] = []
    scaling_list_data['scaling_list_pred_matrix_id_delta'] = []
    scaling_list_data['scaling_list_dc_coef_minus8'] = []
    scaling_list_data['scaling_list_delta_coef'] = []
    scaling_list_data['ScalingList'] = []

    for sizeId in range(4):
        scaling_list_data['scaling_list_pred_mode_flag'].append([])
        scaling_list_data['scaling_list_pred_matrix_id_delta'].append([])
        scaling_list_data['scaling_list_dc_coef_minus8'].append([])
        scaling_list_data['scaling_list_delta_coef'].append([])
        scaling_list_data['ScalingList'].append([])

        for matrixId in range(6 if sizeId != 3 else 2):
            scaling_list_data['scaling_list_pred_mode_flag'][sizeId].append(read_bool_safe(bs))

            if scaling_list_data['scaling_list_pred_mode_flag'][sizeId][matrixId] is None:
                return None

            if not scaling_list_data['scaling_list_pred_mode_flag'][sizeId][matrixId]:
                delta = read_ue_safe(bs)
                if delta is None:
                    return None
                scaling_list_data['scaling_list_pred_matrix_id_delta'][sizeId].append(delta)
            else:
                scaling_list_data['scaling_list_pred_matrix_id_delta'][sizeId].append(None)

                coefNum = min(64, (1 << (4 + (sizeId << 1)))) if sizeId else 8
                nextCoef = 8

                if sizeId > 1:
                    dc_coef = read_se_safe(bs)
                    if dc_coef is None:
                        return None
                    scaling_list_data['scaling_list_dc_coef_minus8'][sizeId].append(dc_coef)
                    nextCoef = dc_coef + 8

                for i in range(coefNum):
                    delta_coef = read_se_safe(bs)
                    if delta_coef is None:
                        return None
                    scaling_list_data['scaling_list_delta_coef'][sizeId].append(delta_coef)
                    nextCoef = (nextCoef + delta_coef + 256) % 256
                    if len(scaling_list_data['ScalingList'][sizeId]) <= matrixId:
                        scaling_list_data['ScalingList'][sizeId].append([])
                    try:
                        scaling_list_data['ScalingList'][sizeId][matrixId].append(nextCoef)
                    except IndexError:  # to-do
                        pass

    return scaling_list_data




def parse_short_term_ref_pic_set(bs, st_rps_idx, num_short_term_ref_pic_sets):
    short_term_ref_pic_set = {}

    short_term_ref_pic_set['inter_ref_pic_set_prediction_flag'] = None
    short_term_ref_pic_set['delta_idx_minus1'] = None
    short_term_ref_pic_set['delta_rps_sign'] = None
    short_term_ref_pic_set['abs_delta_rps_minus1'] = None
    short_term_ref_pic_set['used_by_curr_pic_flag'] = []
    short_term_ref_pic_set['use_delta_flag'] = []

    if st_rps_idx != 0:
        short_term_ref_pic_set['inter_ref_pic_set_prediction_flag'] = read_bool_safe(bs)
        if short_term_ref_pic_set['inter_ref_pic_set_prediction_flag']:
            if st_rps_idx == num_short_term_ref_pic_sets:
                short_term_ref_pic_set['delta_idx_minus1'] = read_ue_safe(bs)
            short_term_ref_pic_set['delta_rps_sign'] = read_uint_safe(bs, 1)
            short_term_ref_pic_set['abs_delta_rps_minus1'] = read_ue_safe(bs)
            NumDeltaPocs = 0  # This should be calculated based on the reference picture set
            for j in range(NumDeltaPocs + 1):
                used_by_curr_pic_flag = read_bool_safe(bs)
                short_term_ref_pic_set['used_by_curr_pic_flag'].append(used_by_curr_pic_flag)
                if not used_by_curr_pic_flag:
                    short_term_ref_pic_set['use_delta_flag'].append(read_bool_safe(bs))
    else:
        short_term_ref_pic_set['num_negative_pics'] = read_ue_safe(bs)
        short_term_ref_pic_set['num_positive_pics'] = read_ue_safe(bs)
        short_term_ref_pic_set['delta_poc_s0_minus1'] = []
        short_term_ref_pic_set['used_by_curr_pic_s0_flag'] = []
        short_term_ref_pic_set['delta_poc_s1_minus1'] = []
        short_term_ref_pic_set['used_by_curr_pic_s1_flag'] = []

        for i in range(short_term_ref_pic_set['num_negative_pics']):
            short_term_ref_pic_set['delta_poc_s0_minus1'].append(read_ue_safe(bs))
            short_term_ref_pic_set['used_by_curr_pic_s0_flag'].append(read_bool_safe(bs))

        for i in range(short_term_ref_pic_set['num_positive_pics']):
            short_term_ref_pic_set['delta_poc_s1_minus1'].append(read_ue_safe(bs))
            short_term_ref_pic_set['used_by_curr_pic_s1_flag'].append(read_bool_safe(bs))

    return short_term_ref_pic_set


def parse_sei_message(bs):
    sei_message = {}

    # Parse payloadType
    sei_message['payload_type'] = 0
    while not bs.pos % 8 == 0:  # byte alignment check
        bit = read_uint_safe(bs, 1)
        if bit is not None:
            sei_message['payload_type'] += bit
    while bs.peek('uint:8') == 0xFF:
        sei_message['payload_type'] += 255
        bs.read(8)  # We need to skip these bytes
    payload_type_additional = read_uint_safe(bs, 8)
    if payload_type_additional is not None:
        sei_message['payload_type'] += payload_type_additional

    # Parse payloadSize
    sei_message['payload_size'] = 0
    while bs.peek('uint:8') == 0xFF:
        sei_message['payload_size'] += 255
        bs.read(8)  # We need to skip these bytes
    payload_size_additional = read_uint_safe(bs, 8)
    if payload_size_additional is not None:
        sei_message['payload_size'] += payload_size_additional

    return sei_message

def more_data_in_payload(bs):
    if bs.pos >= len(bs) - 8:  
        return False
    next_bits = bs.peek('uint:8')
    if next_bits == 0x80:  # rbsp_trailing_bits()
        return False
    return True

def parse_sei_payload(bs, payload_type, payload_size, sps=None):
    payload = {}
    payload['type'] = payload_type
    payload['size'] = payload_size

    start_pos = bs.pos
    if payload_type == 0:
        payload['parsed_data'] = parse_buffering_period(bs, sps)
    elif payload_type == 1:
        payload['parsed_data'] = parse_pic_timing(bs, sps)
    elif payload_type == 2:
        payload['parsed_data'] = parse_pan_scan_rect(bs)
    elif payload_type == 3:
        payload['parsed_data'] = parse_filler_payload(bs, payload_size)
    elif payload_type == 4:
        payload['parsed_data'] = parse_user_data_registered_itu_t_t35(bs, payload_size)
    elif payload_type == 5:
        payload['parsed_data'] = parse_user_data_unregistered(bs, payload_size)
    elif payload_type == 6:
        payload['parsed_data'] = parse_recovery_point(bs)
    elif payload_type == 9:
        payload['parsed_data'] = parse_scene_info(bs)
    elif payload_type == 15:
        payload['parsed_data'] = parse_picture_snapshot(bs)
    elif payload_type == 16:
        payload['parsed_data'] = parse_progressive_refinement_segment_start(bs)
    elif payload_type == 17:
        payload['parsed_data'] = parse_progressive_refinement_segment_end(bs)
    elif payload_type == 19:
        payload['parsed_data'] = parse_film_grain_characteristics(bs)
    elif payload_type == 22:
        payload['parsed_data'] = parse_post_filter_hint(bs)
    elif payload_type == 23:
        payload['parsed_data'] = parse_tone_mapping_info(bs)
    elif payload_type == 45:
        payload['parsed_data'] = parse_frame_packing_arrangement(bs)
    elif payload_type == 47:
        payload['parsed_data'] = parse_display_orientation(bs)
    elif payload_type == 128:
        payload['parsed_data'] = parse_structure_of_pictures_info(bs)
    elif payload_type == 129:
        payload['parsed_data'] = parse_active_parameter_sets(bs)
    elif payload_type == 130:
        payload['parsed_data'] = parse_decoding_unit_info(bs, sps)
    elif payload_type == 131:
        payload['parsed_data'] = parse_temporal_sub_layer_zero_index(bs)
    elif payload_type == 132:
        payload['parsed_data'] = parse_decoded_picture_hash(bs)
    elif payload_type == 133:
        payload['parsed_data'] = parse_scalable_nesting(bs, payload_size)
    elif payload_type == 134:
        payload['parsed_data'] = parse_region_refresh_info(bs)
    elif payload_type == 135:
        payload['parsed_data'] = parse_no_display(bs)
    elif payload_type == 136:
        payload['parsed_data'] = parse_time_code(bs)
    elif payload_type == 137:
        payload['parsed_data'] = parse_mastering_display_colour_volume(bs)
    elif payload_type == 138:
        payload['parsed_data'] = parse_segmented_rect_frame_packing_arrangement(bs)
    elif payload_type == 139:
        payload['parsed_data'] = parse_temporal_motion_constrained_tile_sets(bs)
    elif payload_type == 140:
        payload['parsed_data'] = parse_chroma_resampling_filter_hint(bs)
    elif payload_type == 141:
        payload['parsed_data'] = parse_knee_function_info(bs)
    elif payload_type == 142:
        payload['parsed_data'] = parse_colour_remapping_info(bs)
    elif payload_type == 143:
        payload['parsed_data'] = parse_deinterlaced_field_identification(bs)
    elif payload_type == 144:
        payload['parsed_data'] = parse_content_light_level_info(bs)
    elif payload_type == 145:
        payload['parsed_data'] = parse_dependent_rap_indication(bs)
    elif payload_type == 146:
        payload['parsed_data'] = parse_coded_region_completion(bs)
    elif payload_type == 147:
        payload['parsed_data'] = parse_alternative_transfer_characteristics(bs)
    elif payload_type == 148:
        payload['parsed_data'] = parse_ambient_viewing_environment(bs)
    elif payload_type == 149:
        payload['parsed_data'] = parse_content_colour_volume(bs)
    elif payload_type == 150:
        payload['parsed_data'] = parse_equirectangular_projection(bs)
    elif payload_type == 151:
        payload['parsed_data'] = parse_cubemap_projection(bs)
    elif payload_type == 152:
        payload['parsed_data'] = parse_fisheye_video_info(bs)
    elif payload_type == 154:
        payload['parsed_data'] = parse_sphere_rotation(bs)
    elif payload_type == 155:
        payload['parsed_data'] = parse_regionwise_packing(bs)
    elif payload_type == 156:
        payload['parsed_data'] = parse_omni_viewport(bs)
    elif payload_type == 157:
        payload['parsed_data'] = parse_regional_nesting(bs)
    elif payload_type == 158:
        payload['parsed_data'] = parse_mcts_extraction_info_sets(bs)
    elif payload_type == 159:
        payload['parsed_data'] = parse_mcts_extraction_info_nesting(bs)
    elif payload_type == 161:
        payload['parsed_data'] = parse_alpha_channel_info(bs)
    elif payload_type == 162:
        payload['parsed_data'] = parse_depth_representation_info(bs)
    elif payload_type == 163:
        payload['parsed_data'] = parse_multiview_scene_info(bs)
    elif payload_type == 164:
        payload['parsed_data'] = parse_multiview_acquisition_info(bs)
    elif payload_type == 165:
        payload['parsed_data'] = parse_multiview_view_position(bs)
    elif payload_type == 200:
        payload['parsed_data'] = parse_sei_manifest(bs)
    elif payload_type == 201:
        payload['parsed_data'] = parse_sei_prefix_indication(bs)
    elif payload_type == 202:
        payload['parsed_data'] = parse_annotated_regions(bs)
    else:
        payload['parsed_data'] = bs.read('bytes:' + str(payload_size))

    # Check if we've read exactly payload_size bits
    bits_read = bs.pos - start_pos
    if bits_read != payload_size * 8:
        print(f"Warning: Read {bits_read} bits, expected {payload_size * 8} bits for SEI payload type {payload_type}")

    return payload

def parse_sei_prefix(data, sps):
    bs = BitStream(data)
    sei_prefix = {}
    sei_prefix['messages'] = []

    while bs.pos < len(bs) - 8:
        message = parse_sei_message(bs)
        if message['payload_type'] is not None and message['payload_size'] is not None:
            payload = parse_sei_payload(bs, message['payload_type'], message['payload_size'], sps)
            sei_prefix['messages'].append(payload)

    return sei_prefix

def parse_sei_suffix(data, sps):
    bs = BitStream(data)
    sei_suffix = {}
    sei_suffix['messages'] = []

    while bs.pos < len(bs) - 8:  # Ensure we have at least one byte left
        message = parse_sei_message(bs)
        if message['payload_type'] is not None and message['payload_size'] is not None:
            payload = parse_sei_payload(bs, message['payload_type'], message['payload_size'], sps)
            sei_suffix['messages'].append(payload)

    return sei_suffix

def parse_buffering_period(bs, sps):
    bp = {}
    if sps['vui_parameters_present_flag'] and sps['vui_parameters']['hrd_parameters_present_flag']:
        hrd = sps['vui_parameters']['hrd_parameters']
        bp['bp_seq_parameter_set_id'] = read_ue_safe(bs)
        if not hrd['sub_pic_hrd_params_present_flag']:
            bp['irap_cpb_params_present_flag'] = read_bool_safe(bs)
        if bp['irap_cpb_params_present_flag']:
            bp['cpb_delay_offset'] = read_uint_safe(bs, hrd['au_cpb_removal_delay_length_minus1'] + 1)
            bp['dpb_delay_offset'] = read_uint_safe(bs, hrd['dpb_output_delay_length_minus1'] + 1)
        bp['concatenation_flag'] = read_bool_safe(bs)
        bp['au_cpb_removal_delay_delta_minus1'] = read_uint_safe(bs, hrd['au_cpb_removal_delay_length_minus1'] + 1)
        if hrd['nal_hrd_parameters_present_flag']:
            bp['nal_initial_cpb_removal_delay'] = []
            bp['nal_initial_cpb_removal_offset'] = []
            bp['nal_initial_alt_cpb_removal_delay'] = []
            bp['nal_initial_alt_cpb_removal_offset'] = []
            for i in range(hrd['cpb_cnt_minus1'][0] + 1):
                bp['nal_initial_cpb_removal_delay'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                bp['nal_initial_cpb_removal_offset'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                if hrd['sub_pic_hrd_params_present_flag'] or bp['irap_cpb_params_present_flag']:
                    bp['nal_initial_alt_cpb_removal_delay'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                    bp['nal_initial_alt_cpb_removal_offset'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
        if hrd['vcl_hrd_parameters_present_flag']:
            bp['vcl_initial_cpb_removal_delay'] = []
            bp['vcl_initial_cpb_removal_offset'] = []
            bp['vcl_initial_alt_cpb_removal_delay'] = []
            bp['vcl_initial_alt_cpb_removal_offset'] = []
            for i in range(hrd['cpb_cnt_minus1'][0] + 1):
                bp['vcl_initial_cpb_removal_delay'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                bp['vcl_initial_cpb_removal_offset'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                if hrd['sub_pic_hrd_params_present_flag'] or bp['irap_cpb_params_present_flag']:
                    bp['vcl_initial_alt_cpb_removal_delay'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
                    bp['vcl_initial_alt_cpb_removal_offset'].append(read_uint_safe(bs, hrd['initial_cpb_removal_delay_length_minus1'] + 1))
    return bp

def parse_pic_timing(bs, sps):
    pt = {}
    if sps.get('vui_parameters_present_flag'):
        vui = sps['vui_parameters']
        if vui.get('frame_field_info_present_flag'):
            pt['pic_struct'] = read_uint_safe(bs, 4)
            pt['source_scan_type'] = read_uint_safe(bs, 2)
            pt['duplicate_flag'] = read_bool_safe(bs)
        if sps.get('hrd_parameters_present_flag'):
            hrd = vui['hrd_parameters']
            pt['au_cpb_removal_delay_minus1'] = read_uint_safe(bs, hrd['au_cpb_removal_delay_length_minus1'] + 1)
            pt['pic_dpb_output_delay'] = read_uint_safe(bs, hrd['dpb_output_delay_length_minus1'] + 1)
            if hrd['sub_pic_hrd_params_present_flag']:
                pt['pic_dpb_output_du_delay'] = read_uint_safe(bs, hrd['dpb_output_delay_du_length_minus1'] + 1)
            if hrd['sub_pic_hrd_params_present_flag'] and hrd['sub_pic_cpb_params_in_pic_timing_sei_flag']:
                pt['num_decoding_units_minus1'] = read_ue_safe(bs)
                pt['du_common_cpb_removal_delay_flag'] = read_bool_safe(bs)
                if pt['du_common_cpb_removal_delay_flag']:
                    pt['du_common_cpb_removal_delay_increment_minus1'] = read_uint_safe(bs, hrd['du_cpb_removal_delay_increment_length_minus1'] + 1)
                pt['num_nalus_in_du_minus1'] = []
                pt['du_cpb_removal_delay_increment_minus1'] = []
                for i in range(pt['num_decoding_units_minus1'] + 1):
                    pt['num_nalus_in_du_minus1'].append(read_ue_safe(bs))
                    if not pt['du_common_cpb_removal_delay_flag'] and i < pt['num_decoding_units_minus1']:
                        pt['du_cpb_removal_delay_increment_minus1'].append(read_uint_safe(bs, hrd['du_cpb_removal_delay_increment_length_minus1'] + 1))
    return pt

def parse_pan_scan_rect(bs):
    psr = {}
    psr['pan_scan_rect_id'] = read_ue_safe(bs)
    psr['pan_scan_rect_cancel_flag'] = read_bool_safe(bs)
    if not psr['pan_scan_rect_cancel_flag']:
        psr['pan_scan_cnt_minus1'] = read_ue_safe(bs)
        psr['pan_scan_rect_left_offset'] = []
        psr['pan_scan_rect_right_offset'] = []
        psr['pan_scan_rect_top_offset'] = []
        psr['pan_scan_rect_bottom_offset'] = []
        for i in range(psr['pan_scan_cnt_minus1'] + 1):
            psr['pan_scan_rect_left_offset'].append(read_se_safe(bs))
            psr['pan_scan_rect_right_offset'].append(read_se_safe(bs))
            psr['pan_scan_rect_top_offset'].append(read_se_safe(bs))
            psr['pan_scan_rect_bottom_offset'].append(read_se_safe(bs))
        psr['pan_scan_rect_persistence_flag'] = read_bool_safe(bs)
    return psr

def parse_filler_payload(bs, payload_size):
    fp = {}
    fp['filler_payload'] = bs.read('bytes:' + str(payload_size))
    return fp

def parse_user_data_registered_itu_t_t35(bs, payload_size):
    udr = {}
    udr['itu_t_t35_country_code'] = read_uint_safe(bs, 8)
    if udr['itu_t_t35_country_code'] == 0xFF:
        udr['itu_t_t35_country_code_extension_byte'] = read_uint_safe(bs, 8)
    remaining_size = payload_size - (2 if udr['itu_t_t35_country_code'] == 0xFF else 1)
    udr['itu_t_t35_payload_byte'] = bs.read('bytes:' + str(remaining_size))
    return udr

def parse_user_data_unregistered(bs, payload_size):
    udu = {}
    udu['uuid_iso_iec_11578'] = bs.read('bytes:16')
    udu['user_data_payload_byte'] = bs.read('bytes:' + str(payload_size - 16))
    return udu

def parse_recovery_point(bs):
    rp = {}
    rp['recovery_poc_cnt'] = read_se_safe(bs)
    rp['exact_match_flag'] = read_bool_safe(bs)
    rp['broken_link_flag'] = read_bool_safe(bs)
    return rp

def parse_scene_info(bs):
    si = {}
    si['scene_info_present_flag'] = read_bool_safe(bs)
    if si['scene_info_present_flag']:
        si['prev_scene_id_valid_flag'] = read_bool_safe(bs)
        si['scene_id'] = read_ue_safe(bs)
        si['scene_transition_type'] = read_ue_safe(bs)
        if si['scene_transition_type'] > 3:
            si['second_scene_id'] = read_ue_safe(bs)
    return si

def parse_picture_snapshot(bs):
    ps = {}
    ps['snapshot_id'] = read_ue_safe(bs)
    return ps

def parse_progressive_refinement_segment_start(bs):
    prss = {}
    prss['progressive_refinement_id'] = read_ue_safe(bs)
    prss['pic_order_cnt_delta'] = read_ue_safe(bs)
    return prss

def parse_progressive_refinement_segment_end(bs):
    prse = {}
    prse['progressive_refinement_id'] = read_ue_safe(bs)
    return prse

def parse_film_grain_characteristics(bs):
    fgc = {}
    fgc['film_grain_characteristics_cancel_flag'] = read_bool_safe(bs)
    if not fgc['film_grain_characteristics_cancel_flag']:
        fgc['film_grain_model_id'] = read_uint_safe(bs, 2)
        fgc['separate_colour_description_present_flag'] = read_bool_safe(bs)
        if fgc['separate_colour_description_present_flag']:
            fgc['film_grain_bit_depth_luma_minus8'] = read_uint_safe(bs, 3)
            fgc['film_grain_bit_depth_chroma_minus8'] = read_uint_safe(bs, 3)
            fgc['film_grain_full_range_flag'] = read_bool_safe(bs)
            fgc['film_grain_colour_primaries'] = read_uint_safe(bs, 8)
            fgc['film_grain_transfer_characteristics'] = read_uint_safe(bs, 8)
            fgc['film_grain_matrix_coeffs'] = read_uint_safe(bs, 8)
        fgc['blending_mode_id'] = read_uint_safe(bs, 2)
        fgc['log2_scale_factor'] = read_uint_safe(bs, 4)
        fgc['comp_model_present_flag'] = []
        for c in range(3):
            fgc['comp_model_present_flag'].append(read_bool_safe(bs))
        for c in range(3):
            if fgc['comp_model_present_flag'][c]:
                fgc[f'num_intensity_intervals_minus1[{c}]'] = read_uint_safe(bs, 8)
                fgc[f'num_model_values_minus1[{c}]'] = read_uint_safe(bs, 3)
                fgc[f'intensity_interval_lower_bound[{c}]'] = []
                fgc[f'intensity_interval_upper_bound[{c}]'] = []
                fgc[f'comp_model_value[{c}]'] = []
                for i in range(fgc[f'num_intensity_intervals_minus1[{c}]'] + 1):
                    fgc[f'intensity_interval_lower_bound[{c}]'].append(read_uint_safe(bs, 8))
                    fgc[f'intensity_interval_upper_bound[{c}]'].append(read_uint_safe(bs, 8))
                    fgc[f'comp_model_value[{c}]'].append([])
                    for j in range(fgc[f'num_model_values_minus1[{c}]'] + 1):
                        fgc[f'comp_model_value[{c}'][i].append(read_se_safe(bs))
        fgc['film_grain_characteristics_persistence_flag'] = read_bool_safe(bs)
    return fgc

def parse_post_filter_hint(bs):
    pfh = {}
    pfh['filter_hint_size_y'] = read_ue_safe(bs)
    pfh['filter_hint_size_x'] = read_ue_safe(bs)
    pfh['filter_hint_type'] = read_uint_safe(bs, 2)
    pfh['filter_hint_value'] = []
    for cy in range(pfh['filter_hint_size_y']):
        pfh['filter_hint_value'].append([])
        for cx in range(pfh['filter_hint_size_x']):
            pfh['filter_hint_value'][cy].append(read_se_safe(bs))
    return pfh

def parse_tone_mapping_info(bs):
    tmi = {}
    tmi['tone_map_id'] = read_ue_safe(bs)
    tmi['tone_map_cancel_flag'] = read_bool_safe(bs)
    if not tmi['tone_map_cancel_flag']:
        tmi['tone_map_persistence_flag'] = read_bool_safe(bs)
        tmi['coded_data_bit_depth'] = read_uint_safe(bs, 8)
        tmi['target_bit_depth'] = read_uint_safe(bs, 8)
        tmi['tone_map_model_id'] = read_ue_safe(bs)
        if tmi['tone_map_model_id'] == 0:
            tmi['min_value'] = read_uint_safe(bs, 32)
            tmi['max_value'] = read_uint_safe(bs, 32)
        elif tmi['tone_map_model_id'] == 1:
            tmi['sigmoid_midpoint'] = read_uint_safe(bs, 32)
            tmi['sigmoid_width'] = read_uint_safe(bs, 32)
        elif tmi['tone_map_model_id'] == 2:
            tmi['start_of_coded_interval'] = []
            for i in range(1 << tmi['target_bit_depth']):
                tmi['start_of_coded_interval'].append(read_uint_safe(bs, ((tmi['coded_data_bit_depth'] + 7) >> 3) << 3))
        elif tmi['tone_map_model_id'] == 3:
            tmi['num_pivots'] = read_uint_safe(bs, 16)
            tmi['coded_pivot_value'] = []
            tmi['target_pivot_value'] = []
            for i in range(tmi['num_pivots']):
                tmi['coded_pivot_value'].append(read_uint_safe(bs, ((tmi['coded_data_bit_depth'] + 7) >> 3) << 3))
                tmi['target_pivot_value'].append(read_uint_safe(bs, ((tmi['target_bit_depth'] + 7) >> 3) << 3))
        elif tmi['tone_map_model_id'] == 4:
            tmi['camera_iso_speed_idc'] = read_uint_safe(bs, 8)
            if tmi['camera_iso_speed_idc'] == 255:
                tmi['camera_iso_speed_value'] = read_uint_safe(bs, 32)
            tmi['exposure_index_idc'] = read_uint_safe(bs, 8)
            if tmi['exposure_index_idc'] == 255:
                tmi['exposure_index_value'] = read_uint_safe(bs, 32)
            tmi['exposure_compensation_value_sign_flag'] = read_bool_safe(bs)
            tmi['exposure_compensation_value_numerator'] = read_uint_safe(bs, 16)
            tmi['exposure_compensation_value_denom_idc'] = read_uint_safe(bs, 16)
            tmi['ref_screen_luminance_white'] = read_uint_safe(bs, 32)
            tmi['extended_range_white_level'] = read_uint_safe(bs, 32)
            tmi['nominal_black_level_code_value'] = read_uint_safe(bs, 16)
            tmi['nominal_white_level_code_value'] = read_uint_safe(bs, 16)
            tmi['extended_white_level_code_value'] = read_uint_safe(bs, 16)
    return tmi

def parse_frame_packing_arrangement(bs):
    fpa = {}
    fpa['frame_packing_arrangement_id'] = read_ue_safe(bs)
    fpa['frame_packing_arrangement_cancel_flag'] = read_bool_safe(bs)
    if not fpa['frame_packing_arrangement_cancel_flag']:
        fpa['frame_packing_arrangement_type'] = read_uint_safe(bs, 7)
        fpa['quincunx_sampling_flag'] = read_bool_safe(bs)
        fpa['content_interpretation_type'] = read_uint_safe(bs, 6)
        fpa['spatial_flipping_flag'] = read_bool_safe(bs)
        fpa['frame0_flipped_flag'] = read_bool_safe(bs)
        fpa['field_views_flag'] = read_bool_safe(bs)
        fpa['current_frame_is_frame0_flag'] = read_bool_safe(bs)
        fpa['frame0_self_contained_flag'] = read_bool_safe(bs)
        fpa['frame1_self_contained_flag'] = read_bool_safe(bs)
        if not fpa['quincunx_sampling_flag'] and fpa['frame_packing_arrangement_type'] != 5:
            fpa['frame0_grid_position_x'] = read_uint_safe(bs, 4)
            fpa['frame0_grid_position_y'] = read_uint_safe(bs, 4)
            fpa['frame1_grid_position_x'] = read_uint_safe(bs, 4)
            fpa['frame1_grid_position_y'] = read_uint_safe(bs, 4)
        fpa['frame_packing_arrangement_reserved_byte'] = read_uint_safe(bs, 8)
        fpa['frame_packing_arrangement_persistence_flag'] = read_bool_safe(bs)
    fpa['upsampled_aspect_ratio_flag'] = read_bool_safe(bs)
    return fpa

def parse_display_orientation(bs):
    do = {}
    do['display_orientation_cancel_flag'] = read_bool_safe(bs)
    if not do['display_orientation_cancel_flag']:
        do['hor_flip'] = read_bool_safe(bs)
        do['ver_flip'] = read_bool_safe(bs)
        do['anticlockwise_rotation'] = read_uint_safe(bs, 16)
        do['display_orientation_persistence_flag'] = read_bool_safe(bs)
    return do

def parse_structure_of_pictures_info(bs):
    sopi = {}
    sopi['sop_seq_parameter_set_id'] = read_ue_safe(bs)
    sopi['num_entries_in_sop_minus1'] = read_ue_safe(bs)
    sopi['sop_vcl_nut'] = []
    sopi['sop_temporal_id'] = []
    sopi['sop_short_term_rps_idx'] = []
    sopi['sop_poc_delta'] = []
    for i in range(sopi['num_entries_in_sop_minus1'] + 1):
        sopi['sop_vcl_nut'].append(read_uint_safe(bs, 6))
        sopi['sop_temporal_id'].append(read_uint_safe(bs, 3))
        if sopi['sop_vcl_nut'][i] != 19 and sopi['sop_vcl_nut'][i] != 20:
            sopi['sop_short_term_rps_idx'].append(read_ue_safe(bs))
            if i > 0:
                sopi['sop_poc_delta'].append(read_se_safe(bs))
    return sopi

def parse_active_parameter_sets(bs):
    aps = {}
    aps['active_video_parameter_set_id'] = read_uint_safe(bs, 4)
    aps['self_contained_cvs_flag'] = read_bool_safe(bs)
    aps['no_parameter_set_update_flag'] = read_bool_safe(bs)
    aps['num_sps_ids_minus1'] = read_ue_safe(bs)
    aps['active_seq_parameter_set_id'] = []
    for i in range(aps['num_sps_ids_minus1'] + 1):
        aps['active_seq_parameter_set_id'].append(read_ue_safe(bs))
    return aps

def parse_decoding_unit_info(bs, sps):
    dui = {}
    hrd = sps['vui_parameters']['hrd_parameters']
    dui['decoding_unit_idx'] = read_ue_safe(bs)
    if not hrd['sub_pic_cpb_params_in_pic_timing_sei_flag']:
        dui['du_spt_cpb_removal_delay_increment'] = read_uint_safe(bs, hrd['du_cpb_removal_delay_increment_length_minus1'] + 1)
    dui['dpb_output_du_delay_present_flag'] = read_bool_safe(bs)
    if dui['dpb_output_du_delay_present_flag']:
        dui['pic_spt_dpb_output_du_delay'] = read_uint_safe(bs, hrd['dpb_output_delay_du_length_minus1'] + 1)
    return dui

def parse_temporal_sub_layer_zero_index(bs):
    tslzi = {}
    tslzi['temporal_sub_layer_zero_idx'] = read_uint_safe(bs, 8)
    tslzi['irap_pic_id'] = read_uint_safe(bs, 8)
    return tslzi


def parse_decoded_picture_hash(bs):
    dph = {}
    dph['hash_type'] = read_uint_safe(bs, 8)
    dph['picture_md5'] = []
    for i in range(3):  # Assumes 4:2:0 color format. Adjust if needed.
        if dph['hash_type'] == 0:
            dph['picture_md5'].append(bs.read('bytes:16'))
        elif dph['hash_type'] == 1:
            dph['picture_crc'].append(read_uint_safe(bs, 16))
        elif dph['hash_type'] == 2:
            dph['picture_checksum'].append(read_uint_safe(bs, 32))
    return dph


def parse_scalable_nesting(bs, payload_size):
    sn = {}
    start_pos = bs.pos
    sn['bitstream_subset_flag'] = read_bool_safe(bs)
    sn['nesting_op_flag'] = read_bool_safe(bs)
    if sn['nesting_op_flag']:
        sn['default_op_flag'] = read_bool_safe(bs)
        sn['nesting_num_ops_minus1'] = read_ue_safe(bs)
        sn['nesting_max_temporal_id_plus1'] = []
        sn['nesting_op_idx'] = []
        for i in range(sn['nesting_num_ops_minus1'] + 1):
            if not sn['default_op_flag'] or i == 0:
                sn['nesting_max_temporal_id_plus1'].append(read_uint_safe(bs, 3))
            if not sn['default_op_flag']:
                sn['nesting_op_idx'].append(read_ue_safe(bs))
    sn['all_layers_flag'] = read_bool_safe(bs)
    if not sn['all_layers_flag']:
        sn['nesting_no_op_max_temporal_id_plus1'] = read_uint_safe(bs, 3)
        sn['nesting_num_layers_minus1'] = read_ue_safe(bs)
        sn['nesting_layer_id'] = []
        for i in range(sn['nesting_num_layers_minus1'] + 1):
            sn['nesting_layer_id'].append(read_uint_safe(bs, 6))

    # Parse nested SEI messages
    sn['nested_sei_messages'] = []
    while bs.pos - start_pos < payload_size * 8:
        nested_payload_type = 0
        while read_uint_safe(bs, 8) == 0xFF:
            nested_payload_type += 255
        nested_payload_type += read_uint_safe(bs, 8)

        nested_payload_size = 0
        while read_uint_safe(bs, 8) == 0xFF:
            nested_payload_size += 255
        nested_payload_size += read_uint_safe(bs, 8)

        sn['nested_sei_messages'].append(parse_sei_payload(bs, nested_payload_type, nested_payload_size))

    return sn


def parse_region_refresh_info(bs):
    rri = {}
    rri['refreshed_region_flag'] = read_bool_safe(bs)
    return rri


def parse_no_display(bs):
    # This SEI message doesn't carry any payload
    return {}


def parse_time_code(bs):
    tc = {}
    tc['num_clock_ts'] = read_uint_safe(bs, 2)
    tc['clock_timestamp'] = []
    for i in range(tc['num_clock_ts']):
        cts = {}
        cts['clock_timestamp_flag'] = read_bool_safe(bs)
        if cts['clock_timestamp_flag']:
            cts['units_field_based_flag'] = read_bool_safe(bs)
            cts['counting_type'] = read_uint_safe(bs, 5)
            cts['full_timestamp_flag'] = read_bool_safe(bs)
            cts['discontinuity_flag'] = read_bool_safe(bs)
            cts['cnt_dropped_flag'] = read_bool_safe(bs)
            cts['n_frames'] = read_uint_safe(bs, 9)
            if cts['full_timestamp_flag']:
                cts['seconds_value'] = read_uint_safe(bs, 6)
                cts['minutes_value'] = read_uint_safe(bs, 6)
                cts['hours_value'] = read_uint_safe(bs, 5)
            else:
                cts['seconds_flag'] = read_bool_safe(bs)
                if cts['seconds_flag']:
                    cts['seconds_value'] = read_uint_safe(bs, 6)
                    cts['minutes_flag'] = read_bool_safe(bs)
                    if cts['minutes_flag']:
                        cts['minutes_value'] = read_uint_safe(bs, 6)
                        cts['hours_flag'] = read_bool_safe(bs)
                        if cts['hours_flag']:
                            cts['hours_value'] = read_uint_safe(bs, 5)
            cts['time_offset_length'] = read_uint_safe(bs, 5)
            if cts['time_offset_length'] > 0:
                cts['time_offset_value'] = read_uint_safe(bs, cts['time_offset_length'])
        tc['clock_timestamp'].append(cts)
    return tc


def parse_mastering_display_colour_volume(bs):
    mdcv = {}
    mdcv['display_primaries_x'] = [read_uint_safe(bs, 16) for _ in range(3)]
    mdcv['display_primaries_y'] = [read_uint_safe(bs, 16) for _ in range(3)]
    mdcv['white_point_x'] = read_uint_safe(bs, 16)
    mdcv['white_point_y'] = read_uint_safe(bs, 16)
    mdcv['max_display_mastering_luminance'] = read_uint_safe(bs, 32)
    mdcv['min_display_mastering_luminance'] = read_uint_safe(bs, 32)
    return mdcv


def parse_segmented_rect_frame_packing_arrangement(bs):
    srfpa = {}
    srfpa['content_interpretation_type'] = read_uint_safe(bs, 2)
    srfpa['frame_packing_arrangement_persistence_flag'] = read_bool_safe(bs)
    return srfpa


def parse_temporal_motion_constrained_tile_sets(bs):
    tmcts = {}
    tmcts['mc_all_tiles_exact_sample_value_match_flag'] = read_bool_safe(bs)
    tmcts['each_tile_one_tile_set_flag'] = read_bool_safe(bs)
    if not tmcts['each_tile_one_tile_set_flag']:
        tmcts['limited_tile_set_display_flag'] = read_bool_safe(bs)
        tmcts['num_sets_in_message_minus1'] = read_ue_safe(bs)
        tmcts['mcts_id'] = []
        tmcts['display_tile_set_flag'] = []
        tmcts['num_tile_rects_in_set_minus1'] = []
        tmcts['top_left_tile_index'] = []
        tmcts['bottom_right_tile_index'] = []
        for i in range(tmcts['num_sets_in_message_minus1'] + 1):
            tmcts['mcts_id'].append(read_ue_safe(bs))
            if tmcts['limited_tile_set_display_flag']:
                tmcts['display_tile_set_flag'].append(read_bool_safe(bs))
            tmcts['num_tile_rects_in_set_minus1'].append(read_ue_safe(bs))
            tmcts['top_left_tile_index'].append([])
            tmcts['bottom_right_tile_index'].append([])
            for j in range(tmcts['num_tile_rects_in_set_minus1'][i] + 1):
                tmcts['top_left_tile_index'][i].append(read_ue_safe(bs))
                tmcts['bottom_right_tile_index'][i].append(read_ue_safe(bs))
    tmcts['mc_exact_sample_value_match_flag'] = read_bool_safe(bs)
    tmcts['mcts_tier_level_idc_present_flag'] = read_bool_safe(bs)
    if tmcts['mcts_tier_level_idc_present_flag']:
        tmcts['mcts_tier_flag'] = read_bool_safe(bs)
        tmcts['mcts_level_idc'] = read_uint_safe(bs, 8)
    return tmcts


def parse_chroma_resampling_filter_hint(bs):
    crfh = {}
    crfh['ver_chroma_filter_idc'] = read_uint_safe(bs, 8)
    crfh['hor_chroma_filter_idc'] = read_uint_safe(bs, 8)
    crfh['ver_filtering_field_processing_flag'] = read_bool_safe(bs)
    if crfh['ver_chroma_filter_idc'] == 1 or crfh['hor_chroma_filter_idc'] == 1:
        crfh['target_format_idc'] = read_ue_safe(bs)
        if crfh['ver_chroma_filter_idc'] == 1:
            num_vertical_filters = read_ue_safe(bs)
            crfh['ver_tap_length_minus1'] = [read_ue_safe(bs) for _ in range(num_vertical_filters)]
            crfh['ver_filter_coeff'] = [[read_se_safe(bs) for _ in range(crfh['ver_tap_length_minus1'][i] + 1)] for i in
                                        range(num_vertical_filters)]
        if crfh['hor_chroma_filter_idc'] == 1:
            num_horizontal_filters = read_ue_safe(bs)
            crfh['hor_tap_length_minus1'] = [read_ue_safe(bs) for _ in range(num_horizontal_filters)]
            crfh['hor_filter_coeff'] = [[read_se_safe(bs) for _ in range(crfh['hor_tap_length_minus1'][i] + 1)] for i in
                                        range(num_horizontal_filters)]
    return crfh


def parse_knee_function_info(bs):
    kfi = {}
    kfi['knee_function_id'] = read_ue_safe(bs)
    kfi['knee_function_cancel_flag'] = read_bool_safe(bs)
    if not kfi['knee_function_cancel_flag']:
        kfi['knee_function_persistence_flag'] = read_bool_safe(bs)
        kfi['input_d_range'] = read_uint_safe(bs, 32)
        kfi['input_disp_luminance'] = read_uint_safe(bs, 32)
        kfi['output_d_range'] = read_uint_safe(bs, 32)
        kfi['output_disp_luminance'] = read_uint_safe(bs, 32)
        kfi['num_knee_points_minus1'] = read_ue_safe(bs)
        kfi['input_knee_point'] = []
        kfi['output_knee_point'] = []
        for i in range(kfi['num_knee_points_minus1'] + 1):
            kfi['input_knee_point'].append(read_uint_safe(bs, 10))
            kfi['output_knee_point'].append(read_uint_safe(bs, 10))
    return kfi

def parse_colour_remapping_info(bs):
    cri = {}
    cri['colour_remap_id'] = read_ue_safe(bs)
    cri['colour_remap_cancel_flag'] = read_bool_safe(bs)
    if not cri['colour_remap_cancel_flag']:
        cri['colour_remap_persistence_flag'] = read_bool_safe(bs)
        cri['colour_remap_video_signal_info_present_flag'] = read_bool_safe(bs)
        if cri['colour_remap_video_signal_info_present_flag']:
            cri['colour_remap_full_range_flag'] = read_bool_safe(bs)
            cri['colour_remap_primaries'] = read_uint_safe(bs, 8)
            cri['colour_remap_transfer_function'] = read_uint_safe(bs, 8)
            cri['colour_remap_matrix_coefficients'] = read_uint_safe(bs, 8)
        cri['colour_remap_input_bit_depth'] = read_uint_safe(bs, 8)
        cri['colour_remap_output_bit_depth'] = read_uint_safe(bs, 8)
        cri['pre_lut_num_val_minus1'] = [read_uint_safe(bs, 8) for _ in range(3)]
        cri['pre_lut_coded_value'] = []
        cri['pre_lut_target_value'] = []
        for i in range(3):
            if cri['pre_lut_num_val_minus1'][i] > 0:
                cri['pre_lut_coded_value'].append([read_uint_safe(bs, cri['colour_remap_input_bit_depth']) for _ in range(cri['pre_lut_num_val_minus1'][i] + 1)])
                cri['pre_lut_target_value'].append([read_uint_safe(bs, cri['colour_remap_output_bit_depth']) for _ in range(cri['pre_lut_num_val_minus1'][i] + 1)])
        cri['colour_remap_matrix_present_flag'] = read_bool_safe(bs)
        if cri['colour_remap_matrix_present_flag']:
            cri['log2_matrix_denom'] = read_uint_safe(bs, 4)
            cri['colour_remap_coeffs'] = [[read_se_safe(bs) for _ in range(3)] for _ in range(3)]
        cri['post_lut_num_val_minus1'] = [read_uint_safe(bs, 8) for _ in range(3)]
        cri['post_lut_coded_value'] = []
        cri['post_lut_target_value'] = []
        for i in range(3):
            if cri['post_lut_num_val_minus1'][i] > 0:
                cri['post_lut_coded_value'].append([read_uint_safe(bs, cri['colour_remap_output_bit_depth']) for _ in range(cri['post_lut_num_val_minus1'][i] + 1)])
                cri['post_lut_target_value'].append([read_uint_safe(bs, cri['colour_remap_output_bit_depth']) for _ in range(cri['post_lut_num_val_minus1'][i] + 1)])
    return cri

def parse_deinterlaced_field_identification(bs):
    dfi = {}
    dfi['deinterlaced_picture_source_parity_flag'] = read_bool_safe(bs)
    return dfi

def parse_content_light_level_info(bs):
    clli = {}
    clli['max_content_light_level'] = read_uint_safe(bs, 16)
    clli['max_pic_average_light_level'] = read_uint_safe(bs, 16)
    return clli

def parse_dependent_rap_indication(bs):
    # This SEI message does not carry any payload
    return {}

def parse_coded_region_completion(bs):
    crc = {}
    crc['next_segment_address'] = read_ue_safe(bs)
    crc['independent_slice_segment_flag'] = read_bool_safe(bs)
    return crc

def parse_alternative_transfer_characteristics(bs):
    atc = {}
    atc['preferred_transfer_characteristics'] = read_uint_safe(bs, 8)
    return atc

def parse_ambient_viewing_environment(bs):
    ave = {}
    ave['ambient_illuminance'] = read_uint_safe(bs, 32)
    ave['ambient_light_x'] = read_uint_safe(bs, 16)
    ave['ambient_light_y'] = read_uint_safe(bs, 16)
    return ave

def parse_content_colour_volume(bs):
    ccv = {}
    ccv['ccv_cancel_flag'] = read_bool_safe(bs)
    if not ccv['ccv_cancel_flag']:
        ccv['ccv_persistence_flag'] = read_bool_safe(bs)
        ccv['ccv_primaries_present_flag'] = read_bool_safe(bs)
        ccv['ccv_min_luminance_value_present_flag'] = read_bool_safe(bs)
        ccv['ccv_max_luminance_value_present_flag'] = read_bool_safe(bs)
        ccv['ccv_avg_luminance_value_present_flag'] = read_bool_safe(bs)
        ccv['ccv_reserved_zero_2bits'] = read_uint_safe(bs, 2)
        if ccv['ccv_primaries_present_flag']:
            ccv['ccv_primaries_x'] = [read_uint_safe(bs, 32) for _ in range(3)]
            ccv['ccv_primaries_y'] = [read_uint_safe(bs, 32) for _ in range(3)]
        if ccv['ccv_min_luminance_value_present_flag']:
            ccv['ccv_min_luminance_value'] = read_uint_safe(bs, 32)
        if ccv['ccv_max_luminance_value_present_flag']:
            ccv['ccv_max_luminance_value'] = read_uint_safe(bs, 32)
        if ccv['ccv_avg_luminance_value_present_flag']:
            ccv['ccv_avg_luminance_value'] = read_uint_safe(bs, 32)
    return ccv

def parse_equirectangular_projection(bs):
    erp = {}
    erp['erp_cancel_flag'] = read_bool_safe(bs)
    if not erp['erp_cancel_flag']:
        erp['erp_persistence_flag'] = read_bool_safe(bs)
        erp['erp_guard_band_flag'] = read_bool_safe(bs)
        erp['erp_reserved_zero_2bits'] = read_uint_safe(bs, 2)
        if erp['erp_guard_band_flag']:
            erp['erp_guard_band_type'] = read_uint_safe(bs, 3)
            erp['erp_left_guard_band_width'] = read_ue_safe(bs)
            erp['erp_right_guard_band_width'] = read_ue_safe(bs)
    return erp

def parse_cubemap_projection(bs):
    cmp = {}
    cmp['cmp_cancel_flag'] = read_bool_safe(bs)
    if not cmp['cmp_cancel_flag']:
        cmp['cmp_persistence_flag'] = read_bool_safe(bs)
        cmp['cmp_reserved_zero_6bits'] = read_uint_safe(bs, 6)
    return cmp

def parse_fisheye_video_info(bs):
    fvi = {}
    fvi['fisheye_cancel_flag'] = read_bool_safe(bs)
    if not fvi['fisheye_cancel_flag']:
        fvi['fisheye_persistence_flag'] = read_bool_safe(bs)
        fvi['fisheye_view_dimension'] = read_uint_safe(bs, 8)
        fvi['fisheye_scene_radius'] = read_uint_safe(bs, 32)
        fvi['fisheye_camera_center_azimuth'] = read_se_safe(bs)
        fvi['fisheye_camera_center_elevation'] = read_se_safe(bs)
        fvi['fisheye_camera_center_tilt'] = read_se_safe(bs)
        fvi['fisheye_camera_center_offset'] = read_se_safe(bs)
        fvi['fisheye_circular_region_radius'] = read_uint_safe(bs, 32)
        fvi['fisheye_field_of_view'] = read_uint_safe(bs, 32)
        fvi['num_polynomial_coeffs'] = read_uint_safe(bs, 6)
        fvi['polynomial_coeff'] = [read_se_safe(bs) for _ in range(fvi['num_polynomial_coeffs'])]
    return fvi

def parse_sphere_rotation(bs):
    sr = {}
    sr['sphere_rotation_cancel_flag'] = read_bool_safe(bs)
    if not sr['sphere_rotation_cancel_flag']:
        sr['sphere_rotation_persistence_flag'] = read_bool_safe(bs)
        sr['yaw_rotation'] = read_se_safe(bs)
        sr['pitch_rotation'] = read_se_safe(bs)
        sr['roll_rotation'] = read_se_safe(bs)
    return sr

def parse_regionwise_packing(bs):
    rp = {}
    rp['rwp_cancel_flag'] = read_bool_safe(bs)
    if not rp['rwp_cancel_flag']:
        rp['rwp_persistence_flag'] = read_bool_safe(bs)
        rp['constituent_picture_matching_flag'] = read_bool_safe(bs)
        rp['rwp_reserved_zero_5bits'] = read_uint_safe(bs, 5)
        rp['num_packed_regions'] = read_uint_safe(bs, 8)
        rp['proj_picture_width'] = read_uint_safe(bs, 32)
        rp['proj_picture_height'] = read_uint_safe(bs, 32)
        rp['packed_picture_width'] = read_uint_safe(bs, 16)
        rp['packed_picture_height'] = read_uint_safe(bs, 16)
        rp['rwp_reserved_zero_4bits'] = read_uint_safe(bs, 4)
        rp['rwp_transform_type'] = []
        rp['rwp_guard_band_flag'] = []
        rp['proj_region_width'] = []
        rp['proj_region_height'] = []
        rp['proj_region_top'] = []
        rp['proj_region_left'] = []
        rp['packed_region_width'] = []
        rp['packed_region_height'] = []
        rp['packed_region_top'] = []
        rp['packed_region_left'] = []
        rp['left_guard_band_width'] = []
        rp['right_guard_band_width'] = []
        rp['top_guard_band_height'] = []
        rp['bottom_guard_band_height'] = []
        for i in range(rp['num_packed_regions']):
            rp['rwp_reserved_zero_4bits'].append(read_uint_safe(bs, 4))
            rp['rwp_transform_type'].append(read_uint_safe(bs, 3))
            rp['rwp_guard_band_flag'].append(read_bool_safe(bs))
            rp['proj_region_width'].append(read_uint_safe(bs, 32))
            rp['proj_region_height'].append(read_uint_safe(bs, 32))
            rp['proj_region_top'].append(read_uint_safe(bs, 32))
            rp['proj_region_left'].append(read_uint_safe(bs, 32))
            rp['packed_region_width'].append(read_uint_safe(bs, 16))
            rp['packed_region_height'].append(read_uint_safe(bs, 16))
            rp['packed_region_top'].append(read_uint_safe(bs, 16))
            rp['packed_region_left'].append(read_uint_safe(bs, 16))
            if rp['rwp_guard_band_flag'][i]:
                rp['left_guard_band_width'].append(read_uint_safe(bs, 8))
                rp['right_guard_band_width'].append(read_uint_safe(bs, 8))
                rp['top_guard_band_height'].append(read_uint_safe(bs, 8))
                rp['bottom_guard_band_height'].append(read_uint_safe(bs, 8))
            else:
                rp['left_guard_band_width'].append(None)
                rp['right_guard_band_width'].append(None)
                rp['top_guard_band_height'].append(None)
                rp['bottom_guard_band_height'].append(None)
    return rp

def parse_omni_viewport(bs):
    ov = {}
    ov['omni_viewport_id'] = read_ue_safe(bs)
    ov['omni_viewport_cancel_flag'] = read_bool_safe(bs)
    if not ov['omni_viewport_cancel_flag']:
        ov['omni_viewport_persistence_flag'] = read_bool_safe(bs)
        ov['omni_viewport_cnt_minus1'] = read_uint_safe(bs, 4)
        ov['omni_viewport_azimuth'] = []
        ov['omni_viewport_elevation'] = []
        ov['omni_viewport_tilt'] = []
        ov['omni_viewport_hor_range'] = []
        ov['omni_viewport_ver_range'] = []
        for i in range(ov['omni_viewport_cnt_minus1'] + 1):
            ov['omni_viewport_azimuth'].append(read_se_safe(bs))
            ov['omni_viewport_elevation'].append(read_se_safe(bs))
            ov['omni_viewport_tilt'].append(read_se_safe(bs))
            ov['omni_viewport_hor_range'].append(read_ue_safe(bs))
            ov['omni_viewport_ver_range'].append(read_ue_safe(bs))
    return ov

def parse_regional_nesting(bs):
    rn = {}
    rn['regional_nesting_id'] = read_ue_safe(bs)
    rn['regional_nesting_cancel_flag'] = read_bool_safe(bs)
    if not rn['regional_nesting_cancel_flag']:
        rn['regional_nesting_persistence_flag'] = read_bool_safe(bs)
        rn['num_regions_minus1'] = read_ue_safe(bs)
        rn['regional_nesting_sei_payload'] = []
        for i in range(rn['num_regions_minus1'] + 1):
            rn['regional_nesting_sei_payload'].append(parse_sei_payload(bs))
    return rn

def parse_mcts_extraction_info_sets(bs):
    meis = {}
    meis['num_mcts_sets'] = read_ue_safe(bs)
    meis['num_mcts_in_set_minus1'] = []
    meis['default_target_output_layer_idc'] = []
    meis['extraction_info_present_for_set'] = []
    meis['num_referenced_mcts'] = []
    meis['referenced_mcts_idx'] = []
    for i in range(meis['num_mcts_sets']):
        meis['num_mcts_in_set_minus1'].append(read_ue_safe(bs))
        meis['default_target_output_layer_idc'].append(read_uint_safe(bs, 2))
        meis['extraction_info_present_for_set'].append(read_bool_safe(bs))
        if meis['extraction_info_present_for_set'][i]:
            meis['num_referenced_mcts'].append(read_ue_safe(bs))
            meis['referenced_mcts_idx'].append([])
            for j in range(meis['num_referenced_mcts'][i]):
                meis['referenced_mcts_idx'][i].append(read_ue_safe(bs))
    return meis

def parse_mcts_extraction_info_nesting(bs):
    mein = {}
    mein['all_mcts_flag'] = read_bool_safe(bs)
    if not mein['all_mcts_flag']:
        mein['num_mcts'] = read_ue_safe(bs)
        mein['mcts_id'] = [read_ue_safe(bs) for _ in range(mein['num_mcts'])]
    mein['nested_sei_payloads'] = []
    while more_data_in_payload(bs):
        mein['nested_sei_payloads'].append(parse_sei_payload(bs))
    return mein

def parse_alpha_channel_info(bs):
    aci = {}
    aci['alpha_channel_cancel_flag'] = read_bool_safe(bs)
    if not aci['alpha_channel_cancel_flag']:
        aci['alpha_channel_use_idc'] = read_uint_safe(bs, 3)
        aci['alpha_channel_bit_depth_minus8'] = read_uint_safe(bs, 3)
        aci['alpha_transparent_value'] = read_uint_safe(bs, aci['alpha_channel_bit_depth_minus8'] + 8)
        aci['alpha_opaque_value'] = read_uint_safe(bs, aci['alpha_channel_bit_depth_minus8'] + 8)
        aci['alpha_channel_incr_flag'] = read_bool_safe(bs)
        aci['alpha_channel_clip_flag'] = read_bool_safe(bs)
        if aci['alpha_channel_clip_flag']:
            aci['alpha_channel_clip_type_flag'] = read_bool_safe(bs)
    return aci

def parse_depth_representation_info(bs):
    dri = {}
    dri['z_near_flag'] = read_bool_safe(bs)
    dri['z_far_flag'] = read_bool_safe(bs)
    dri['d_min_flag'] = read_bool_safe(bs)
    dri['d_max_flag'] = read_bool_safe(bs)
    dri['depth_representation_type'] = read_uint_safe(bs, 3)
    if dri['z_near_flag']:
        dri['z_near_val'] = read_uint_safe(bs, 32)
    if dri['z_far_flag']:
        dri['z_far_val'] = read_uint_safe(bs, 32)
    if dri['d_min_flag']:
        dri['d_min_val'] = read_uint_safe(bs, 32)
    if dri['d_max_flag']:
        dri['d_max_val'] = read_uint_safe(bs, 32)
    if dri['depth_representation_type'] == 3:
        dri['depth_nonlinear_representation_num_minus1'] = read_uint_safe(bs, 16)
        dri['depth_nonlinear_representation_model'] = [read_uint_safe(bs, 16) for _ in range(dri['depth_nonlinear_representation_num_minus1'] + 1)]
    return dri

def parse_multiview_scene_info(bs):
    msi = {}
    msi['min_disparity'] = read_se_safe(bs)
    msi['max_disparity_range'] = read_ue_safe(bs)
    return msi

def parse_multiview_acquisition_info(bs):
    mai = {}
    mai['intrinsic_param_flag'] = read_bool_safe(bs)
    mai['extrinsic_param_flag'] = read_bool_safe(bs)
    mai['num_views_minus1'] = read_ue_safe(bs)
    if mai['intrinsic_param_flag']:
        mai['intrinsic_params_equal_flag'] = read_bool_safe(bs)
        mai['prec_focal_length'] = read_ue_safe(bs)
        mai['prec_principal_point'] = read_ue_safe(bs)
        mai['prec_skew_factor'] = read_ue_safe(bs)
        num_views = 1 if mai['intrinsic_params_equal_flag'] else mai['num_views_minus1'] + 1
        mai['sign_focal_length_x'] = [read_bool_safe(bs) for _ in range(num_views)]
        mai['exponent_focal_length_x'] = [read_uint_safe(bs, 6) for _ in range(num_views)]
        mai['mantissa_focal_length_x'] = [read_uint_safe(bs, mai['prec_focal_length']) for _ in range(num_views)]
        mai['sign_focal_length_y'] = [read_bool_safe(bs) for _ in range(num_views)]
        mai['exponent_focal_length_y'] = [read_uint_safe(bs, 6) for _ in range(num_views)]
        mai['mantissa_focal_length_y'] = [read_uint_safe(bs, mai['prec_focal_length']) for _ in range(num_views)]
        mai['sign_principal_point_x'] = [read_bool_safe(bs) for _ in range(num_views)]
        mai['exponent_principal_point_x'] = [read_uint_safe(bs, 6) for _ in range(num_views)]
        mai['mantissa_principal_point_x'] = [read_uint_safe(bs, mai['prec_principal_point']) for _ in range(num_views)]
        mai['sign_principal_point_y'] = [read_bool_safe(bs) for _ in range(num_views)]
        mai['exponent_principal_point_y'] = [read_uint_safe(bs, 6) for _ in range(num_views)]
        mai['mantissa_principal_point_y'] = [read_uint_safe(bs, mai['prec_principal_point']) for _ in range(num_views)]
        mai['sign_skew_factor'] = [read_bool_safe(bs) for _ in range(num_views)]
        mai['exponent_skew_factor'] = [read_uint_safe(bs, 6) for _ in range(num_views)]
        mai['mantissa_skew_factor'] = [read_uint_safe(bs, mai['prec_skew_factor']) for _ in range(num_views)]
    if mai['extrinsic_param_flag']:
        mai['prec_rotation_param'] = read_ue_safe(bs)
        mai['prec_translation_param'] = read_ue_safe(bs)
        for i in range(mai['num_views_minus1']):
            mai[f'sign_r_{i}'] = [read_bool_safe(bs) for _ in range(3)]
            mai[f'exponent_r_{i}'] = [read_uint_safe(bs, 6) for _ in range(3)]
            mai[f'mantissa_r_{i}'] = [read_uint_safe(bs, mai['prec_rotation_param']) for _ in range(3)]
            mai[f'sign_t_{i}'] = [read_bool_safe(bs) for _ in range(3)]
            mai[f'exponent_t_{i}'] = [read_uint_safe(bs, 6) for _ in range(3)]
            mai[f'mantissa_t_{i}'] = [read_uint_safe(bs, mai['prec_translation_param']) for _ in range(3)]
    return mai

def parse_multiview_view_position(bs):
    mvp = {}
    mvp['num_views_minus1'] = read_ue_safe(bs)
    mvp['view_position'] = [read_ue_safe(bs) for _ in range(mvp['num_views_minus1'] + 1)]
    return mvp

def parse_sei_manifest(bs):
    sm = {}
    sm['manifest_num_sei_msg_types'] = read_ue_safe(bs)
    sm['manifest_sei_payload_type'] = []
    sm['manifest_sei_description'] = []
    for i in range(sm['manifest_num_sei_msg_types']):
        sm['manifest_sei_payload_type'].append(read_uint_safe(bs, 16))
        sm['manifest_sei_description'].append(read_string(bs))
    return sm

def parse_sei_prefix_indication(bs):
    spi = {}
    spi['num_sei_prefix_indications_minus1'] = read_ue_safe(bs)
    spi['prefix_sei_payload_type'] = []
    spi['num_bits_in_prefix_indication_minus1'] = []
    spi['sei_prefix_data_bit'] = []
    for i in range(spi['num_sei_prefix_indications_minus1'] + 1):
        spi['prefix_sei_payload_type'].append(read_uint_safe(bs, 16))
        spi['num_bits_in_prefix_indication_minus1'].append(read_ue_safe(bs))
        spi['sei_prefix_data_bit'].append([read_bool_safe(bs) for _ in range(spi['num_bits_in_prefix_indication_minus1'][i] + 1)])
    return spi

def parse_annotated_regions(bs):
    ar = {}
    ar['annotated_regions_cancel_flag'] = read_bool_safe(bs)
    if not ar['annotated_regions_cancel_flag']:
        ar['annotated_regions_persistence_flag'] = read_bool_safe(bs)
        ar['num_annotated_regions'] = read_ue_safe(bs)
        ar['annotated_regions'] = []
        for i in range(ar['num_annotated_regions']):
            region = {}
            region['annotated_region_id'] = read_ue_safe(bs)
            region['annotated_region_bounding_box_specified'] = read_bool_safe(bs)
            if region['annotated_region_bounding_box_specified']:
                region['ar_left_horiz_offset'] = read_ue_safe(bs)
                region['ar_right_horiz_offset'] = read_ue_safe(bs)
                region['ar_top_vert_offset'] = read_ue_safe(bs)
                region['ar_bottom_vert_offset'] = read_ue_safe(bs)
            region['annotated_region_label_flags'] = read_uint_safe(bs, 3)
            if region['annotated_region_label_flags'] & 1:
                region['annotated_region_label'] = read_string(bs)
            if region['annotated_region_label_flags'] & 2:
                region['annotated_region_header_label'] = read_string(bs)
            if region['annotated_region_label_flags'] & 4:
                region['annotated_region_body_label'] = read_string(bs)
            ar['annotated_regions'].append(region)
    return ar

def read_string(bs):
    string_length = read_ue_safe(bs)
    return ''.join([chr(read_uint_safe(bs, 8)) for _ in range(string_length)])

def more_rbsp_data(bs):
    if bs.pos >= bs.len:
        return False
    current_pos = bs.pos
    trailing_bits = bs.read(f'bin:{bs.len - bs.pos}')
    bs.pos = current_pos  # Reset position
    return '1' in trailing_bits[:-8]

def parse_slice_segment(data, nal_unit_type, sps, pps, shared_state=None):
    """
    Parse a single slice segment, initializing shared state when necessary.
    """
    slice_segment = {}
    bs = BitStream(data)
    
    # Parse slice_segment_header
    slice_segment['header'] = parse_slice_segment_header(bs, nal_unit_type, sps, pps)

    return slice_segment


def parse_slice_segment_header(bs, nal_unit_type, sps, pps):
    slice_header = {}

    slice_header['first_slice_segment_in_pic_flag'] = read_bool_safe(bs)

    if nal_unit_type >= 16 and nal_unit_type <= 23:
        slice_header['no_output_of_prior_pics_flag'] = read_bool_safe(bs)

    slice_header['slice_pic_parameter_set_id'] = read_ue_safe(bs)

    slice_header['dependent_slice_segment_flag'] = False  # Set the default value
    slice_header['slice_segment_address'] = 0 if slice_header['first_slice_segment_in_pic_flag'] else None # Set the default value

    if slice_header.get('first_slice_segment_in_pic_flag', False) == False:
        if pps.get('dependent_slice_segments_enabled_flag', False):
            slice_header['dependent_slice_segment_flag'] = read_bool_safe(bs)

        log2_min = sps.get('log2_min_luma_coding_block_size_minus3', 0) + 3
        log2_diff = sps.get('log2_diff_max_min_luma_coding_block_size', 0)
        CtbLog2SizeY = log2_min + log2_diff
        CtbSizeY = 1 << CtbLog2SizeY
        pic_width  = sps.get('pic_width_in_luma_samples', 0)
        pic_height = sps.get('pic_height_in_luma_samples', 0)
        PicWidthInCtbsY  = (pic_width  + CtbSizeY - 1) // CtbSizeY
        PicHeightInCtbsY = (pic_height + CtbSizeY - 1) // CtbSizeY
        PicSizeInCtbsY   = PicWidthInCtbsY * PicHeightInCtbsY

        if PicSizeInCtbsY > 0:
            num_bits = max(1, math.ceil(math.log2(PicSizeInCtbsY)))
            slice_header['slice_segment_address'] = read_uint_safe(bs, num_bits)
        else:
            slice_header['slice_segment_address'] = 0

    if slice_header.get('dependent_slice_segment_flag') == False:
        slice_header['slice_reserved_flag'] = [read_bool_safe(bs) for _ in range(pps.get('num_extra_slice_header_bits', 0))]

        slice_header['slice_type'] = read_ue_safe(bs)  # 0 = B, 1 = P, 2 = I
        if slice_header['slice_type'] == 0:
            slice_header['slice_type'] = 'B'
        elif slice_header['slice_type'] == 1:
            slice_header['slice_type'] = 'P'
        elif slice_header['slice_type'] == 2:
            slice_header['slice_type'] = 'I'

        if not slice_header['slice_type'] in ['B', 'P', 'I']:
            print("Error: slice type not supported")
            return False

        if pps.get('output_flag_present_flag', False):
            slice_header['pic_output_flag'] = read_bool_safe(bs)

        if sps.get('separate_colour_plane_flag', False):
            slice_header['colour_plane_id'] = read_uint_safe(bs, 2)

        if nal_unit_type != 19 and nal_unit_type != 20:
            slice_header['slice_pic_order_cnt_lsb'] = read_uint_safe(bs, sps['log2_max_pic_order_cnt_lsb_minus4'] + 4)
            slice_header['short_term_ref_pic_set_sps_flag'] = read_bool_safe(bs)

            num_short_term_ref_pic_sets = sps['num_short_term_ref_pic_sets']

            if slice_header.get('short_term_ref_pic_set_sps_flag') == False:
                stRpsIdx = num_short_term_ref_pic_sets
                slice_header['short_term_ref_pic_set'] = parse_short_term_ref_pic_set(bs, stRpsIdx, num_short_term_ref_pic_sets)
            elif num_short_term_ref_pic_sets > 1:
                bit_length = math.ceil(math.log2(num_short_term_ref_pic_sets))
                slice_header['short_term_ref_pic_set_idx'] = read_uint_safe(bs, bit_length)
                
            if sps.get('long_term_ref_pics_present_flag', False):
                if sps.get('num_long_term_ref_pics_sps', 0) > 0:
                    slice_header['num_long_term_sps'] = read_ue_safe(bs)
                slice_header['num_long_term_pics'] = read_ue_safe(bs)

                slice_header['lt_idx_sps'] = list()
                slice_header['poc_lsb_lt'] = list()
                slice_header['used_by_curr_pic_lt_flag'] = list()
                slice_header['delta_poc_msb_present_flag'] = list()
                slice_header['delta_poc_msb_cycle_lt'] = list()

                num_long_term = slice_header['num_long_term_sps'] + slice_header['num_long_term_pics']
                for _ in range(num_long_term):
                    if slice_header['num_long_term_sps'] > 0:
                        if math.ceil(math.log2(sps['num_long_term_ref_pics_sps'])) != 0:
                            slice_header['lt_idx_sps'].append(read_uint_safe(bs, math.ceil(math.log2(sps['num_long_term_ref_pics_sps']))))
                        else:
                            slice_header['lt_idx_sps'].append(None)
                    slice_header['poc_lsb_lt'].append(read_uint_safe(bs, sps['log2_max_pic_order_cnt_lsb_minus4'] + 4))
                    slice_header['used_by_curr_pic_lt_flag'].append(read_bool_safe(bs))
                    slice_header['delta_poc_msb_present_flag'].append(read_bool_safe(bs))
                    if slice_header['delta_poc_msb_present_flag'][-1]:
                        slice_header['delta_poc_msb_cycle_lt'].append(read_ue_safe(bs))
                    else:
                        slice_header['delta_poc_msb_cycle_lt'].append(None)

            if sps.get('sps_temporal_mvp_enabled_flag', False):
                slice_header['slice_temporal_mvp_enabled_flag'] = read_bool_safe(bs)

        if sps.get('sample_adaptive_offset_enabled_flag', False):
            slice_header['slice_sao_luma_flag']  = read_bool_safe(bs)
            cfi = sps.get('chroma_format_idc', 1)
            scp = sps.get('separate_colour_plane_flag', 0)
            ChromaArrayType = 0 if (cfi == 3 and scp == 1) else cfi
            if ChromaArrayType != 0:
                slice_header['slice_sao_chroma_flag'] = read_bool_safe(bs)

        if slice_header['slice_type'] in ['B', 'P']:
            slice_header['num_ref_idx_active_override_flag'] = read_bool_safe(bs)
            if slice_header.get('num_ref_idx_active_override_flag'):
                slice_header['num_ref_idx_l0_active_minus1'] = read_ue_safe(bs)
                if slice_header['slice_type'] == 'B':
                    slice_header['num_ref_idx_l1_active_minus1'] = read_ue_safe(bs)

            NumPocTotalurr = 0
            for i in slice_header.get('short_term_ref_pic_set', {}).get('used_by_curr_pic_flag', []):
                NumPocTotalurr += 1
            for lt_flag in slice_header.get('used_by_curr_pic_lt_flag', []):
                if lt_flag:
                    NumPocTotalurr += 1
            
            if pps.get('lists_modification_present_flag', False) and NumPocTotalurr > 1:
                slice_header['ref_pic_lists_modification'] = parse_ref_pic_lists_modification(bs, slice_header)

            if slice_header['slice_type'] == 'B':
                slice_header['mvd_l1_zero_flag'] = read_bool_safe(bs)

            if pps.get('cabac_init_present_flag', False):
                slice_header['cabac_init_flag'] = read_bool_safe(bs)

            if slice_header.get('slice_temporal_mvp_enabled_flag'):
                if slice_header['slice_type'] == 'B':
                    slice_header['collocated_from_l0_flag'] = read_bool_safe(bs)
                if (slice_header.get('collocated_from_l0_flag') and slice_header.get('num_ref_idx_l0_active_minus1') is not None and slice_header.get('num_ref_idx_l0_active_minus1') > 0) or \
                        (not slice_header.get('collocated_from_l0_flag') and slice_header.get(
                            'num_ref_idx_l1_active_minus1') is not None and slice_header.get(
                            'num_ref_idx_l1_active_minus1') > 0):
                    slice_header['collocated_ref_idx'] = read_ue_safe(bs)

            if (pps.get('weighted_pred_flag', False) and slice_header['slice_type'] == 'P') or \
                    (pps.get('weighted_bipred_flag', False) and slice_header['slice_type'] == 'B'):
                slice_header['pred_weight_table'] = parse_pred_weight_table(bs, slice_header, sps,
                                                                            slice_header.get('num_ref_idx_l0_active_minus1'),
                                                                            slice_header.get('num_ref_idx_l1_active_minus1'))

            slice_header['five_minus_max_num_merge_cand'] = read_ue_safe(bs)

            if sps.get('sps_scc_extension_flag', False):
                scc_ext = sps.get('scc_extension', {})
                if scc_ext.get('motion_vector_resolution_control_idc', 0) == 2:
                    slice_header['use_integer_mv_flag'] = read_bool_safe(bs)

        slice_header['slice_qp_delta'] = read_se_safe(bs)

        if pps.get('pps_slice_chroma_qp_offsets_present_flag', False):
            slice_header['slice_cb_qp_offset'] = read_se_safe(bs)
            slice_header['slice_cr_qp_offset'] = read_se_safe(bs)

        if pps.get('pps_slice_act_qp_offsets_present_flag', False):
            slice_header['slice_act_y_qp_offset'] = read_se_safe(bs)
            slice_header['slice_act_cb_qp_offset'] = read_se_safe(bs)
            slice_header['slice_act_cr_qp_offset'] = read_se_safe(bs)

        if pps.get('pps_range_extension', {}):
            if pps['pps_range_extension'].get('chroma_qp_offset_list_enabled_flag', False):
                slice_header['cu_chroma_qp_offset_enabled_flag'] = read_bool_safe(bs)

        if pps.get('deblocking_filter_override_enabled_flag', False):
            slice_header['deblocking_filter_override_flag'] = read_bool_safe(bs)
        if slice_header.get('deblocking_filter_override_flag'):
            slice_header['slice_deblocking_filter_disabled_flag'] = read_bool_safe(bs)
            if not slice_header.get('slice_deblocking_filter_disabled_flag'):
                slice_header['slice_beta_offset_div2'] = read_se_safe(bs)
                slice_header['slice_tc_offset_div2'] = read_se_safe(bs)

        if pps.get('pps_loop_filter_across_slices_enabled_flag', False) and (slice_header.get('slice_sao_luma_flag') or slice_header.get('slice_sao_chroma_flag') or not slice_header.get('slice_deblocking_filter_disabled_flag')):
            slice_header['slice_loop_filter_across_slices_enabled_flag'] = read_bool_safe(bs)


    if pps.get('tiles_enabled_flag', False) or pps.get('entropy_coding_sync_enabled_flag', False):
        slice_header['num_entry_point_offsets'] = read_ue_safe(bs)
        if slice_header.get('num_entry_point_offsets') is not None:
            if slice_header['num_entry_point_offsets'] > 0:
                slice_header['offset_len_minus1'] = read_ue_safe(bs)
                if slice_header['num_entry_point_offsets'] > 1000:
                    slice_header['entry_point_offset_minus1'] = [None]
                else:
                    slice_header['entry_point_offset_minus1'] = [
                        read_uint_safe(bs, slice_header['offset_len_minus1'] + 1) for _ in
                        range(slice_header['num_entry_point_offsets'])]

    if pps.get('slice_segment_header_extension_present_flag', False):
        slice_header['slice_segment_header_extension_length'] = read_ue_safe(bs)
        slice_header['slice_segment_header_extension_data_byte'] = [read_uint_safe(bs, 8) for _ in range(
            slice_header['slice_segment_header_extension_length'])]

    byte_alignment(bs)

    return slice_header

def parse_ref_pic_lists_modification(bs, slice_header):
    ref_pic_list_modification = {}

    ref_pic_list_modification['ref_pic_list_modification_flag_l0'] = read_bool_safe(bs)
    if ref_pic_list_modification['ref_pic_list_modification_flag_l0']:
        ref_pic_list_modification['list_entry_l0'] = []
        for i in range(slice_header['num_ref_idx_l0_active_minus1'] + 1):
            ref_pic_list_modification['list_entry_l0'].append(read_ue_safe(bs))

    if slice_header['slice_type'] == 'B':
        ref_pic_list_modification['ref_pic_list_modification_flag_l1'] = read_bool_safe(bs)
        if ref_pic_list_modification['ref_pic_list_modification_flag_l1']:
            ref_pic_list_modification['list_entry_l1'] = []
            for i in range(slice_header['num_ref_idx_l1_active_minus1'] + 1):
                ref_pic_list_modification['list_entry_l1'].append(read_ue_safe(bs))

    return ref_pic_list_modification

def parse_pred_weight_table(bs, slice_header, sps, num_ref_idx_l0_active_minus1, num_ref_idx_l1_active_minus1):
    pred_weight_table = {}

    ChromaArrayType = sps['chroma_format_idc'] if sps.get('separate_colour_plane_flag', 0) == 0 else 0

    pred_weight_table['luma_log2_weight_denom'] = read_ue_safe(bs)
    if ChromaArrayType != 0:
        pred_weight_table['delta_chroma_log2_weight_denom'] = read_se_safe(bs)

    pred_weight_table['luma_weight_l0'] = []
    pred_weight_table['luma_offset_l0'] = []
    pred_weight_table['chroma_weight_l0'] = []
    pred_weight_table['chroma_offset_l0'] = []
    if num_ref_idx_l0_active_minus1 is not None:
        for i in range(num_ref_idx_l0_active_minus1 + 1):
            pred_weight_table['luma_weight_l0_flag'] = read_bool_safe(bs)
            if pred_weight_table['luma_weight_l0_flag']:
                pred_weight_table['luma_weight_l0'].append(read_se_safe(bs))
                pred_weight_table['luma_offset_l0'].append(read_se_safe(bs))
            if ChromaArrayType != 0:
                pred_weight_table['chroma_weight_l0_flag'] = read_bool_safe(bs)
                if pred_weight_table['chroma_weight_l0_flag']:
                    pred_weight_table['delta_chroma_weight_l0'] = [[read_se_safe(bs) for _ in range(2)] for _ in range(num_ref_idx_l0_active_minus1 + 1)]
                    pred_weight_table['delta_chroma_offset_l0'] = [[read_se_safe(bs) for _ in range(2)] for _ in range(num_ref_idx_l0_active_minus1 + 1)]

    if num_ref_idx_l1_active_minus1 is not None:
        if slice_header['slice_type'] == 'B':  # B-frame
            pred_weight_table['luma_weight_l1'] = []
            pred_weight_table['luma_offset_l1'] = []
            pred_weight_table['chroma_weight_l1'] = []
            pred_weight_table['chroma_offset_l1'] = []

            for i in range(num_ref_idx_l1_active_minus1 + 1):
                pred_weight_table['luma_weight_l1_flag'] = read_bool_safe(bs)
                if pred_weight_table['luma_weight_l1_flag']:
                    pred_weight_table['luma_weight_l1'].append(read_se_safe(bs))
                    pred_weight_table['luma_offset_l1'].append(read_se_safe(bs))
                if ChromaArrayType != 0:
                    pred_weight_table['chroma_weight_l1_flag'] = read_bool_safe(bs)
                    if pred_weight_table['chroma_weight_l1_flag']:
                        pred_weight_table['delta_chroma_weight_l1'] = [[read_se_safe(bs) for _ in range(2)] for _ in range(num_ref_idx_l1_active_minus1 + 1)]
                        pred_weight_table['delta_chroma_offset_l1'] = [[read_se_safe(bs) for _ in range(2)] for _ in range(num_ref_idx_l1_active_minus1 + 1)]

    return pred_weight_table



def parse_aud(data):
    bs = BitStream(data)
    aud = {}
    aud['primary_pic_type'] = read_uint_safe(bs, 3)
    return aud

def parse_eos(data):
    return {}

def parse_eob(data):
    return {}

def parse_fd(data):
    bs = BitStream(data)
    fd = {}
    fd['fd_intensity_compensation_flag'] = read_bool_safe(bs)
    return fd

def parse_vui_parameters(bs, sps):
    vui = {}

    vui['aspect_ratio_info_present_flag'] = read_bool_safe(bs)
    if vui['aspect_ratio_info_present_flag']:
        vui['aspect_ratio_idc'] = read_uint_safe(bs, 8)
        if vui['aspect_ratio_idc'] == 255:  # EXTENDED_SAR
            vui['sar_width'] = read_uint_safe(bs, 16)
            vui['sar_height'] = read_uint_safe(bs, 16)

    vui['overscan_info_present_flag'] = read_bool_safe(bs)
    if vui['overscan_info_present_flag']:
        vui['overscan_appropriate_flag'] = read_bool_safe(bs)

    vui['video_signal_type_present_flag'] = read_bool_safe(bs)
    if vui['video_signal_type_present_flag']:
        vui['video_format'] = read_uint_safe(bs, 3)
        vui['video_full_range_flag'] = read_bool_safe(bs)
        vui['colour_description_present_flag'] = read_bool_safe(bs)
        if vui['colour_description_present_flag']:
            vui['colour_primaries'] = read_uint_safe(bs, 8)
            vui['transfer_characteristics'] = read_uint_safe(bs, 8)
            vui['matrix_coeffs'] = read_uint_safe(bs, 8)

    vui['chroma_loc_info_present_flag'] = read_bool_safe(bs)
    if vui['chroma_loc_info_present_flag']:
        vui['chroma_sample_loc_type_top_field'] = read_ue_safe(bs)
        vui['chroma_sample_loc_type_bottom_field'] = read_ue_safe(bs)

    vui['neutral_chroma_indication_flag'] = read_bool_safe(bs)
    vui['field_seq_flag'] = read_bool_safe(bs)
    vui['frame_field_info_present_flag'] = read_bool_safe(bs)
    vui['default_display_window_flag'] = read_bool_safe(bs)
    if vui['default_display_window_flag']:
        vui['def_disp_win_left_offset'] = read_ue_safe(bs)
        vui['def_disp_win_right_offset'] = read_ue_safe(bs)
        vui['def_disp_win_top_offset'] = read_ue_safe(bs)
        vui['def_disp_win_bottom_offset'] = read_ue_safe(bs)

    vui['vui_timing_info_present_flag'] = read_bool_safe(bs)
    if vui['vui_timing_info_present_flag']:
        vui['vui_num_units_in_tick'] = read_uint_safe(bs, 32)
        vui['vui_time_scale'] = read_uint_safe(bs, 32)
        vui['vui_poc_proportional_to_timing_flag'] = read_bool_safe(bs)
        if vui['vui_poc_proportional_to_timing_flag']:
            vui['vui_num_ticks_poc_diff_one_minus1'] = read_ue_safe(bs)

    vui['vui_hrd_parameters_present_flag'] = read_bool_safe(bs)
    if vui['vui_hrd_parameters_present_flag']:
        vui['hrd_parameters'] = parse_hrd_parameters(bs, True,
                                                     sps.get('sps_max_sub_layers_minus1'))  # Assuming values based on common_inf_present_flag and max_num_sub_layers_minus1

    vui['bitstream_restriction_flag'] = read_bool_safe(bs)
    if vui['bitstream_restriction_flag']:
        vui['tiles_fixed_structure_flag'] = read_bool_safe(bs)
        vui['motion_vectors_over_pic_boundaries_flag'] = read_bool_safe(bs)
        vui['restricted_ref_pic_lists_flag'] = read_bool_safe(bs)
        vui['min_spatial_segmentation_idc'] = read_ue_safe(bs)
        vui['max_bytes_per_pic_denom'] = read_ue_safe(bs)
        vui['max_bits_per_min_cu_denom'] = read_ue_safe(bs)
        vui['log2_max_mv_length_horizontal'] = read_ue_safe(bs)
        vui['log2_max_mv_length_vertical'] = read_ue_safe(bs)

    return vui

def parse_hrd_parameters(bs, common_inf_present_flag, max_num_sub_layers_minus1):
    hrd = {}
    hrd['nal_hrd_parameters_present_flag'] = False
    hrd['vcl_hrd_parameters_present_flag'] = False

    if common_inf_present_flag:
        hrd['nal_hrd_parameters_present_flag'] = read_bool_safe(bs)
        hrd['vcl_hrd_parameters_present_flag'] = read_bool_safe(bs)

        if hrd['nal_hrd_parameters_present_flag'] or hrd['vcl_hrd_parameters_present_flag']:
            hrd['sub_pic_hrd_params_present_flag'] = read_bool_safe(bs)
            if hrd['sub_pic_hrd_params_present_flag']:
                hrd['tick_divisor_minus2'] = read_uint_safe(bs, 8)
                hrd['du_cpb_removal_delay_increment_length_minus1'] = read_uint_safe(bs, 5)
                hrd['sub_pic_cpb_params_in_pic_timing_sei_flag'] = read_bool_safe(bs)
                hrd['dpb_output_delay_du_length_minus1'] = read_uint_safe(bs, 5)
            hrd['bit_rate_scale'] = read_uint_safe(bs, 4)
            hrd['cpb_size_scale'] = read_uint_safe(bs, 4)
            if hrd['sub_pic_hrd_params_present_flag']:
                hrd['cpb_size_du_scale'] = read_uint_safe(bs, 4)
            hrd['initial_cpb_removal_delay_length_minus1'] = read_uint_safe(bs, 5)
            hrd['au_cpb_removal_delay_length_minus1'] = read_uint_safe(bs, 5)
            hrd['dpb_output_delay_length_minus1'] = read_uint_safe(bs, 5)

    hrd['fixed_pic_rate_general_flag'] = []
    hrd['fixed_pic_rate_within_cvs_flag'] = []
    hrd['low_delay_hrd_flag'] = []
    hrd['cpb_cnt_minus1'] = []
    hrd['bit_rate_value_minus1'] = []
    hrd['cpb_size_value_minus1'] = []
    hrd['cpb_size_du_value_minus1'] = []
    hrd['bit_rate_du_value_minus1'] = []
    hrd['cbr_flag'] = []
    hrd['elemental_duration_in_tc_minus1'] = []


    for i in range(max_num_sub_layers_minus1 + 1):
        hrd['fixed_pic_rate_general_flag'].append(read_bool_safe(bs))
        if not hrd['fixed_pic_rate_general_flag'][i]:
            hrd['fixed_pic_rate_within_cvs_flag'].append(read_bool_safe(bs))
        else:
            hrd['fixed_pic_rate_within_cvs_flag'].append(0)
        if hrd['fixed_pic_rate_within_cvs_flag'][i]:
            hrd['elemental_duration_in_tc_minus1'].append(read_ue_safe(bs))
        else:
            hrd['elemental_duration_in_tc_minus1'].append(None)
        hrd['low_delay_hrd_flag'].append(read_bool_safe(bs))
        if not hrd['low_delay_hrd_flag'][i]:
            hrd['cpb_cnt_minus1'].append(read_ue_safe(bs))
        else:
            hrd['cpb_cnt_minus1'].append(None)

        if hrd['nal_hrd_parameters_present_flag'] or hrd['vcl_hrd_parameters_present_flag']:
            if hrd['cpb_cnt_minus1'][i] is not None:
                for j in range(hrd['cpb_cnt_minus1'][i] + 1):
                    if hrd['nal_hrd_parameters_present_flag']:
                        hrd['bit_rate_value_minus1'].append(read_ue_safe(bs))
                        hrd['cpb_size_value_minus1'].append(read_ue_safe(bs))
                        if hrd['sub_pic_hrd_params_present_flag']:
                            hrd['cpb_size_du_value_minus1'].append(read_ue_safe(bs))
                            hrd['bit_rate_du_value_minus1'].append(read_ue_safe(bs))
                        hrd['cbr_flag'].append(read_bool_safe(bs))

                    if hrd['vcl_hrd_parameters_present_flag']:
                        hrd['bit_rate_value_minus1'].append(read_ue_safe(bs))
                        hrd['cpb_size_value_minus1'].append(read_ue_safe(bs))
                        if hrd['sub_pic_hrd_params_present_flag']:
                            hrd['cpb_size_du_value_minus1'].append(read_ue_safe(bs))
                            hrd['bit_rate_du_value_minus1'].append(read_ue_safe(bs))
                        hrd['cbr_flag'].append(read_bool_safe(bs))

    return hrd


def byte_alignment(bs):
    while bs.pos % 8 != 0:
        bit = bs.read(1)
        if bs.pos % 8 == 0:
            if bit != 1:
                pass
                # print(f"Warning: last bit before byte alignment is not 1 (got {bit})")
        else:
            if bit != 0:
                pass
                # print(f"Warning: non-last bit before byte alignment is not 0 (got {bit})")