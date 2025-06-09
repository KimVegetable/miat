import re
import math
import struct

import bitstring.exceptions
from bitstring import BitStream, BitArray, ReadError

NAL_UNIT_TYPES = {
    1: "Coded slice of a non-IDR picture",
    2: "Coded slice data partition A",
    3: "Coded slice data partition B",
    4: "Coded slice data partition C",
    5: "Coded slice of an IDR picture",
    6: "Supplemental enhancement information (SEI)",
    7: "Sequence parameter set",
    8: "Picture parameter set",
    9: "Access unit delimiter",
    10: "End of sequence",
    11: "End of stream",
    12: "Filler data",
    13: "Sequence parameter set extension",
    19: "Coded slice of an auxiliary coded picture without partitioning",
}

def read_ue_safe(bs):
    if bs.pos < bs.len:
        try:
            return bs.read('ue')
        except ReadError:
            print(f'[Read Error] read_ue_safe - position {bs.pos}')
            raise ReadError
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

def read_bits(bs, num_bits):
    """
    A small helper if we want to read a fixed number of bits and return as int.
    """
    if bs.pos + num_bits <= bs.len:
        try:
            return bs.read(f'bits:{num_bits}')
        except ReadError:
            print(f'[Read Error] read_bits - position {bs.pos}')
            return None
    return None

def read_ae_safe(bs):
    """
    Placeholder for CABAC-coded syntax element (ae(v)).
    Actual CABAC decoding is non-trivial and requires context models.
    """
    # We'll just simulate a bool or small int
    try:
        # Suppose we treat it as a single bit for demonstration
        return bs.read('bool')  
    except ReadError:
        print(f'[Read Error] read_ae_safe - position {bs.pos}')
        return None

def byte_aligned(bs):
    return (bs.pos % 8) == 0

def next_mb_address(curr_mb_addr, MbaffFrameFlag):
    # If MBAFF is on, two MBs form a pair in field mode
    # Simplified:
    return curr_mb_addr + 1

def more_rbsp_data(bs):
    # Check if bitstream still has data or if next bits are trailing
    # Placeholder
    return (bs.pos < bs.len)

def read_mb_field_decoding_flag(bs, entropy_coding_mode_flag):
    if entropy_coding_mode_flag:
        return read_ae_safe(bs)
    else:
        return read_uint_safe(bs, 1)
def get_MbPartPredMode(mb_type, mbPartIdx, slice_type):
    """
    Returns something like "Intra_16x16", "Intra_4x4", "Pred_L0", "Direct", etc.
    Real logic uses the standard's mb_type mapping.
    """
    # Placeholder
    if mb_type in ["I_NxN", "Intra_4x4", "Intra_8x8", "Intra_16x16"]:
        return mb_type
    if slice_type == "B":
        return "Direct"
    return "Pred_L0"


def get_NumMbPart(mb_type, slice_type):
    """
    Returns how many MB partitions for the given mb_type.
    """
    # Placeholder
    if mb_type in ["P_8x8", "B_8x8"]:
        return 4
    return 1


def mb_part_pred_mode_is_intra16x16(mb_type, slice_type):
    """
    Check if MbPartPredMode(mb_type,0) == Intra_16x16
    """
    return (mb_type == "Intra_16x16")


def num_sub_mb_part(sub_mb_type):
    """
    Returns the number of sub partitions in sub_mb_type.
    """
    # Placeholder
    return 2 if sub_mb_type not in ["B_Direct_8x8"] else 1


def next_mb_address(curr_mb_addr, MbaffFrameFlag):
    return curr_mb_addr + 1


def read_mb_field_decoding_flag(bs, entropy_coding_mode_flag):
    if entropy_coding_mode_flag:
        return read_ae_safe(bs)
    else:
        return read_uint_safe(bs, 1)

def find_start_codes(data):
    start_codes = []
    i = 0
    while i < len(data) - 3:
        if data[i:i+3] == b'\x00\x00\x01':
            start_codes.append(i)
            i += 3
        elif i < len(data) - 4 and data[i:i+4] == b'\x00\x00\x00\x01':
            start_codes.append(i)
            i += 4
        else:
            i += 1
    return start_codes

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

def parse_h264_nal_units(video_stream_data, sps, pps):
    nal_units = []

    # Use regex to find all NAL unit start codes in the video stream data
    nal_start_codes = [(m.start(), m.end()) for m in re.finditer(b'\x00\x00\x01|\x00\x00\x00\x01', video_stream_data)]
    # nal_start_codes = [(m.start(), m.end()) for m in re.finditer(b'\x00\x00\x00\x01', video_stream_data)]

    for i, (nal_start, nal_end) in enumerate(nal_start_codes):
        start_code_len = nal_end - nal_start
        nal_start = nal_end

        if i + 1 < len(nal_start_codes):
            next_start = nal_start_codes[i + 1][0]
            nal_unit = video_stream_data[nal_start - start_code_len:next_start]
        else:
            nal_unit = video_stream_data[nal_start - start_code_len:]

        nal_units.append(parse_nal_unit(nal_unit, has_start_code=True))

    # Parse each NAL unit
    parsed_sps = None
    parsed_pps = None
    parsed_sei = []
    parsed_slice_segments = []
    parsed_aud = []
    parsed_eos = []
    parsed_filler_data = []
    parsed_sps_extension = []
    parsed_aux_slice = []

    count = 0
    for nal in nal_units:
        # print(count)
        count += 1

        nal_data = nal['raw_data']
        nal_type = nal['nal_type']

        if nal_data[0:4] == b'\x00\x00\x00\x00' or nal_type == b'\x00':
            print(f'{count} 0000000')
            nal['parsed_data'] = nal_data
            continue

        if nal_type == 7:  # SPS
            if sps is None:
                parsed_sps = parse_sps(nal_data)
                nal['parsed_data'] = parsed_sps
            elif sps is not None:
                parsed_sps = parse_sps(sps)
                nal['parsed_data'] = parsed_sps
        elif nal_type == 8:  # PPS
            if pps is None:
                parsed_pps = parse_pps(nal_data, parsed_sps)
                nal['parsed_data'] = parsed_pps
            elif pps is not None:
                parsed_pps = parse_pps(pps, parsed_sps)
                nal['parsed_data'] = parsed_pps
        elif nal_type == 6:  # SEI
            sei_data = parse_sei(nal_data)
            parsed_sei.extend(sei_data)
            nal['parsed_data'] = sei_data
        elif nal_type in [1, 5]:  # Slice types
            if parsed_sps is not None and parsed_pps is not None:
                slice_segment = dict()
                slice_segment['header'], slice_segment['data'] = parse_slice(nal_data, parsed_sps, parsed_pps, nal_type, nal['nal_ref_idc'])
                parsed_slice_segments.append(slice_segment)
                nal['parsed_data'] = slice_segment
            else:
                nal['parsed_data'] = None
        elif nal_type == 9:  # AUD
            aud_data = parse_aud(nal_data)
            parsed_aud.append(aud_data)
            nal['parsed_data'] = aud_data
        elif nal_type in [10, 11]:  # End of Sequence or End of Stream
            eos_data = parse_eos(nal_data)
            parsed_eos.append(eos_data)
            nal['parsed_data'] = eos_data
        elif nal_type == 12:  # Filler data
            filler_data = parse_filler_data(nal_data)
            parsed_filler_data.append(filler_data)
            nal['parsed_data'] = filler_data
        elif nal_type == 13:  # SPS extension
            sps_extension = parse_sps_extension(nal_data)
            parsed_sps_extension.append(sps_extension)
            nal['parsed_data'] = sps_extension
        elif nal_type == 19:  # Auxiliary slice
            aux_slice = parse_aux_slice(nal_data, parsed_sps, parsed_pps)
            parsed_aux_slice.append(aux_slice)
            nal['parsed_data'] = aux_slice
        else:
            nal['parsed_data'] = nal_data  # For now, return raw data for other types

    return {
        'nal_units': nal_units,
        'sps': parsed_sps,
        'pps': parsed_pps,
        'sei': parsed_sei,
        'slice_segments': parsed_slice_segments,
        'aud': parsed_aud,
        'eos': parsed_eos,
        'filler_data': parsed_filler_data,
        'sps_extension': parsed_sps_extension,
        'aux_slice': parsed_aux_slice
    }



def parse_nal_unit(nal_unit, has_start_code):
    if has_start_code:
        start_code_len = 3 if nal_unit[:3] == b'\x00\x00\x01' else 4
        nal_data = nal_unit[start_code_len:]
    else:
        nal_data = nal_unit

    nal_header = nal_data[0]
    nal_type = nal_header & 0x1F
    forbidden_zero_bit = (nal_header >> 7) & 0x01
    nal_ref_idc = (nal_header >> 5) & 0x03

    nal_data = remove_emulation_prevention_bytes(nal_data[1:])

    return {
        'forbidden_zero_bit': forbidden_zero_bit,
        'nal_ref_idc': nal_ref_idc,
        'nal_type': nal_type,
        'data': nal_unit,
        'raw_data': nal_data
    }

def parse_nal_type(nal_type, nal_data):
    if nal_type == 9:  # Access unit delimiter
        return parse_aud(nal_data)
    elif nal_type == 10:  # End of sequence
        return parse_eos(nal_data)
    elif nal_type == 11:  # End of stream
        return parse_eos(nal_data)
    elif nal_type == 12:  # Filler data
        return parse_filler_data(nal_data)
    elif nal_type == 13:  # Sequence parameter set extension
        return parse_sps_extension(nal_data)
    elif nal_type == 19:  # Auxiliary slice
        return parse_aux_slice(nal_data)
    else:
        return nal_data  # For now, return raw data for other types


def parse_sps(data):
    bs = BitStream(data)

    profile_idc = read_uint_safe(bs, 8)
    constraint_set0_flag = read_bool_safe(bs)
    constraint_set1_flag = read_bool_safe(bs)
    constraint_set2_flag = read_bool_safe(bs)
    constraint_set3_flag = read_bool_safe(bs)
    constraint_set4_flag = read_bool_safe(bs)
    constraint_set5_flag = read_bool_safe(bs)
    reserved_zero_2bits = read_uint_safe(bs, 2)
    level_idc = read_uint_safe(bs, 8)
    seq_parameter_set_id = read_ue_safe(bs)

    if profile_idc in [100, 110, 122, 244, 44, 83, 86, 118, 128, 134, 135, 138, 139, 144]:
        chroma_format_idc = read_ue_safe(bs)
        if chroma_format_idc == 3:
            separate_colour_plane_flag = read_bool_safe(bs)
        bit_depth_luma_minus8 = read_ue_safe(bs)
        bit_depth_chroma_minus8 = read_ue_safe(bs)
        qpprime_y_zero_transform_bypass_flag = read_bool_safe(bs)
        seq_scaling_matrix_present_flag = read_bool_safe(bs)
        if seq_scaling_matrix_present_flag:
            for i in range((8 if chroma_format_idc != 3 else 12)):
                seq_scaling_list_present_flag = read_bool_safe(bs)
                if seq_scaling_list_present_flag:
                    sizeOfScalingList = 16 if i < 6 else 64
                    lastScale = 8
                    nextScale = 8
                    for j in range(sizeOfScalingList):
                        if nextScale != 0:
                            delta_scale = read_se_safe(bs)
                            nextScale = (lastScale + delta_scale + 256) % 256
                        lastScale = nextScale if nextScale != 0 else lastScale

    log2_max_frame_num_minus4 = read_ue_safe(bs)
    pic_order_cnt_type = read_ue_safe(bs)
    if pic_order_cnt_type == 0:
        log2_max_pic_order_cnt_lsb_minus4 = read_ue_safe(bs)
    elif pic_order_cnt_type == 1:
        delta_pic_order_always_zero_flag = read_bool_safe(bs)
        offset_for_non_ref_pic = read_se_safe(bs)
        offset_for_top_to_bottom_field = read_se_safe(bs)
        num_ref_frames_in_pic_order_cnt_cycle = read_ue_safe(bs)
        offset_for_ref_frame = []
        for i in range(num_ref_frames_in_pic_order_cnt_cycle):
            offset_for_ref_frame.append(read_se_safe(bs))
    num_ref_frames = read_ue_safe(bs)
    gaps_in_frame_num_value_allowed_flag = read_bool_safe(bs)
    pic_width_in_mbs_minus1 = read_ue_safe(bs)
    pic_height_in_map_units_minus1 = read_ue_safe(bs)
    frame_mbs_only_flag = read_bool_safe(bs)
    if not frame_mbs_only_flag:
        mb_adaptive_frame_field_flag = read_bool_safe(bs)
    direct_8x8_inference_flag = read_bool_safe(bs)
    frame_cropping_flag = read_bool_safe(bs)
    if frame_cropping_flag:
        frame_crop_left_offset = read_ue_safe(bs)
        frame_crop_right_offset = read_ue_safe(bs)
        frame_crop_top_offset = read_ue_safe(bs)
        frame_crop_bottom_offset = read_ue_safe(bs)
    vui_parameters_present_flag = read_bool_safe(bs)

    vui_parameters = None
    if vui_parameters_present_flag:
        vui_parameters = parse_vui_parameters(bs)

    return {
        'profile_idc': profile_idc,
        'constraint_set0_flag': constraint_set0_flag,
        'constraint_set1_flag': constraint_set1_flag,
        'constraint_set2_flag': constraint_set2_flag,
        'constraint_set3_flag': constraint_set3_flag,
        'constraint_set4_flag': constraint_set4_flag,
        'constraint_set5_flag': constraint_set5_flag,
        'reserved_zero_2bits': reserved_zero_2bits,
        'level_idc': level_idc,
        'seq_parameter_set_id': seq_parameter_set_id,
        'chroma_format_idc': chroma_format_idc if profile_idc in [100, 110, 122, 244, 44, 83, 86, 118, 128, 134, 135, 138, 139, 144] else None,
        'separate_colour_plane_flag': separate_colour_plane_flag if 'chroma_format_idc' in locals() and chroma_format_idc == 3 else None,
        'bit_depth_luma_minus8': bit_depth_luma_minus8 if 'chroma_format_idc' in locals() else None,
        'bit_depth_chroma_minus8': bit_depth_chroma_minus8 if 'chroma_format_idc' in locals() else None,
        'qpprime_y_zero_transform_bypass_flag': qpprime_y_zero_transform_bypass_flag if 'chroma_format_idc' in locals() else None,
        'seq_scaling_matrix_present_flag': seq_scaling_matrix_present_flag if 'chroma_format_idc' in locals() else None,
        'log2_max_frame_num_minus4': log2_max_frame_num_minus4,
        'pic_order_cnt_type': pic_order_cnt_type,
        'log2_max_pic_order_cnt_lsb_minus4': log2_max_pic_order_cnt_lsb_minus4 if pic_order_cnt_type == 0 else None,
        'delta_pic_order_always_zero_flag': delta_pic_order_always_zero_flag if pic_order_cnt_type == 1 else None,
        'offset_for_non_ref_pic': offset_for_non_ref_pic if pic_order_cnt_type == 1 else None,
        'offset_for_top_to_bottom_field': offset_for_top_to_bottom_field if pic_order_cnt_type == 1 else None,
        'num_ref_frames_in_pic_order_cnt_cycle': num_ref_frames_in_pic_order_cnt_cycle if pic_order_cnt_type == 1 else None,
        'offset_for_ref_frame': offset_for_ref_frame if pic_order_cnt_type == 1 else None,
        'num_ref_frames': num_ref_frames,
        'gaps_in_frame_num_value_allowed_flag': gaps_in_frame_num_value_allowed_flag,
        'pic_width_in_mbs_minus1': pic_width_in_mbs_minus1,
        'pic_height_in_map_units_minus1': pic_height_in_map_units_minus1,
        'frame_mbs_only_flag': frame_mbs_only_flag,
        'mb_adaptive_frame_field_flag': mb_adaptive_frame_field_flag if not frame_mbs_only_flag else None,
        'direct_8x8_inference_flag': direct_8x8_inference_flag,
        'frame_cropping_flag': frame_cropping_flag,
        'frame_crop_left_offset': frame_crop_left_offset if frame_cropping_flag else None,
        'frame_crop_right_offset': frame_crop_right_offset if frame_cropping_flag else None,
        'frame_crop_top_offset': frame_crop_top_offset if frame_cropping_flag else None,
        'frame_crop_bottom_offset': frame_crop_bottom_offset if frame_cropping_flag else None,
        'vui_parameters_present_flag': vui_parameters_present_flag,
        'vui_parameters': vui_parameters,
        'data': data
    }


def parse_vui_parameters(bs):
    vui = {}
    vui['aspect_ratio_info_present_flag'] = read_bool_safe(bs)
    if vui['aspect_ratio_info_present_flag']:
        vui['aspect_ratio_idc'] = read_uint_safe(bs, 8)
        if vui['aspect_ratio_idc'] == 255:  # Extended_SAR
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
            vui['matrix_coefficients'] = read_uint_safe(bs, 8)

    vui['chroma_loc_info_present_flag'] = read_bool_safe(bs)
    if vui['chroma_loc_info_present_flag']:
        vui['chroma_sample_loc_type_top_field'] = read_ue_safe(bs)
        vui['chroma_sample_loc_type_bottom_field'] = read_ue_safe(bs)

    vui['timing_info_present_flag'] = read_bool_safe(bs)
    if vui['timing_info_present_flag']:
        vui['num_units_in_tick'] = read_uint_safe(bs, 32)
        vui['time_scale'] = read_uint_safe(bs, 32)
        vui['fixed_frame_rate_flag'] = read_bool_safe(bs)

    vui['nal_hrd_parameters_present_flag'] = read_bool_safe(bs)
    if vui['nal_hrd_parameters_present_flag']:
        vui['nal_hrd_parameters'] = parse_hrd_parameters(bs)

    vui['vcl_hrd_parameters_present_flag'] = read_bool_safe(bs)
    if vui['vcl_hrd_parameters_present_flag']:
        vui['vcl_hrd_parameters'] = parse_hrd_parameters(bs)

    if vui['nal_hrd_parameters_present_flag'] or vui['vcl_hrd_parameters_present_flag']:
        vui['low_delay_hrd_flag'] = read_bool_safe(bs)

    vui['pic_struct_present_flag'] = read_bool_safe(bs)
    vui['bitstream_restriction_flag'] = read_bool_safe(bs)
    if vui['bitstream_restriction_flag']:
        vui['motion_vectors_over_pic_boundaries_flag'] = read_bool_safe(bs)
        vui['max_bytes_per_pic_denom'] = read_ue_safe(bs)
        vui['max_bits_per_mb_denom'] = read_ue_safe(bs)
        vui['log2_max_mv_length_horizontal'] = read_ue_safe(bs)
        vui['log2_max_mv_length_vertical'] = read_ue_safe(bs)
        vui['num_reorder_frames'] = read_ue_safe(bs)
        vui['max_dec_frame_buffering'] = read_ue_safe(bs)

    return vui


def parse_hrd_parameters(bs):
    hrd = {}
    hrd['cpb_cnt_minus1'] = read_ue_safe(bs)
    hrd['bit_rate_scale'] = read_uint_safe(bs, 4)
    hrd['cpb_size_scale'] = read_uint_safe(bs, 4)
    hrd['bit_rate_value_minus1'] = []
    hrd['cpb_size_value_minus1'] = []
    hrd['cbr_flag'] = []
    for i in range(hrd['cpb_cnt_minus1'] + 1):
        hrd['bit_rate_value_minus1'].append(read_ue_safe(bs))
        hrd['cpb_size_value_minus1'].append(read_ue_safe(bs))
        hrd['cbr_flag'].append(read_bool_safe(bs))
    hrd['initial_cpb_removal_delay_length_minus1'] = read_uint_safe(bs, 5)
    hrd['cpb_removal_delay_length_minus1'] = read_uint_safe(bs, 5)
    hrd['dpb_output_delay_length_minus1'] = read_uint_safe(bs, 5)
    hrd['time_offset_length'] = read_uint_safe(bs, 5)

    return hrd

def more_rbsp_data(data, bit_pos):
    """
    Check if there is more RBSP data.
    """
    byte_pos = bit_pos // 8
    bit_in_byte = bit_pos % 8

    if byte_pos >= len(data):
        return False

    trailing_data = data[byte_pos:]

    # Find the last significant bit equal to 1
    last_significant_bit_pos = -1
    for i in range(len(trailing_data) * 8 - 1, -1, -1):
        if (trailing_data[i // 8] >> (7 - (i % 8))) & 0x01:
            last_significant_bit_pos = i + byte_pos * 8
            break

    if last_significant_bit_pos == -1:
        return False

    # Check if there is more data before the rbsp_trailing_bits() structure
    return last_significant_bit_pos > bit_pos

def parse_pps(data, sps):
    # DFC issue
    if data[0:4] == b'\x00\x00\x00\x00':
        bs = BitStream(data[4:])
    else:        
        bs = BitStream(data)

    pic_parameter_set_id = read_ue_safe(bs)
    seq_parameter_set_id = read_ue_safe(bs)
    entropy_coding_mode_flag = read_bool_safe(bs)
    bottom_field_pic_order_in_frame_present_flag = read_bool_safe(bs)
    num_slice_groups_minus1 = read_ue_safe(bs)

    slice_group_map_type = None
    run_length_minus1 = []
    top_left = []
    bottom_right = []
    slice_group_change_rate_minus1 = None
    pic_size_in_map_units_minus1 = None
    slice_group_id = []
    slice_group_change_direction_flag = None

    if num_slice_groups_minus1 > 0:
        slice_group_map_type = read_ue_safe(bs)
        if slice_group_map_type == 0:
            for i in range(num_slice_groups_minus1 + 1):
                run_length_minus1.append(read_ue_safe(bs))
        elif slice_group_map_type == 2:
            for i in range(num_slice_groups_minus1 + 1):
                top_left.append(read_ue_safe(bs))
                bottom_right.append(read_ue_safe(bs))
        elif slice_group_map_type in [3, 4, 5]:
            slice_group_change_direction_flag = read_bool_safe(bs)
            slice_group_change_rate_minus1 = read_ue_safe(bs)
        elif slice_group_map_type == 6:
            pic_size_in_map_units_minus1 = read_ue_safe(bs)
            for i in range(pic_size_in_map_units_minus1 + 1):
                slice_group_id.append(read_uint_safe(bs, math.ceil(math.log2(num_slice_groups_minus1 + 1))))

    num_ref_idx_l0_default_active_minus1 = read_ue_safe(bs)
    num_ref_idx_l1_default_active_minus1 = read_ue_safe(bs)
    weighted_pred_flag = read_bool_safe(bs)
    weighted_bipred_idc = read_uint_safe(bs, 2)
    pic_init_qp_minus26 = read_se_safe(bs)
    pic_init_qs_minus26 = read_se_safe(bs)
    chroma_qp_index_offset = read_se_safe(bs)
    deblocking_filter_control_present_flag = read_bool_safe(bs)
    constrained_intra_pred_flag = read_bool_safe(bs)
    redundant_pic_cnt_present_flag = read_bool_safe(bs)

    transform_8x8_mode_flag = None
    pic_scaling_matrix_present_flag = None
    second_chroma_qp_index_offset = None

    if more_rbsp_data(data, bs.pos):
        transform_8x8_mode_flag = read_bool_safe(bs)
        pic_scaling_matrix_present_flag = read_bool_safe(bs)
        scaling_matrix_4x4 = []
        scaling_matrix_8x8 = []

        chroma_format_idc = sps.get('chroma_format_idc', 1)

        if pic_scaling_matrix_present_flag:
            for i in range(6 + 2 * (chroma_format_idc == 3)):
                pic_scaling_list_present_flag = read_bool_safe(bs)
                if pic_scaling_list_present_flag:
                    if i < 6:
                        scaling_matrix_4x4.append(scaling_list_4x4(bs))
                    else:
                        scaling_matrix_8x8.append(scaling_list_8x8(bs))
        second_chroma_qp_index_offset = read_se_safe(bs)

    return {
        'pic_parameter_set_id': pic_parameter_set_id,
        'seq_parameter_set_id': seq_parameter_set_id,
        'entropy_coding_mode_flag': entropy_coding_mode_flag,
        'bottom_field_pic_order_in_frame_present_flag': bottom_field_pic_order_in_frame_present_flag,
        'num_slice_groups_minus1': num_slice_groups_minus1,
        'slice_group_map_type': slice_group_map_type,
        'run_length_minus1': run_length_minus1,
        'top_left': top_left,
        'bottom_right': bottom_right,
        'slice_group_change_rate_minus1': slice_group_change_rate_minus1,
        'pic_size_in_map_units_minus1': pic_size_in_map_units_minus1,
        'slice_group_id': slice_group_id,
        'num_ref_idx_l0_default_active_minus1': num_ref_idx_l0_default_active_minus1,
        'num_ref_idx_l1_default_active_minus1': num_ref_idx_l1_default_active_minus1,
        'weighted_pred_flag': weighted_pred_flag,
        'weighted_bipred_idc': weighted_bipred_idc,
        'pic_init_qp_minus26': pic_init_qp_minus26,
        'pic_init_qs_minus26': pic_init_qs_minus26,
        'chroma_qp_index_offset': chroma_qp_index_offset,
        'deblocking_filter_control_present_flag': deblocking_filter_control_present_flag,
        'constrained_intra_pred_flag': constrained_intra_pred_flag,
        'redundant_pic_cnt_present_flag': redundant_pic_cnt_present_flag,
        'transform_8x8_mode_flag': transform_8x8_mode_flag,
        'pic_scaling_matrix_present_flag': pic_scaling_matrix_present_flag,
        'second_chroma_qp_index_offset': second_chroma_qp_index_offset,
        'scaling_matrix_4x4': scaling_matrix_4x4 if pic_scaling_matrix_present_flag else None,
        'scaling_matrix_8x8': scaling_matrix_8x8 if pic_scaling_matrix_present_flag else None,
        'slice_group_change_direction_flag': slice_group_change_direction_flag,
        'data': data
    }


def scaling_list_4x4(bs):
    scaling_list = []
    last_scale = 8
    next_scale = 8
    for i in range(16):
        if next_scale != 0:
            delta_scale = read_se_safe(bs)
            next_scale = (last_scale + delta_scale + 256) % 256
        scaling_list.append(next_scale)
        last_scale = next_scale if next_scale != 0 else last_scale
    return scaling_list


def scaling_list_8x8(bs):
    scaling_list = []
    last_scale = 8
    next_scale = 8
    for i in range(64):
        if next_scale != 0:
            delta_scale = read_se_safe(bs)
            next_scale = (last_scale + delta_scale + 256) % 256
        scaling_list.append(next_scale)
        last_scale = next_scale if next_scale != 0 else last_scale
    return scaling_list


def parse_sei(data):
    bs = BitStream(data)
    sei_messages = []

    while bs.pos < bs.len:
        sei_message = {}

        # Read sei_payload_type
        payload_type = 0
        while True:
            if bs.pos + 8 > bs.len:
                return sei_messages
            byte = read_uint_safe(bs, 8)
            payload_type += byte
            if byte != 0xFF:
                break
        sei_message['payload_type'] = payload_type

        # Read sei_payload_size
        payload_size = 0
        while True:
            if bs.pos + 8 > bs.len:
                return sei_messages
            byte = read_uint_safe(bs, 8)
            payload_size += byte
            if byte != 0xFF:
                break
        sei_message['payload_size'] = payload_size

        # Ensure there is enough data for the payload
        if bs.pos + payload_size * 8 > bs.len:
            raise ValueError("Insufficient data for reading sei_payload_data")

        # Read sei_payload_data
        sei_message['payload_data'] = bs.read(f'bytes:{payload_size}')
        sei_messages.append(sei_message)

    return sei_messages

def parse_sei_payload(payload_type, payload_data):
    # This function can be extended to parse different SEI payloads based on the type
    return {
        'type': payload_type,
        'data': payload_data
    }


def parse_slice(data, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Parses a slice NAL unit according to H.264 standard sections:
    - 7.3.2.8 Slice layer without partitioning
    - 7.3.2.9 Slice data partition A/B/C
    - 7.3.2.10~7.3.2.13 for trailing bits, etc.
    
    This function checks if the slice is partitioned (A,B,C) or not,
    then calls the appropriate functions.
    """
    bs = BitStream(data)

    # For demonstration, let's assume partitioned slices use NAL types 8,9,10
    # and non-partitioned slices use NAL type 1,5, etc.
    # This can vary depending on exact usage.

    if nal_unit_type in [1, 5]:
        # Standard slice without partitioning
        return slice_layer_without_partitioning_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc)
    elif nal_unit_type == 8:
        # Partition A
        return slice_data_partition_a_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc)
    elif nal_unit_type == 9:
        # Partition B
        return slice_data_partition_b_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc)
    elif nal_unit_type == 10:
        # Partition C
        return slice_data_partition_c_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc)
    else:
        # Fallback or extension
        return slice_layer_without_partitioning_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc)


########################################################
# 7.3.2.8 slice_layer_without_partitioning_rbsp()
########################################################

def slice_layer_without_partitioning_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    7.3.2.8:
    - slice_header()
    - slice_data() (all categories)
    - rbsp_slice_trailing_bits()
    """
    # Parse slice header
    slice_header_info = parse_slice_header(bs, sps, pps, nal_unit_type, nal_ref_idc)
    slice_data_info = {}
    # # Parse slice data - "all" categories
    # slice_data_info = parse_slice_data(
    #     bs, 
    #     sps, 
    #     pps, 
    #     nal_unit_type, 
    #     nal_ref_idc, 
    #     category="all",
    #     slice_header=slice_header_info
    # )

    # # Trailing bits
    # parse_rbsp_slice_trailing_bits(bs, pps.get('entropy_coding_mode_flag', False))

    return slice_header_info, slice_data_info


########################################################
# 7.3.2.9.1 slice_data_partition_a_layer_rbsp()
########################################################

def slice_data_partition_a_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    7.3.2.9.1:
    - slice_header()
    - slice_id (ue(v))
    - slice_data() (only category 2)
    - rbsp_slice_trailing_bits()
    """
    slice_header_info = parse_slice_header(bs, sps, pps, nal_unit_type, nal_ref_idc)
    slice_id = read_ue_safe(bs)

    # Parse slice data (category 2 only)
    slice_data_info = parse_slice_data(
        bs, sps, pps, nal_unit_type, nal_ref_idc, 
        category="2",
        slice_header=slice_header_info
    )

    parse_rbsp_slice_trailing_bits(bs, pps.get('entropy_coding_mode_flag', False))
    return slice_header_info, slice_id, slice_data_info


########################################################
# 7.3.2.9.2 slice_data_partition_b_layer_rbsp()
########################################################

def slice_data_partition_b_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    7.3.2.9.2:
    - slice_id (ue(v))
    - if(separate_colour_plane_flag) colour_plane_id (u(2))
    - if(redundant_pic_cnt_present_flag) redundant_pic_cnt (ue(v))
    - slice_data() (only category 3)
    - rbsp_slice_trailing_bits()
    
    Note that partition B doesn't include the slice header 
    (already parsed in partition A).
    """
    slice_id = read_ue_safe(bs)

    if sps.get('separate_colour_plane_flag', False):
        colour_plane_id = read_uint_safe(bs, 2)
    else:
        colour_plane_id = None

    if pps.get('redundant_pic_cnt_present_flag', False):
        redundant_pic_cnt = read_ue_safe(bs)
    else:
        redundant_pic_cnt = None

    # Parse slice data (category 3 only)
    slice_data_info = parse_slice_data(
        bs, sps, pps, nal_unit_type, nal_ref_idc, 
        category="3"
    )

    parse_rbsp_slice_trailing_bits(bs, pps.get('entropy_coding_mode_flag', False))

    return {
        "slice_id": slice_id,
        "colour_plane_id": colour_plane_id,
        "redundant_pic_cnt": redundant_pic_cnt,
        "slice_data": slice_data_info
    }


########################################################
# 7.3.2.9.3 slice_data_partition_c_layer_rbsp()
########################################################

def slice_data_partition_c_layer_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    7.3.2.9.3:
    - slice_id (ue(v))
    - if(separate_colour_plane_flag) colour_plane_id
    - if(redundant_pic_cnt_present_flag) redundant_pic_cnt
    - slice_data() (only category 4)
    - rbsp_slice_trailing_bits()
    
    Similar to partition B, no slice header here.
    """
    slice_id = read_ue_safe(bs)

    if sps.get('separate_colour_plane_flag', False):
        colour_plane_id = read_uint_safe(bs, 2)
    else:
        colour_plane_id = None

    if pps.get('redundant_pic_cnt_present_flag', False):
        redundant_pic_cnt = read_ue_safe(bs)
    else:
        redundant_pic_cnt = None

    # Parse slice data (category 4 only)
    slice_data_info = parse_slice_data(
        bs, sps, pps, nal_unit_type, nal_ref_idc, 
        category="4"
    )

    parse_rbsp_slice_trailing_bits(bs, pps.get('entropy_coding_mode_flag', False))

    return {
        "slice_id": slice_id,
        "colour_plane_id": colour_plane_id,
        "redundant_pic_cnt": redundant_pic_cnt,
        "slice_data": slice_data_info
    }


def slice_layer_extension_rbsp(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Implements 7.3.2.13: slice_layer_extension_rbsp().
    - Handles svc_extension_flag or avc_3d_extension_flag if present
    - Otherwise, parses like a normal slice
    - Calls rbsp_slice_trailing_bits()
    """
    # Placeholder reads for extension flags (implementation-dependent)
    svc_extension_flag = False  # Example: read from NAL unit header if needed
    avc_3d_extension_flag = False

    if svc_extension_flag:
        # 7.3.2.13 + Annex F
        slice_header_info = slice_header_in_scalable_extension(bs, sps, pps, nal_unit_type, nal_ref_idc)
        if not slice_header_info.get('slice_skip_flag', False):
            slice_data_info = slice_data_in_scalable_extension(bs, sps, pps, nal_unit_type, nal_ref_idc)
        else:
            slice_data_info = {}
    elif avc_3d_extension_flag:
        # 7.3.2.13 + Annex J
        slice_header_info = slice_header_in_3davc_extension(bs, sps, pps, nal_unit_type, nal_ref_idc)
        slice_data_info = slice_data_in_3davc_extension(bs, sps, pps, nal_unit_type, nal_ref_idc)
    else:
        # Standard slice_header, slice_data (without partitioning), then trailing bits
        slice_header_info = parse_slice_header(bs, sps, pps, nal_unit_type, nal_ref_idc)
        slice_data_info = parse_slice_data(bs, sps, pps, nal_unit_type, nal_ref_idc, category="all")

    rbsp_slice_trailing_bits(bs, pps.get('entropy_coding_mode_flag', False))

    return slice_header_info, slice_data_info


########################################################
# parse_slice_data() - Implements 7.3.2.8 or 7.3.2.9.x's slice_data()
########################################################

def parse_slice_data(
    bs, 
    sps, 
    pps, 
    nal_unit_type, 
    nal_ref_idc, 
    category="all",
    slice_header=None
):
    """
    Parses the slice_data() syntax as per H.264 standard 7.3.2.8 (without partitioning)
    or 7.3.2.9.x (with partitioning).
    
    'category' indicates which partition's MB data to parse (2,3,4) or "all".
    
    This function uses the standard MB loop:
     - Skip logic (mb_skip_run / mb_skip_flag)
     - MBAFF consideration
     - Calls macroblock_layer()
     - Updates moreDataFlag until no more MBs
    
    'slice_header' should contain:
     - first_mb_in_slice
     - slice_type
     - MbaffFrameFlag
     - entropy_coding_mode_flag
     - direct_8x8_inference_flag
     - transform_8x8_mode_flag
     - num_ref_idx_l0_active_minus1, etc.
    """
    # If slice_header is None, assume defaults (demonstration)
    if slice_header is None:
        slice_header = {
            "first_mb_in_slice": 0,
            "slice_type": "P",
            "MbaffFrameFlag": False,
            "entropy_coding_mode_flag": pps.get('entropy_coding_mode_flag', False),
            "direct_8x8_inference_flag": True,
            "transform_8x8_mode_flag": False,
            "num_ref_idx_l0_active_minus1": pps.get('num_ref_idx_l0_default_active_minus1', 0),
            "num_ref_idx_l1_active_minus1": pps.get('num_ref_idx_l1_default_active_minus1', 0)
        }

    # 1) CABAC alignment if needed
    if slice_header["entropy_coding_mode_flag"]:
        while not byte_aligned(bs):
            cabac_align_bit = read_bits(bs, 1)  # should be '1' in standard

    # 2) Initialize CurrMbAddr
    first_mb_in_slice = slice_header["first_mb_in_slice"]
    MbaffFrameFlag = slice_header["MbaffFrameFlag"]
    CurrMbAddr = first_mb_in_slice * (1 + (1 if MbaffFrameFlag else 0))

    # 3) moreDataFlag, prevMbSkipped
    moreDataFlag = True
    prevMbSkipped = False
    slice_type = slice_header["slice_type"]
    entropy_coding_mode_flag = slice_header["entropy_coding_mode_flag"]

    mb_list = []

    # 4) MB loop
    while moreDataFlag:
        # Skip logic
        if slice_type not in ["I", "SI"]:
            if not entropy_coding_mode_flag:
                # CAVLC skip run
                mb_skip_run = read_ue_safe(bs)
                prevMbSkipped = (mb_skip_run > 0)
                # Move CurrMbAddr by skip run
                for _ in range(mb_skip_run):
                    CurrMbAddr = next_mb_address(CurrMbAddr, MbaffFrameFlag)
                # Check if more data
                moreDataFlag = more_rbsp_data(bs)
                mb_skip_flag = (mb_skip_run > 0)
            else:
                # CABAC skip flag
                mb_skip_flag = read_ae_safe(bs)
                moreDataFlag = not mb_skip_flag
        else:
            # I or SI slice => no skip
            mb_skip_flag = False

        # Parse MB if more data
        if moreDataFlag:
            # MBAFF consideration
            if MbaffFrameFlag and (
                (CurrMbAddr % 2 == 0) or
                (CurrMbAddr % 2 == 1 and prevMbSkipped)
            ):
                mb_field_decoding_flag = read_mb_field_decoding_flag(bs, entropy_coding_mode_flag)
            else:
                mb_field_decoding_flag = False

            # Call macroblock_layer
            mb_info = macroblock_layer(bs, sps, pps, slice_header, mb_field_decoding_flag, category)
            mb_list.append({
                "CurrMbAddr": CurrMbAddr,
                "mb_skip_flag": mb_skip_flag,
                "mb_field_decoding_flag": mb_field_decoding_flag,
                "mb_info": mb_info
            })

        # Update moreDataFlag
        if not entropy_coding_mode_flag:
            moreDataFlag = more_rbsp_data(bs)
        else:
            # CABAC
            if slice_type not in ["I", "SI"]:
                prevMbSkipped = mb_skip_flag
            if MbaffFrameFlag and (CurrMbAddr % 2 == 0):
                moreDataFlag = True
            else:
                # end_of_slice_flag (ae(v))
                end_of_slice_flag = read_ae_safe(bs)
                moreDataFlag = not end_of_slice_flag

        # Move to next MB
        CurrMbAddr = next_mb_address(CurrMbAddr, MbaffFrameFlag)

    return {"macroblock_list": mb_list}


########################################################
# 7.3.5 macroblock_layer() and sub-functions
########################################################

def macroblock_layer(bs, sps, pps, slice_header, mb_field_decoding_flag, category):
    """
    Implements 7.3.5 macroblock_layer() syntax:
      - mb_type
      - if mb_type == I_PCM => PCM samples
      - else => sub_mb_pred / mb_pred + coded_block_pattern + transform_size_8x8_flag + residual
    
    The 'category' parameter indicates partition category if needed (2,3,4, or "all").
    In practice, we often parse the whole macroblock even if category != "all". 
    """
    mb_info = {}

    # Read mb_type (u(UE) or ae)
    if slice_header["entropy_coding_mode_flag"]:
        mb_type = read_ae_safe(bs)
    else:
        mb_type = read_ue_safe(bs)
    mb_info["mb_type"] = mb_type

    # Check if I_PCM
    # Real code would check actual numeric mapping for I_PCM
    is_IPCM = (mb_type == "I_PCM" or mb_type == 25)  # Example placeholder
    if is_IPCM:
        # while( !byte_aligned() ) => read zero bits
        while not byte_aligned(bs):
            zbit = read_bits(bs, 1)  # should be 0
        # Read 256 luma samples, then chroma samples
        # This depends on bit depth and chroma format. Here, placeholder:
        pcm_luma = [read_uint_safe(bs, 8) for _ in range(256)]
        pcm_chroma = [read_uint_safe(bs, 8) for _ in range(128)]
        mb_info["pcm_luma"] = pcm_luma
        mb_info["pcm_chroma"] = pcm_chroma
    else:
        # noSubMbPartSizeLessThan8x8Flag = 1 by default
        noSubMbPartSizeLessThan8x8Flag = True
        direct_8x8_inference_flag = slice_header["direct_8x8_inference_flag"]
        transform_8x8_mode_flag = slice_header["transform_8x8_mode_flag"]
        slice_type = slice_header["slice_type"]

        mb_pred_mode_0 = get_MbPartPredMode(mb_type, 0, slice_type)
        num_mb_part = get_NumMbPart(mb_type, slice_type)

        # Check sub_mb_pred
        if (mb_type != "I_NxN" and 
            mb_pred_mode_0 != "Intra_16x16" and 
            num_mb_part == 4):
            # sub_mb_pred
            sub_pred_info = sub_mb_pred(bs, sps, pps, slice_header, mb_type, category)
            mb_info["sub_mb_pred"] = sub_pred_info

            # If sub_mb_type indicates < 8x8 or direct inference = false => noSubMbPartSizeLessThan8x8Flag = 0
            if sub_pred_info.get("found_small_partition", False) or not direct_8x8_inference_flag:
                noSubMbPartSizeLessThan8x8Flag = False
        else:
            # If transform_8x8_mode_flag && mb_type==I_NxN => transform_size_8x8_flag
            if transform_8x8_mode_flag and mb_type == "I_NxN":
                if slice_header["entropy_coding_mode_flag"]:
                    ts8_flag = read_ae_safe(bs)
                else:
                    ts8_flag = read_uint_safe(bs, 1)
                mb_info["transform_size_8x8_flag"] = ts8_flag

            # mb_pred
            mb_info["mb_pred"] = mb_pred(bs, sps, pps, slice_header, mb_type, category)

        # coded_block_pattern
        if slice_header["entropy_coding_mode_flag"]:
            coded_block_pattern = read_ae_safe(bs)
        else:
            coded_block_pattern = read_ue_safe(bs)
        mb_info["coded_block_pattern"] = coded_block_pattern

        # If coded_block_pattern_luma>0 and transform_8x8_mode_flag ...
        # Possibly read transform_size_8x8_flag again, etc. (skipped for brevity)

        # If coded_block_pattern>0 or Intra_16x16 => parse mb_qp_delta + residual
        if coded_block_pattern > 0 or mb_part_pred_mode_is_intra16x16(mb_type, slice_type):
            # mb_qp_delta
            if slice_header["entropy_coding_mode_flag"]:
                mb_qp_delta = read_ae_safe(bs)
            else:
                mb_qp_delta = read_se_safe(bs)
            mb_info["mb_qp_delta"] = mb_qp_delta

            # residual(0,15)
            res_info = parse_residual(bs, sps, pps, slice_header, start_idx=0, end_idx=15, category=category)
            mb_info["residual"] = res_info

    return mb_info


def mb_pred(bs, sps, pps, slice_header, mb_type, category):
    """
    7.3.5.1 mb_pred():
      - Intra (4x4 / 8x8 / 16x16) => parse intra prediction data
      - Else if not Direct => parse ref_idx, mvd, etc.
    """
    result = {}
    entropy_coding_mode_flag = slice_header["entropy_coding_mode_flag"]
    slice_type = slice_header["slice_type"]
    mode0 = get_MbPartPredMode(mb_type, 0, slice_type)

    if mode0 in ["Intra_4x4", "Intra_8x8", "Intra_16x16", "I_NxN"]:
        # handle Intra
        if mode0 == "Intra_4x4":
            pred4x4 = []
            for _ in range(16):
                if entropy_coding_mode_flag:
                    prev_flag = read_ae_safe(bs)
                else:
                    prev_flag = read_uint_safe(bs, 1)
                if not prev_flag:
                    if entropy_coding_mode_flag:
                        rem_mode = read_ae_safe(bs)
                    else:
                        rem_mode = read_uint_safe(bs, 3)
                else:
                    rem_mode = None
                pred4x4.append((prev_flag, rem_mode))
            result["intra4x4_pred"] = pred4x4

        elif mode0 == "Intra_8x8":
            pred8x8 = []
            for _ in range(4):
                if entropy_coding_mode_flag:
                    prev_flag = read_ae_safe(bs)
                else:
                    prev_flag = read_uint_safe(bs, 1)
                if not prev_flag:
                    if entropy_coding_mode_flag:
                        rem_mode = read_ae_safe(bs)
                    else:
                        rem_mode = read_uint_safe(bs, 3)
                else:
                    rem_mode = None
                pred8x8.append((prev_flag, rem_mode))
            result["intra8x8_pred"] = pred8x8

        # Intra Chroma
        if pps.get("chroma_array_type", 1) in [1,2]:
            if entropy_coding_mode_flag:
                intra_chroma_pred_mode = read_ae_safe(bs)
            else:
                intra_chroma_pred_mode = read_ue_safe(bs)
            result["intra_chroma_pred_mode"] = intra_chroma_pred_mode

    elif mode0 != "Direct":
        # Inter MB
        n_parts = get_NumMbPart(mb_type, slice_type)
        # parse ref_idx_l0/l1
        # parse mvd_l0/l1
        # ...
        result["inter_pred"] = "parsed_inter_placeholder"

    return result


def sub_mb_pred(bs, sps, pps, slice_header, mb_type, category):
    """
    7.3.5.2 sub_mb_pred():
      - sub_mb_type[4]
      - ref_idx_l0/l1
      - mvd_l0/l1
    """
    entropy_coding_mode_flag = slice_header["entropy_coding_mode_flag"]
    result = {}
    found_small_partition = False

    sub_types = []
    for _ in range(4):
        if entropy_coding_mode_flag:
            val = read_ae_safe(bs)
        else:
            val = read_ue_safe(bs)
        sub_types.append(val)
        # If the sub_mb_type has multiple partitions => found_small_partition = True
        if num_sub_mb_part(val) > 1:
            found_small_partition = True

    result["sub_mb_type"] = sub_types
    result["found_small_partition"] = found_small_partition

    # Additional logic for ref_idx, mvd, etc.
    return result


def parse_residual(bs, sps, pps, slice_header, start_idx, end_idx, category):
    """
    7.3.5.3 residual():
      - Calls residual_luma and residual_chroma logic
      - Distinguishes CAVLC vs CABAC
    """
    result = {}
    # For demonstration only
    result["residual_luma"] = "res_luma_placeholder"
    result["residual_chroma"] = "res_chroma_placeholder"
    return result


########################################################
# Trailing bits, etc.
########################################################

def parse_rbsp_slice_trailing_bits(bs, entropy_coding_mode_flag=False):
    """
    7.3.2.10 + 7.3.2.11:
    - rbsp_trailing_bits()
    - if CABAC, handle cabac_zero_word while more_rbsp_trailing_data()
    """
    rbsp_trailing_bits(bs)
    if entropy_coding_mode_flag:
        while more_rbsp_trailing_data(bs):
            czw = read_uint_safe(bs, 16)  # cabac_zero_word = 0x0000?


def rbsp_trailing_bits(bs):
    # read 1 bit => stop bit (should be 1)
    stop_bit = read_bits(bs, 1)
    # read alignment zero bits until byte aligned
    while not byte_aligned(bs):
        zero_bit = read_bits(bs, 1)
        # check zero_bit == 0 if needed


def more_rbsp_trailing_data(bs):
    # Typically checks if there's leftover bits that are not trailing
    # placeholder
    return False

def rbsp_slice_trailing_bits(bs, entropy_coding_mode_flag=False):
    """
    Implements 7.3.2.10: rbsp_slice_trailing_bits().
    - Calls rbsp_trailing_bits()
    - If entropy_coding_mode_flag == 1, parse cabac_zero_word while more_rbsp_trailing_data()
    """
    rbsp_trailing_bits(bs)

    if entropy_coding_mode_flag:
        while more_rbsp_trailing_data(bs):
            cabac_zero_word(bs)


def rbsp_trailing_bits(bs):
    """
    Implements 7.3.2.11: rbsp_trailing_bits().
    - Reads 1 'stop bit' (equal to 1)
    - Then reads alignment zero bits until byte-aligned
    """
    # Example: read one bit (stop bit)
    stop_bit = read_bool_safe(bs)
    # Then read alignment zero bits until byte aligned
    while not bs.byte_aligned:
        zero_bit = read_bool_safe(bs)
        # Validate zero_bit == 0 if needed


def more_rbsp_trailing_data(bs):
    """
    Checks if there is more trailing data in the RBSP that should be 
    consumed as cabac_zero_word. This is typically implementation-specific.
    """
    # Placeholder logic
    # For example, check the number of remaining bits or pattern in the bitstream
    return False


def cabac_zero_word(bs):
    """
    Reads a 16-bit field that should be equal to 0x0000 in CABAC mode 
    if needed (7.3.2.10).
    """
    val = read_uint_safe(bs, 16)
    # Validate val == 0x0000 if needed


def slice_header_in_scalable_extension(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Placeholder for 7.3.2.13 + Annex F: slice_header_in_scalable_extension().
    """
    header_info = {}
    # Parse extension-specific fields here
    header_info['slice_skip_flag'] = False
    return header_info


def slice_data_in_scalable_extension(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Placeholder for 7.3.2.13 + Annex F: slice_data_in_scalable_extension().
    """
    data_info = {}
    # Parse extension-specific MB data
    data_info['svc_data'] = read_uint_safe(bs, 8)
    return data_info


def slice_header_in_3davc_extension(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Placeholder for 7.3.2.13 + Annex J: slice_header_in_3davc_extension().
    """
    header_info = {}
    return header_info


def slice_data_in_3davc_extension(bs, sps, pps, nal_unit_type, nal_ref_idc):
    """
    Placeholder for 7.3.2.13 + Annex J: slice_data_in_3davc_extension().
    """
    data_info = {}
    data_info['3davc_data'] = read_uint_safe(bs, 8)
    return data_info



def parse_slice_header(bs, sps, pps, nal_unit_type, nal_ref_idc):
    slice_header = {}

    slice_header['first_mb_in_slice'] = read_ue_safe(bs)

    raw_slice_type = read_ue_safe(bs)
    slice_header['slice_type'] = raw_slice_type
    st_mod = raw_slice_type % 5  # (P=0, B=1, I=2, SP=3, SI=4)

    slice_header['pic_parameter_set_id'] = read_ue_safe(bs)

    if sps.get('separate_colour_plane_flag', False):
        slice_header['colour_plane_id'] = read_uint_safe(bs, 2)  # u(2)

    frame_num_bits = sps['log2_max_frame_num_minus4'] + 4
    slice_header['frame_num'] = read_uint_safe(bs, frame_num_bits)

    if not sps['frame_mbs_only_flag']:
        slice_header['field_pic_flag'] = read_bool_safe(bs)
        if slice_header['field_pic_flag']:
            slice_header['bottom_field_flag'] = read_bool_safe(bs)
    else:
        slice_header['field_pic_flag'] = False

    IdrPicFlag = (nal_unit_type == 5)
    if IdrPicFlag:
        slice_header['idr_pic_id'] = read_ue_safe(bs)

    if sps['pic_order_cnt_type'] == 0:
        poc_lsb_bits = sps['log2_max_pic_order_cnt_lsb_minus4'] + 4
        slice_header['pic_order_cnt_lsb'] = read_uint_safe(bs, poc_lsb_bits)

        if (pps.get('bottom_field_pic_order_in_frame_present_flag', False)
                and not slice_header['field_pic_flag']):
            slice_header['delta_pic_order_cnt_bottom'] = read_se_safe(bs)

    elif (sps['pic_order_cnt_type'] == 1 and 
          not sps.get('delta_pic_order_always_zero_flag', False)):
        slice_header['delta_pic_order_cnt'] = []
        # delta_pic_order_cnt[0]
        slice_header['delta_pic_order_cnt'].append(read_se_safe(bs))

        # delta_pic_order_cnt[1]
        if pps.get('bottom_field_pic_order_in_frame_present_flag', False) \
           and not slice_header['field_pic_flag']:
            slice_header['delta_pic_order_cnt'].append(read_se_safe(bs))

    if pps.get('redundant_pic_cnt_present_flag', False):
        slice_header['redundant_pic_cnt'] = read_ue_safe(bs)

    if st_mod == 1:  # B-slice
        slice_header['direct_spatial_mv_pred_flag'] = read_bool_safe(bs)

    if st_mod in [0, 1, 3]:  # P(0), B(1), SP(3)
        slice_header['num_ref_idx_active_override_flag'] = read_bool_safe(bs)
        if slice_header['num_ref_idx_active_override_flag']:
            # num_ref_idx_l0_active_minus1
            slice_header['num_ref_idx_l0_active_minus1'] = read_ue_safe(bs)

            if st_mod == 1:  # B-slice
                slice_header['num_ref_idx_l1_active_minus1'] = read_ue_safe(bs)
        else:
            slice_header['num_ref_idx_l0_active_minus1'] = pps['num_ref_idx_l0_default_active_minus1']
            if 'num_ref_idx_l1_default_active_minus1' in pps:
                slice_header['num_ref_idx_l1_active_minus1'] = pps['num_ref_idx_l1_default_active_minus1']
            else:
                slice_header['num_ref_idx_l1_active_minus1'] = 0

    if nal_unit_type in [20, 21]:
        slice_header['mvc_modification'] = parse_ref_pic_list_mvc_modification(bs, raw_slice_type)
    else:
        slice_header['ref_pic_list_modification'] = parse_ref_pic_list_modification(bs, raw_slice_type)

    weighted_pred_flag = pps.get('weighted_pred_flag', False)
    weighted_bipred_idc = pps.get('weighted_bipred_idc', 0)

    if ((weighted_pred_flag and st_mod in [0, 3]) or
        (weighted_bipred_idc == 1 and st_mod == 1)):
        slice_header['pred_weight_table'] = parse_pred_weight_table(bs, slice_header, sps, pps)

    if nal_ref_idc != 0:
        slice_header['dec_ref_pic_marking'] = parse_dec_ref_pic_marking(bs, IdrPicFlag)

    if pps.get('entropy_coding_mode_flag', False) and (st_mod not in [2, 4]):
        slice_header['cabac_init_idc'] = read_ue_safe(bs)

    slice_header['slice_qp_delta'] = read_se_safe(bs)

    if st_mod in [3, 4]:
        if st_mod == 3:  # SP
            slice_header['sp_for_switch_flag'] = read_bool_safe(bs)
        slice_header['slice_qs_delta'] = read_se_safe(bs)

    if pps.get('deblocking_filter_control_present_flag', False):
        slice_header['disable_deblocking_filter_idc'] = read_ue_safe(bs)
        if slice_header['disable_deblocking_filter_idc'] != 1:
            slice_header['slice_alpha_c0_offset_div2'] = read_se_safe(bs)
            slice_header['slice_beta_offset_div2'] = read_se_safe(bs)

    if (pps['num_slice_groups_minus1'] > 0 and
        3 <= pps['slice_group_map_type'] <= 5):
        slice_header['slice_group_change_cycle'] = read_uint_safe(
            bs, pps['pic_size_in_map_units_minus1'] + 4
        )

    return slice_header


def parse_ref_pic_list_mvc_modification(bs, slice_type):
    st_mod = slice_type % 5
    result = {}

    # if( slice_type % 5 != 2 && slice_type % 5 != 4 ) => (I=2), (SI=4)
    if st_mod not in [2, 4]:  # P(0), B(1), SP(3)
        flag_l0 = read_bool_safe(bs)  # ref_pic_list_modification_flag_l0
        result['ref_pic_list_modification_flag_l0'] = flag_l0
        if flag_l0:
            modifications_l0 = []
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                if modification_of_pic_nums_idc == 3:
                    break
                item = {
                    'modification_of_pic_nums_idc': modification_of_pic_nums_idc
                }
                if modification_of_pic_nums_idc in [0, 1]:
                    item['abs_diff_pic_num_minus1'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc == 2:
                    item['long_term_pic_num'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc in [4, 5]:
                    item['abs_diff_view_idx_minus1'] = read_ue_safe(bs)
                modifications_l0.append(item)
            result['modifications_l0'] = modifications_l0

    # if( slice_type % 5 == 1 ) => B-slice
    if st_mod == 1:
        flag_l1 = read_bool_safe(bs)  # ref_pic_list_modification_flag_l1
        result['ref_pic_list_modification_flag_l1'] = flag_l1
        if flag_l1:
            modifications_l1 = []
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                if modification_of_pic_nums_idc == 3:
                    break
                item = {
                    'modification_of_pic_nums_idc': modification_of_pic_nums_idc
                }
                if modification_of_pic_nums_idc in [0, 1]:
                    item['abs_diff_pic_num_minus1'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc == 2:
                    item['long_term_pic_num'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc in [4, 5]:
                    item['abs_diff_view_idx_minus1'] = read_ue_safe(bs)
                modifications_l1.append(item)
            result['modifications_l1'] = modifications_l1

    return result


def parse_ref_pic_list_modification(bs, slice_type):
    st_mod = slice_type % 5
    result = {}

    # if( slice_type % 5 != 2 && slice_type % 5 != 4 ) => (I=2), (SI=4)
    if st_mod not in [2, 4]:  # P(0), B(1), SP(3)
        flag_l0 = read_bool_safe(bs)  # ref_pic_list_modification_flag_l0
        result['ref_pic_list_modification_flag_l0'] = flag_l0
        if flag_l0:
            modifications_l0 = []
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                if modification_of_pic_nums_idc == 3:
                    break
                item = {
                    'modification_of_pic_nums_idc': modification_of_pic_nums_idc
                }
                if modification_of_pic_nums_idc in [0, 1]:
                    item['abs_diff_pic_num_minus1'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc == 2:
                    item['long_term_pic_num'] = read_ue_safe(bs)
                modifications_l0.append(item)
            result['modifications_l0'] = modifications_l0

    # if( slice_type % 5 == 1 ) => B-slice
    if st_mod == 1:
        flag_l1 = read_bool_safe(bs)  # ref_pic_list_modification_flag_l1
        result['ref_pic_list_modification_flag_l1'] = flag_l1
        if flag_l1:
            modifications_l1 = []
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                if modification_of_pic_nums_idc == 3:
                    break
                item = {
                    'modification_of_pic_nums_idc': modification_of_pic_nums_idc
                }
                if modification_of_pic_nums_idc in [0, 1]:
                    item['abs_diff_pic_num_minus1'] = read_ue_safe(bs)
                elif modification_of_pic_nums_idc == 2:
                    item['long_term_pic_num'] = read_ue_safe(bs)
                modifications_l1.append(item)
            result['modifications_l1'] = modifications_l1

    return result


def parse_pred_weight_table(bs, slice_header, sps, pps):
    result = {}

    ChromaArrayType = sps.get('ChromaArrayType', 1)  

    # num_ref_idx_l0_active_minus1, num_ref_idx_l1_active_minus1
    nL0 = slice_header.get('num_ref_idx_l0_active_minus1', 0)
    nL1 = slice_header.get('num_ref_idx_l1_active_minus1', 0)

    # 1) luma_log2_weight_denom
    luma_log2_weight_denom = read_ue_safe(bs)
    result['luma_log2_weight_denom'] = luma_log2_weight_denom

    # 2) chroma_log2_weight_denom (ChromaArrayType != 0 )
    if ChromaArrayType != 0:
        chroma_log2_weight_denom = read_ue_safe(bs)
        result['chroma_log2_weight_denom'] = chroma_log2_weight_denom

    # 3) L0
    result['luma_weight_l0_flag'] = []
    result['luma_weight_l0'] = []
    result['luma_offset_l0'] = []
    if ChromaArrayType != 0:
        result['chroma_weight_l0_flag'] = []
        result['chroma_weight_l0'] = []
        result['chroma_offset_l0'] = []

    for i in range(nL0 + 1):
        lw_flag = read_bool_safe(bs)  # luma_weight_l0_flag
        result['luma_weight_l0_flag'].append(lw_flag)
        luma_weight = 0
        luma_offset = 0
        if lw_flag:
            luma_weight = read_se_safe(bs)  # luma_weight_l0[i]
            luma_offset = read_se_safe(bs)  # luma_offset_l0[i]
        result['luma_weight_l0'].append(luma_weight)
        result['luma_offset_l0'].append(luma_offset)

        if ChromaArrayType != 0:
            cw_flag = read_bool_safe(bs)  # chroma_weight_l0_flag
            result['chroma_weight_l0_flag'].append(cw_flag)
            if cw_flag:
                cw_list = []
                co_list = []
                for j in range(2):
                    cw_val = read_se_safe(bs)  # chroma_weight_l0[i][j]
                    co_val = read_se_safe(bs)  # chroma_offset_l0[i][j]
                    cw_list.append(cw_val)
                    co_list.append(co_val)
            else:
                cw_list = [0, 0]
                co_list = [0, 0]
            if 'chroma_weight_l0' not in result:
                result['chroma_weight_l0'] = []
                result['chroma_offset_l0'] = []
            result['chroma_weight_l0'].append(cw_list)
            result['chroma_offset_l0'].append(co_list)

    # 4) L1 (B-slice : slice_type % 5 == 1)
    if (slice_header['slice_type'] % 5) == 1:
        result['luma_weight_l1_flag'] = []
        result['luma_weight_l1'] = []
        result['luma_offset_l1'] = []
        if ChromaArrayType != 0:
            result['chroma_weight_l1_flag'] = []
            result['chroma_weight_l1'] = []
            result['chroma_offset_l1'] = []

        for i in range(nL1 + 1):
            lw_flag = read_bool_safe(bs)  # luma_weight_l1_flag
            result['luma_weight_l1_flag'].append(lw_flag)
            luma_weight = 0
            luma_offset = 0
            if lw_flag:
                luma_weight = read_se_safe(bs)  # luma_weight_l1[i]
                luma_offset = read_se_safe(bs)  # luma_offset_l1[i]
            result['luma_weight_l1'].append(luma_weight)
            result['luma_offset_l1'].append(luma_offset)

            if ChromaArrayType != 0:
                cw_flag = read_bool_safe(bs)  # chroma_weight_l1_flag
                result['chroma_weight_l1_flag'].append(cw_flag)
                if cw_flag:
                    cw_list = []
                    co_list = []
                    for j in range(2):
                        cw_val = read_se_safe(bs)  # chroma_weight_l1[i][j]
                        co_val = read_se_safe(bs)  # chroma_offset_l1[i][j]
                        cw_list.append(cw_val)
                        co_list.append(co_val)
                else:
                    cw_list = [0, 0]
                    co_list = [0, 0]
                if 'chroma_weight_l1' not in result:
                    result['chroma_weight_l1'] = []
                    result['chroma_offset_l1'] = []
                result['chroma_weight_l1'].append(cw_list)
                result['chroma_offset_l1'].append(co_list)

    return result

def parse_dec_ref_pic_marking(bs, IdrPicFlag):
    result = {}
    if IdrPicFlag:
        # IDR picture
        result['no_output_of_prior_pics_flag'] = read_bool_safe(bs)
        result['long_term_reference_flag'] = read_bool_safe(bs)
    else:
        # Non-IDR
        result['adaptive_ref_pic_marking_mode_flag'] = read_bool_safe(bs)
        if result['adaptive_ref_pic_marking_mode_flag']:
            operations = []
            while True:
                mmco = read_ue_safe(bs)
                if mmco == 0:
                    break
                op = {
                    'memory_management_control_operation': mmco
                }
                if mmco in [1, 3]:
                    op['difference_of_pic_nums_minus1'] = read_ue_safe(bs)
                if mmco == 2:
                    op['long_term_pic_num'] = read_ue_safe(bs)
                if mmco in [3, 6]:
                    op['long_term_frame_idx'] = read_ue_safe(bs)
                if mmco == 4:
                    op['max_long_term_frame_idx_plus1'] = read_ue_safe(bs)
                operations.append(op)
            result['operations'] = operations
    return result




def parse_aud(data):
    # Access Unit Delimiter (AUD) parsing
    bs = BitStream(data)
    primary_pic_type = read_uint_safe(bs, 3)
    return {
        'primary_pic_type': primary_pic_type
    }


def parse_eos(data):
    # End of sequence/stream has no specific payload
    return {
        'data': data  # EOS does not contain any specific fields
    }


def parse_filler_data(data):
    # Filler data, can be ignored or processed if necessary
    bs = BitStream(data)
    filler_data = []
    while bs.pos < bs.len:
        filler_data.append(read_uint_safe(bs, 8))
    return {
        'filler_data': filler_data
    }

def parse_sps_extension(data):
    bs = BitStream(data)

    seq_parameter_set_id = read_ue_safe(bs)
    aux_format_idc = read_ue_safe(bs)
    bit_depth_aux_minus8 = read_ue_safe(bs)
    alpha_incr_flag = read_bool_safe(bs)
    alpha_opaque_value = read_uint_safe(bs, bit_depth_aux_minus8 + 9)
    alpha_transparent_value = read_uint_safe(bs, bit_depth_aux_minus8 + 9)
    additional_extension_flag = read_bool_safe(bs)

    return {
        'seq_parameter_set_id': seq_parameter_set_id,
        'aux_format_idc': aux_format_idc,
        'bit_depth_aux_minus8': bit_depth_aux_minus8,
        'alpha_incr_flag': alpha_incr_flag,
        'alpha_opaque_value': alpha_opaque_value,
        'alpha_transparent_value': alpha_transparent_value,
        'additional_extension_flag': additional_extension_flag
    }


def parse_aux_slice(data, sps, pps):
    bs = BitStream(data)

    first_mb_in_slice = read_ue_safe(bs)
    slice_type = read_ue_safe(bs)
    pic_parameter_set_id = read_ue_safe(bs)
    frame_num = bs.read(f'uint:{sps["log2_max_frame_num_minus4"] + 4}')

    field_pic_flag = None
    bottom_field_flag = None
    if sps['frame_mbs_only_flag'] == 0:
        field_pic_flag = read_bool_safe(bs)
        if field_pic_flag:
            bottom_field_flag = read_bool_safe(bs)

    idr_pic_id = None
    pic_order_cnt_lsb = None
    delta_pic_order_cnt_bottom = None
    delta_pic_order_cnt = []
    if slice_type in [5]:  # IDR slice
        idr_pic_id = read_ue_safe(bs)

    if sps['pic_order_cnt_type'] == 0:
        pic_order_cnt_lsb = bs.read(f'uint:{sps["log2_max_pic_order_cnt_lsb_minus4"] + 4}')
        if pps['bottom_field_pic_order_in_frame_present_flag'] and not field_pic_flag:
            delta_pic_order_cnt_bottom = read_se_safe(bs)
    elif sps['pic_order_cnt_type'] == 1 and not sps['delta_pic_order_always_zero_flag']:
        delta_pic_order_cnt.append(read_se_safe(bs))
        if pps['bottom_field_pic_order_in_frame_present_flag'] and not field_pic_flag:
            delta_pic_order_cnt.append(read_se_safe(bs))

    redundant_pic_cnt = None
    if pps['redundant_pic_cnt_present_flag']:
        redundant_pic_cnt = read_ue_safe(bs)

    direct_spatial_mv_pred_flag = None
    num_ref_idx_active_override_flag = None
    num_ref_idx_l0_active_minus1 = pps['num_ref_idx_l0_default_active_minus1']
    num_ref_idx_l1_active_minus1 = pps['num_ref_idx_l1_default_active_minus1']
    if slice_type in [0, 5, 2, 7, 4, 9]:
        num_ref_idx_active_override_flag = read_bool_safe(bs)
        if num_ref_idx_active_override_flag:
            num_ref_idx_l0_active_minus1 = read_ue_safe(bs)
            if slice_type in [2, 7]:
                num_ref_idx_l1_active_minus1 = read_ue_safe(bs)

    ref_pic_list_modification_flag_l0 = None
    modification_of_pic_nums_idc_l0 = []
    if slice_type in [0, 5, 1, 6]:
        ref_pic_list_modification_flag_l0 = read_bool_safe(bs)
        if ref_pic_list_modification_flag_l0:
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                modification_of_pic_nums_idc_l0.append(modification_of_pic_nums_idc)
                if modification_of_pic_nums_idc == 3:
                    break
                if modification_of_pic_nums_idc in [0, 1]:
                    read_ue_safe(bs)  # abs_diff_pic_num_minus1
                elif modification_of_pic_nums_idc == 2:
                    read_ue_safe(bs)  # long_term_pic_num

    ref_pic_list_modification_flag_l1 = None
    modification_of_pic_nums_idc_l1 = []
    if slice_type in [1, 6]:
        ref_pic_list_modification_flag_l1 = read_bool_safe(bs)
        if ref_pic_list_modification_flag_l1:
            while True:
                modification_of_pic_nums_idc = read_ue_safe(bs)
                modification_of_pic_nums_idc_l1.append(modification_of_pic_nums_idc)
                if modification_of_pic_nums_idc == 3:
                    break
                if modification_of_pic_nums_idc in [0, 1]:
                    read_ue_safe(bs)  # abs_diff_pic_num_minus1
                elif modification_of_pic_nums_idc == 2:
                    read_ue_safe(bs)  # long_term_pic_num

    return {
        'first_mb_in_slice': first_mb_in_slice,
        'slice_type': slice_type,
        'pic_parameter_set_id': pic_parameter_set_id,
        'frame_num': frame_num,
        'field_pic_flag': field_pic_flag,
        'bottom_field_flag': bottom_field_flag,
        'idr_pic_id': idr_pic_id,
        'pic_order_cnt_lsb': pic_order_cnt_lsb,
        'delta_pic_order_cnt_bottom': delta_pic_order_cnt_bottom,
        'delta_pic_order_cnt': delta_pic_order_cnt,
        'redundant_pic_cnt': redundant_pic_cnt,
        'direct_spatial_mv_pred_flag': direct_spatial_mv_pred_flag,
        'num_ref_idx_active_override_flag': num_ref_idx_active_override_flag,
        'num_ref_idx_l0_active_minus1': num_ref_idx_l0_active_minus1,
        'num_ref_idx_l1_active_minus1': num_ref_idx_l1_active_minus1,
        'ref_pic_list_modification_flag_l0': ref_pic_list_modification_flag_l0,
        'modification_of_pic_nums_idc_l0': modification_of_pic_nums_idc_l0,
        'ref_pic_list_modification_flag_l1': ref_pic_list_modification_flag_l1,
        'modification_of_pic_nums_idc_l1': modification_of_pic_nums_idc_l1,
    }