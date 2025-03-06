from parsers.codecs.video.h264_parser import parse_h264_nal_units
from parsers.codecs.video.hevc_parser import parse_hevc_nal_units
from parsers.codecs.audio.aac_parser import parse_aac_audio
from parsers.codecs.audio.ac3_parser import parse_ac3_audio

def parse_h264(video_stream_data, sps, pps):
    return parse_h264_nal_units(video_stream_data, sps, pps)

def parse_hevc(video_stream_data, sps, pps, vps):
    return parse_hevc_nal_units(video_stream_data, sps, pps, vps)

def parse_audio_data(mdat_data, codec_data):
    if 'esds' in codec_data:
        return parse_aac_audio(mdat_data)
    elif 'dac3' in codec_data:
        return parse_ac3_audio(mdat_data)
    else:
        raise ValueError("Unsupported audio codec data")