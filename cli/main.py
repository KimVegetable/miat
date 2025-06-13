import os
import sys
import tempfile
import argparse
import subprocess
from datetime import datetime

from export.export_to_csv import export_to_csv
from export.export_to_json import export_to_json
from parsers.video_file import VideoFile
from parsers.image_file import ImageFile

from utils.file_utils import get_file_signature, supported_extensions

def parse_args():
    parser = argparse.ArgumentParser(description="Multimedia Integrated Analysis Tool")
    parser.add_argument("-p", "--parse", action='store_true',help="Parse mode")
    parser.add_argument("-sc", "--slack_carver", action='store_true',help="Slack carving mode")
    parser.add_argument("-i", "--input",type=str, help='Directory containing the video files')
    parser.add_argument("-o", "--output", type=str, help='Output directory')
    parser.add_argument("-e", '--export', type=str, choices=['csv', 'json'], help='Export parsed data to CSV or JSON')
    parser.add_argument("-a", "--apple", action='store_true', help="Detect tampered videos using Apple \'Photos\'")
    return parser.parse_args()

def main():
    sys.set_int_max_str_digits(100000)
    
    args = parse_args()
    video_files = []
    image_files = []

    now = datetime.now()
    print(f"[{now.strftime('%Y-%m-%d-%H.%M.%S')}] Start analyzing.")
    # Parse mode
    if args.parse:
        for root, dirs, files in os.walk(args.input):
            for file in files:
                if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.heic', '.h264', '.h265', '.m4a', '.aac', '.3gp')):
                    video_files.append(os.path.join(root, file))
                elif file.lower().endswith(('.jpg', '.jpeg', '.dng', '.tiff', '.png', '.gif', 'webp')):
                    image_files.append(os.path.join(root, file))

        all_parsed_data = []
        for video_file in video_files:
            print(f"Parsing video file: {video_file}")
            video = VideoFile(video_file)
            video.parse()

            # Task to lffower output size
            if True:
                if video.data.get('container') != 'H.264' and video.data.get('container') != 'H.265':
                    # mdat skip
                    if type(video.data.get('container', {}).get('mdat', {})) is list: # multiple mdat
                        for data in video.data['container']['mdat']:
                            data['data'] = "skip"
                    elif video.data.get('container', {}).get('mdat', {}).get('data') is not None:
                        video.data['container']['mdat']['data'] = "skip"
                # nal rawdata skip
                for video_stream in video.video_streams:
                    for nal in video_stream['nal_units']['nal_units']:
                        nal['data'] = nal['raw_data'] = "skip"
                    for segment in video_stream['nal_units']['slice_segments']:
                        segment['data'] = "skip"
                    # nal slice_headers skip
                    video_stream['nal_units']['slice_headers'] = "skip"

            all_parsed_data.append(video.data)

        # Forensic analysis for trimmed videos
        if args.apple:
            for video in all_parsed_data:
                # media_time = Zero (There is no unreferenced frames.)
                if type(video['container']['moov']['trak']) == list:
                    trak = video['container']['moov']['trak'][0]
                elif type(video['container']['moov']['trak']) == dict:
                    trak = video['container']['moov']['trak']
                if trak.get('edts') == None:
                    continue
                
                media_time = 0
                for entry in trak['edts']['elst']['entries']:
                    if entry['media_time'] == b'\xFF\xFF\xFF\xFF':
                        continue
                    else:
                        media_time = entry['media_time']
                
                ctts_flag = True

                if trak.get('mdia', {}).get('minf', {}).get('stbl', {}).get('ctts', None) == None:
                    ctts_flag = False

                if media_time == 0 or (ctts_flag and media_time - trak.get('mdia', {}).get('minf', {}).get('stbl', {}).get('ctts', None)['entries'][0]['sample_offset'] == 0): # arrange for lead_in
                    if video['video_streams'][0]['codec'] == 'H.264':
                        if video['video_streams'][0]['nal_units']['sps']['pic_order_cnt_type'] == 0:
                            if video['video_streams'][0]['nal_units']['slice_segments'][0]['header'].get('pic_order_cnt_lsb', '0') == 0:
                                print(f"[Analysis] \'{video['file_path']}\' is a unknown file. (There is no unreferenced frames.)")
                            else:
                                print(f"[Analysis] \'{video['file_path']}\' is a edited file. (There is no unreferenced frames.)")

                        elif video['video_streams'][0]['nal_units']['sps']['pic_order_cnt_type'] == 1:
                            if video['video_streams'][0]['nal_units']['slice_segments'][0]['header']['slice_type'] % 5 in [2, 4]:
                                # IDR = 0
                                print(f"[Analysis] \'{video['file_path']}\' is a unknown file. (There is no unreferenced frames.)")

                        elif video['video_streams'][0]['nal_units']['sps']['pic_order_cnt_type'] == 2:
                            if video['video_streams'][0]['nal_units']['slice_segments'][0]['header']['frame_num'] == 0:
                                print(f"[Analysis] \'{video['file_path']}\' is a unknown file. (There is no unreferenced frames.)")
                            else:
                                print(f"[Analysis] \'{video['file_path']}\' is a edited file. (There is no unreferenced frames.)")

                    elif video['video_streams'][0]['codec'] == 'H.265':
                        if video['video_streams'][0]['nal_units']['slice_segments'][0]['header'].get('pic_order_cnt_lsb', 0) == 0:
                            print(f"[Analysis] \'{video['file_path']}\' is a unknown file. (There is no unreferenced frames.)")
                        else:
                            print(f"[Analysis] \'{video['file_path']}\' is a edited file. (There is no unreferenced frames.)")

                else:
                    media_time = 0
                    for entry in trak['edts']['elst']['entries']:
                        if entry['media_time'] == b'\xFF\xFF\xFF\xFF':
                            continue
                        else:
                            media_time = entry['media_time']
                    
                    
                    if trak.get('mdia', {}).get('minf', {}).get('stbl', {}).get('ctts', None) != None:
                        media_time = media_time - trak.get('mdia', {}).get('minf', {}).get('stbl', {}).get('ctts', None)['entries'][0]['sample_offset']

                    if len(trak['mdia']['minf']['stbl']['stts']['entries']) > 0:
                        if media_time > trak['mdia']['minf']['stbl']['stts']['entries'][0]['sample_delta']:
                            # extract unreferenced frames

                            stts_entries = trak['mdia']['minf']['stbl']['stts']['entries']
                            stts_list = []
                            for stts_entry in stts_entries:
                                stts_list.extend([stts_entry['sample_delta']] * stts_entry['sample_count'])
                            
                            start_time = 0
                            start_offset = 0

                            for i, sample_delta in enumerate(stts_list):
                                if start_time >= media_time:
                                    start_offset = i - 1
                                    break
                                start_time += sample_delta
                            
                            if start_offset == 0:
                                raise Exception("Start offset Error")
                            
                            unreferenced_frame_range = [0, start_offset]

                            # demux
                            if video['video_streams'][0]['codec'] == 'H.264':
                                codec_name = 'h264'
                            elif video['video_streams'][0]['codec'] == 'H.265':
                                codec_name = 'h265'
                            with tempfile.TemporaryDirectory() as temp_dir:
                                temp_output = os.path.join(temp_dir, f'ffmpeg_temp.{codec_name}')

                                cmd = [
                                    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'ffmpeg', 'ffmpeg.exe'),
                                    '-i', video['file_path'],
                                    '-c:v', 'copy',
                                    '-an',
                                    temp_output
                                ]

                                try:
                                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                except FileNotFoundError:
                                    cmd = [
                                        os.path.join(os.path.dirname(__file__), 'utils', 'ffmpeg',
                                                    'ffmpeg.exe'),
                                        '-i', video['file_path'],
                                        '-c:v', 'copy',
                                        '-an',
                                        temp_output
                                    ]

                                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                                if result.returncode != 0:
                                    print(f"ffmpeg error: {result.stderr.decode('utf-8')}")
                                    return

                                # extract unreferenced frames
                                cmd = [
                                    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'ffmpeg', 'ffmpeg.exe'),
                                    '-i', temp_output,
                                    '-vf', f'select=\'between(n,{unreferenced_frame_range[0]},{unreferenced_frame_range[1]})\'',
                                    '-vsync', '0',
                                    os.path.join(args.output, 'unreferenced_frame', video['file_path'].rsplit(os.path.sep, 1)[-1], 'extracted_frame_%04d.png')
                                ]

                                unref_dir = os.path.join(
                                    args.output,
                                    'unreferenced_frame',
                                    video['file_path'].rsplit(os.path.sep, 1)[-1]
                                )

                                os.makedirs(unref_dir, exist_ok=True)

                                print(f"[Analysis] \'{video['file_path']}\' is a edited file. Extracted unreferenced frames.")

                                try:
                                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                except FileNotFoundError:
                                    cmd = [
                                        os.path.join(os.path.dirname(__file__), 'utils', 'ffmpeg',
                                                    'ffmpeg.exe'),
                                        '-i', temp_output,
                                        '-vf',
                                        f'select=\'between(n,{unreferenced_frame_range[0]},{unreferenced_frame_range[1]})\'',
                                        '-vsync', '0',
                                        os.path.join(args.output, 'unreferenced_frame',
                                                    video['file_path'].rsplit(os.path.sep, 1)[-1],
                                                    'extracted_frame_%04d.png')
                                    ]
                                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                except Exception:
                                    print("Please check if the file '.\\utils\\ffmpeg\\ffmpeg.exe' exists.")

                                if result.returncode != 0:
                                    print(f"ffmpeg error: {result.stderr.decode('utf-8')}")
                                    return
                                
                    elif len(video.get('container', {}).get('moof', {})) > 0: # multiple mdat

                        moof_list = video.get('container', {}).get('moof', {})
                        first_moof = moof_list[0]

                        samples = first_moof.get('traf', {}).get('trun', {}).get('samples', {})
                        
                        start_time = 0
                        start_offset = 0

                        if len(samples) > 0:
                            for i, sample in enumerate(samples):
                                if start_time >= media_time:
                                    start_offset = i - 1
                                    break
                                start_time += sample['sample_composition_time_offset']

                        if start_offset == -1:
                            print(f"[Analysis] \'{video['file_path']}\' is a edited file. (There is no unreferenced frames)")

                        unreferenced_frame_range = [0, start_offset]

                        # demux
                        if video['video_streams'][0]['codec'] == 'H.264':
                            codec_name = 'h264'
                        elif video['video_streams'][0]['codec'] == 'H.265':
                            codec_name = 'h265'
                        with tempfile.TemporaryDirectory() as temp_dir:
                            temp_output = os.path.join(temp_dir, f'ffmpeg_temp.{codec_name}')

                            cmd = [
                                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'ffmpeg', 'ffmpeg.exe'),
                                '-i', video['file_path'],
                                '-c:v', 'copy',
                                '-an',
                                temp_output
                            ]

                            try:
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            except FileNotFoundError:
                                cmd = [
                                    os.path.join(os.path.dirname(__file__), 'utils', 'ffmpeg',
                                                'ffmpeg.exe'),
                                    '-i', video['file_path'],
                                    '-c:v', 'copy',
                                    '-an',
                                    temp_output
                                ]

                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                            if result.returncode != 0:
                                print(f"ffmpeg error: {result.stderr.decode('utf-8')}")
                                return

                            # extract unreferenced frames
                            cmd = [
                                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'ffmpeg', 'ffmpeg.exe'),
                                '-i', temp_output,
                                '-vf', f'select=\'between(n,{unreferenced_frame_range[0]},{unreferenced_frame_range[1]})\'',
                                '-vsync', '0',
                                os.path.join(args.output, 'unreferenced_frame', video['file_path'].rsplit(os.path.sep, 1)[-1], 'extracted_frame_%04d.png')
                            ]

                            unref_dir = os.path.join(
                                args.output,
                                'unreferenced_frame',
                                video['file_path'].rsplit(os.path.sep, 1)[-1]
                            )

                            os.makedirs(unref_dir, exist_ok=True)

                            print(f"[Analysis] \'{video['file_path']}\' is a edited file. Extracted unreferenced frames.")

                            try:
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            except FileNotFoundError:
                                cmd = [
                                    os.path.join(os.path.dirname(__file__), 'utils', 'ffmpeg',
                                                'ffmpeg.exe'),
                                    '-i', temp_output,
                                    '-vf',
                                    f'select=\'between(n,{unreferenced_frame_range[0]},{unreferenced_frame_range[1]})\'',
                                    '-vsync', '0',
                                    os.path.join(args.output, 'unreferenced_frame',
                                                video['file_path'].rsplit(os.path.sep, 1)[-1],
                                                'extracted_frame_%04d.png')
                                ]
                                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            except Exception:
                                print("Please check if the file '.\\utils\\ffmpeg\\ffmpeg.exe' exists.")

                            if result.returncode != 0:
                                print(f"ffmpeg error: {result.stderr.decode('utf-8')}")
                                return

                    else:
                        print(f"[Analysis] \'{video['file_path']}\' is a edited file. (There is no unreferenced frames)")

        # Forensic analysis for rotated and flipped videos
        if args.apple:
            for video in all_parsed_data:

                if type(video['container']['moov']['trak']) == list:
                    trak = video['container']['moov']['trak'][0]
                elif type(video['container']['moov']['trak']) == dict:
                    trak = video['container']['moov']['trak']
                if trak.get('tkhd') == None:
                    continue

                print(f"\n[Analysis] The matrix of \'{video['file_path']}\': [a = {trak['tkhd']['matrix'][0]}, b = {trak['tkhd']['matrix'][1]}, c = {trak['tkhd']['matrix'][3]}, d = {trak['tkhd']['matrix'][4]}].")

        # Forensic analysis for cropped and perspective-adjusted videos
        if args.apple:
            for video in all_parsed_data:
                if type(video['container']['moov']['trak']) == list:
                    trak = video['container']['moov']['trak'][0]
                elif type(video['container']['moov']['trak']) == dict:
                    trak = video['container']['moov']['trak']
                if trak.get('tkhd') == None:
                    continue

                print(f"\n[Analysis] \'{video['file_path']}\': [width: {trak['tkhd']['width']}, height: {trak['tkhd']['height']}] ")

                if video['container']['moov'].get('meta') != None:
                    meta = video['container']['moov'].get('meta')
                
                    if meta.get('keys') != None:
                        for i, entry in enumerate(meta['keys']['entries']):
                            if meta['ilst'][i]['subatoms'][0].get('value') == None:
                                continue
                            print(f'key: {entry}, value: {meta['ilst'][i]['subatoms'][0]['value']} ')

                if video['container']['moov'].get('udta') != None:
                    meta = video['container']['moov']['udta'].get('meta')
                
                    if meta.get('keys') != None:
                        for i, entry in enumerate(meta['keys']['entries']):
                            if meta['ilst'][i]['subatoms'][0].get('value') == None:
                                continue
                            print(f'key: {entry}, value: {meta['ilst'][i]['subatoms'][0]['value']} ')

                if video['container']['moov'].get('udta', None) != None:
                    if video['container']['moov']['udta'].get('©xyz', None) != None:
                        print(f"[coordinate: {video['container']['moov']['udta'].get('©xyz')}]")


        # for image file
        for image_file in image_files:
            print(f"Parsing image file: {image_file}")
            image = ImageFile(image_file)
            image.parse()
            all_parsed_data.append(image.data)

        if args.export:
            output_file = os.path.join(args.output, f'{now.strftime('%Y-%m-%d-%H.%M.%S')}-output.{args.export}')
            if args.export == 'csv':
                export_to_csv(all_parsed_data, output_file)
            elif args.export == 'json':
                export_to_json(all_parsed_data, output_file)
            print(f"Exported data to {output_file}")

    elif args.slack_carver:
        for root, dirs, files in os.walk(args.input):
            for file in files:
                if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov')):
                    video_files.append(os.path.join(root, file))

    end = datetime.now()
    print(f"[{end.strftime('%Y-%m-%d-%H.%M.%S')}] Finished.")

if __name__ == "__main__":
    main()