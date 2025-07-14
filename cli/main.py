import os
import sys
import tempfile
import argparse
import subprocess
from datetime import datetime

from analyze.analyze import run_analyze
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

        # for image file
        for image_file in image_files:
            print(f"Parsing image file: {image_file}")
            image = ImageFile(image_file)
            image.parse()
            all_parsed_data.append(image.data)

        run_analyze(all_parsed_data, args)

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