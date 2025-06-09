import os
import subprocess
import tempfile

import ffmpeg
from parsers.containers.mp4_parser import MP4Parser
from parsers.codecs.codec import parse_h264, parse_hevc, parse_audio_data

class VideoFile:
    def __init__(self, file_path):
        self.file_path = file_path
        self.container = None
        self.video_streams = []
        self.audio_streams = []
        self.data = {}
        self.ffmpeg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'utils', 'ffmpeg', 'ffmpeg.exe')

    def determine_container(self):
        extension = os.path.splitext(self.file_path)[1].lower()
        if extension in ['.mp4', '.mov', '.heic', '.aac', '.m4a', '.3gp']:
            self.container = MP4Parser(self.file_path)
        elif extension in ['.h264', '.h265']:
            self.container = extension[1:]  # codec
        else:
            raise ValueError("Unsupported file format")

    def parse(self):
        self.determine_container()
        if isinstance(self.container, MP4Parser):
            self.container.parse()
            self.handle_container_specific_codecs()
            self.data = {
                'file_path': self.file_path,
                'container': self.container.atoms, # To-do, container name
                'video_streams': self.video_streams,
                'audio_streams': self.audio_streams
            }
            
        elif type(self.container) == str and self.container in ['h264', 'h265']:
            if self.container == 'h264':
                codec_type = 'avc1'
            elif self.container == 'h265':
                codec_type = 'hvc1'
                
            with open(self.file_path, 'rb') as f:
                video_stream = f.read()
                self.parse_video_codec(codec_type=codec_type, video_stream=video_stream)
                
            self.data = {
                'file_path': self.file_path,
                'container': self.container,
                'video_streams': self.video_streams,
                'audio_streams': self.audio_streams
            }
        
        return self.data

    def handle_container_specific_codecs(self):
        if isinstance(self.container, MP4Parser):
            atoms = self.container.atoms

            self.handle_mp4_codecs(atoms)

        # Add other container-specific handlers here

    def handle_mp4_codecs(self, atoms):
        # Threr is a moov box
        if 'moov' in atoms:
            moov = atoms['moov']
            if type(moov.get('trak', [])) == list:  # Two more tracks
                for trak in moov.get('trak', []):
                    mdia = trak.get('mdia', {})
                    hdlr = mdia.get('hdlr', {})
                    minf = mdia.get('minf', {})
                    stbl = minf.get('stbl', {})

                    if hdlr.get('handler_type') == 'vide':
                        stsd = stbl.get('stsd', {})
                        entries = stsd.get('entries', [])
                        for entry in entries:
                            codec_type = entry.get('type')
                            self.parse_video_codec(codec_type=codec_type)

                    elif hdlr.get('handler_type') == 'soun':
                        # self.parse_audio_codec(stbl, mdat_data)
                        pass

            elif type(moov.get('trak', [])) == dict:  # One track
                trak = moov.get('trak', {})
                mdia = trak.get('mdia', {})
                hdlr = mdia.get('hdlr', {})
                minf = mdia.get('minf', {})
                stbl = minf.get('stbl', {})

                if hdlr.get('handler_type') == 'vide':
                    stsd = stbl.get('stsd', {})
                    entries = stsd.get('entries', [])
                    for entry in entries:
                        codec_type = entry.get('type')
                        self.parse_video_codec(codec_type=codec_type)
                elif hdlr.get('handler_type') == 'soun':
                    # self.parse_audio_codec(stbl, mdat_data)
                    pass

        # There is no moov box, ex) HEIF
        elif 'meta' in atoms:
            meta = atoms['meta']
            codec_type = None
            sps = None
            pps = None
            vps = None

            if type(meta.get('iprp')) == dict:
                if type(meta.get('iprp').get('boxes')) == list:
                    for box in meta.get('iprp').get('boxes'):
                        if type(box.get('properties')) == list:
                            for prop in box.get('properties'):
                                if prop.get('type') == 'hvcC':
                                    codec_type = 'hvc1'
                                    sps = prop['sps'][0]
                                    pps = prop['pps'][0]
                                    vps = prop['vps'][0]
                                    break

            with open(self.file_path, 'rb') as f:
                mp4_stream = f.read()

            video_stream = b''
            if type(meta.get('iloc')) == dict:
                for item in meta.get('iloc').get('items'):
                    extent_offset = item['extents']['extent_offset']
                    extent_length = item['extents']['extent_length']
                    video_stream += b'\x00\x00\x00\x01' + mp4_stream[extent_offset + 4 : extent_offset + extent_length]


            self.parse_video_codec(codec_type=codec_type, video_stream=video_stream, sps=sps, pps=pps, vps=vps)



    def demux_video(self, video_codec=None):
        video_stream_data = None

        if video_codec != None:
            if video_codec == 'avc1':
                codec_name = 'h264'
            elif video_codec in ['hvc1', 'hev1']:
                codec_name = 'h265'
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_output = os.path.join(temp_dir, f'ffmpeg_temp.{codec_name}')

                cmd = [
                    self.ffmpeg_path,
                    '-i', self.file_path,
                    '-c:v', 'copy',
                    '-an',
                    temp_output
                ]
                
                try:
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except Exception:
                    print("Please check if the file '.\\utils\\ffmpeg\\ffmpeg.exe' exists.")

                if result.returncode != 0:
                    print(f"ffmpeg error: {result.stderr.decode('utf-8')}")
                    return

                # Read the extracted video stream into memory
                with open(temp_output, 'rb') as f:
                    video_stream_data = f.read()
        return video_stream_data

    def parse_video_codec(self, codec_type=None, video_stream=None, sps=None, pps=None, vps=None):
        if codec_type == 'avc1':
            if video_stream == None:
                video_stream = self.demux_video(codec_type)
            # video_stream = self.demux_using_container()
            self.handle_avc1(video_stream, sps, pps)
        elif codec_type in ['hvc1', 'hev1']:
            if video_stream == None:
                video_stream = self.demux_video(codec_type)
            # video_stream = self.demux_using_container()
            self.handle_hevc(video_stream, sps, pps, vps)
        # Add other video codecs here

    # Test code
    def demux_using_container(self):
        container = self.container

        if not container or 'moov' not in container.atoms:
            raise ValueError("Invalid or incomplete container information")

        file_name = os.path.splitext(os.path.basename(self.file_path))[0]
        output_dir = os.path.join(r"G:\MIAT-test\target\cut", file_name)
        os.makedirs(output_dir, exist_ok=True)

        moov = container.atoms['moov']
        traks = moov.get('trak', [])

        vps, sps, pps, sei = None, None, None, None
        entries = moov.get('trak', [])[0].get('mdia', {}).get('minf', {}).get('stbl', {}).get('stsd', {}).get('entries', [])
        if entries:
            extensions = entries[0].get('extensions', [])
            if extensions:
                vps = extensions[0].get('vps', [None])[0]
                sps = extensions[0].get('sps', [None])[0]
                pps = extensions[0].get('pps', [None])[0]
                sei = extensions[0].get('sei', [None])[0]

        stsc, stsz, stco = [], [], []

        for trak in traks:
            mdia = trak.get('mdia', {})
            hdlr = mdia.get('hdlr', {})
            minf = mdia.get('minf', {})
            stbl = minf.get('stbl', {})

            if hdlr.get('handler_type') == 'vide':
                stsc = stbl.get('stsc', {}).get('entries', [])
                stsz = stbl.get('stsz', {}).get('entries', [])
                stco = stbl.get('stco', {}).get('entries', [])
                break

        full_stream = b''
        sample_size_index = 0
        with open(self.file_path, 'rb') as f:
            stsc_ranges = []
            for i, entry in enumerate(stsc):
                start_chunk = entry['first_chunk']
                samples_per_chunk = entry['samples_per_chunk']
                if i < len(stsc) - 1:
                    end_chunk = stsc[i+1]['first_chunk'] - 1
                else:
                    end_chunk = len(stco)
                stsc_ranges.append((start_chunk, end_chunk, samples_per_chunk))


            for (start_chunk, end_chunk, samples_per_chunk) in stsc_ranges:
                for chunk_index in range(start_chunk - 1, end_chunk):
                    chunk_offset = stco[chunk_index]
                    for _ in range(samples_per_chunk):
                        if sample_size_index >= len(stsz):
                            break
                        sample_size = stsz[sample_size_index]
                        f.seek(chunk_offset)
                        sample_data = f.read(sample_size)
                        full_stream += sample_data
                        chunk_offset += sample_size
                        sample_size_index += 1

                    if sample_size_index >= len(stsz):
                        break
                if sample_size_index >= len(stsz):
                    break


        nal_units = []
        i = 0
        while i < len(full_stream):
            if i + 4 > len(full_stream):
                break

            nal_size = int.from_bytes(full_stream[i:i+4], 'big')
            i += 4
            if i + nal_size > len(full_stream):
                break

            nal_unit = b'\x00\x00\x00\x01' + full_stream[i:i+nal_size]
            nal_units.append(nal_unit)
            i += nal_size

        parameter_sets = b''
        if vps: parameter_sets += b'\x00\x00\x00\x01' + vps
        if sps: parameter_sets += b'\x00\x00\x00\x01' + sps
        if pps: parameter_sets += b'\x00\x00\x00\x01' + pps
        if sei: parameter_sets += b'\x00\x00\x00\x01' + sei

        updated_nal_units = []
        for nal_unit in nal_units:
            if len(nal_unit) > 5:
                nal_type = (nal_unit[4] & 0x7E) >> 1
                if 16 <= nal_type <= 21:
                    if parameter_sets:
                        updated_nal_units.append(parameter_sets)
            updated_nal_units.append(nal_unit)

        nal_units = updated_nal_units

        frame_count = 0
        for nal_unit in nal_units:
            if len(nal_unit) > 5:
                nal_type = (nal_unit[4] & 0x7E) >> 1
                if nal_type < 32:  
                    frame_count += 1
                    frame_path = os.path.join(output_dir, f"{frame_count}.h265")
                    with open(frame_path, 'wb') as f:
                        f.write(parameter_sets + nal_unit)

        final_stream = b''.join(nal_units)
        return final_stream

    def parse_audio_codec(self, stbl, mdat_data):
        stsd = stbl.get('stsd', {})
        entries = stsd.get('entries', [])
        for entry in entries:
            codec_type = entry.get('type')
            if codec_type == 'mp4a':
                self.handle_mp4a(entry, mdat_data)
            elif codec_type == 'ac-3':
                self.handle_ac3(entry, mdat_data)
            # Add other audio codecs here

    def handle_avc1(self, video_stream_data, sps, pps):
        nal_units = parse_h264(video_stream_data, sps, pps)
        self.video_streams.append({
            'codec': 'H.264',
            'nal_units': nal_units
        })


    def handle_hevc(self, video_stream_data, sps, pps, vps):
        # Parse hvcC data here
        nal_units = parse_hevc(video_stream_data, sps, pps, vps)
        self.video_streams.append({
            'codec': 'H.265',
            'nal_units': nal_units
        })

    def handle_mp4a(self, entry, mdat_data):
        esds_data = entry.get('extensions', {}).get('esds', {})
        audio_data = parse_audio_data(mdat_data, esds_data)
        self.audio_streams.append({
            'codec': 'AAC',
            'audio_data': audio_data
        })

    def handle_ac3(self, entry, mdat_data):
        dac3_data = entry.get('extensions', {}).get('dac3', {})
        audio_data = parse_audio_data(mdat_data, dac3_data)
        self.audio_streams.append({
            'codec': 'AC-3',
            'audio_data': audio_data
        })
