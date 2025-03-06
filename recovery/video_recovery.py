from parsers.video_file import VideoFile

class VideoRecovery:
    def recover(self, file_path):
        video_file = VideoFile(file_path)
        video_file.parse()

        for codec in video_file.codecs:
            pass
        