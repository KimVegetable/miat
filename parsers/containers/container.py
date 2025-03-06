class Container:
    def __init__(self, file_path):
        self.file_path = file_path
        self.video_tracks = []
        self.audio_tracks = []
        self.metadata = {}

    def parse(self):
        raise NotImplementedError("Subclasses should implement this method")

    def add_video_track(self, track):
        self.video_tracks.append(track)

    def add_audio_track(self, track):
        self.audio_tracks.append(track)