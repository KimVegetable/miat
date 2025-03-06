import json
import base64
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return super().default(obj)

def export_to_json(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, cls=CustomJSONEncoder, indent=4)
