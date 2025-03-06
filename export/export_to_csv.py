import csv

def export_to_csv(data, output_file):
    def flatten(data, parent_key='', sep='.'):
        items = []
        for k, v in data.items():
            new_key = f'{parent_key}{sep}{k}' if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, sub_item in enumerate(v):
                    items.extend(flatten({f'{k}_{i}': sub_item}, parent_key, sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    flattened_data = [flatten(d) for d in data]
    keys = sorted(set(k for d in flattened_data for k in d.keys()))

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(keys)
        for row in flattened_data:
            writer.writerow([row.get(key, '') for key in keys])