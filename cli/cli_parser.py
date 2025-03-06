import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Multimedia Integrated Analysis Tool CLI")
    parser.add_argument("-p", "--parse", help="Parse mode")
    parser.add_argument("-sc", "--slack_carver", help="Slack carving mode")
    parser.add_argument("-i", "--input", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path", default="output.txt")
    return parser.parse_args()