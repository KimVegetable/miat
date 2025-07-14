from analyze.engines.apple import analyze_apple
from analyze.aggregator import compute_cdas

def run_analyze(all_parsed_data, args):

    if args.apple:
        analyze_apple(all_parsed_data, args)

    cdas_report = compute_cdas(all_parsed_data)

    return cdas_report