from typing import Dict

from analyze.models import DomainResult
from analyze.scoring.scoring_audio import audio_structure, audio_metadata, audio_compression
from analyze.scoring.scoring_image import image_structure, image_metadata, image_compression
from analyze.scoring.scoring_video import video_structure, video_metadata, video_compression

def compute_cdas(all_parsed_data) -> Dict[str, DomainResult]:
    domain_funcs = {
        "audio_structure": audio_structure,
        "audio_metadata":  audio_metadata,
        "audio_compression": audio_compression,
        "image_structure": image_structure,
        "image_metadata": image_metadata,
        "image_compression": image_compression,
        "video_structure": video_structure,
        "video_metadata": video_metadata,
        "video_compression": video_compression
    }
    beta = {"audio_structure":1, "audio_metadata":1, "audio_compression":1, "video_structure":1, "video_metadata":1, "video_compression":1, "image_structure":1, "image_metadata":1, "image_compression":1}
    weighted_sum, weight_total = 0, 0
    domain_results = {}

    for name, func in domain_funcs.items():
        result: DomainResult = func(all_parsed_data)
        domain_results[name] = result
        weighted_sum   += result.score * beta[name]
        weight_total   += beta[name]

    cdas_score = weighted_sum / weight_total if weight_total else 0
    return {"cdas": cdas_score, "domains": domain_results}





# from analyze.scoring.scoring_audio import audio_structure, audio_metadata, audio_compression
# from analyze.scoring.scoring_image import image_structure, image_metadata, image_compression
# from analyze.scoring.scoring_video import video_structure, video_metadata, video_compression

# def compute_cdas(all_parsed_data):
    
#     result_cdas = {
#         "audio_structure": audio_structure(all_parsed_data),
#         "audio_metadata": audio_metadata(all_parsed_data),
#         "audio_compression": audio_compression(all_parsed_data),
#         "image_structure": image_structure(all_parsed_data),
#         "image_metadata": image_metadata(all_parsed_data),
#         "image_compression": image_compression(all_parsed_data),
#         "video_structure": video_structure(all_parsed_data),
#         "video_metadata": video_metadata(all_parsed_data),
#         "video_compression": video_compression(all_parsed_data)
#     }

#     return result_cdas