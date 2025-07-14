from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Finding:
    item: str          # ex) "SPS.pic_width_in_mbs_minus1"
    value: Any         # 실제 값
    severity: str      # Low / Info / Warn / Critical
    comment: str       # 사람이 읽을 설명

@dataclass
class DomainResult:
    domain: str        # "video_structure" …
    score: float       # 0~1 정규화
    findings: List[Finding] = field(default_factory=list)