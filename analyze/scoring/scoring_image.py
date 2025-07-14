from analyze.models import DomainResult, Finding

def image_structure(all_parsed_data):
    findings = []

    jitter = 0

    findings.append(
        Finding(
            item="frame_rate_jitter",
            value=jitter,
            severity="Critical" if jitter > 0.8 else "Low",
            comment="Test message."
        )
    )
    score = _normalize(jitter)   # normalize from 0 to 1
    return DomainResult(domain="image_structure", score=score, findings=findings)

def image_metadata(all_parsed_data):
    findings = []

    jitter = 0

    findings.append(
        Finding(
            item="frame_rate_jitter",
            value=jitter,
            severity="Critical" if jitter > 0.8 else "Low",
            comment="Test message."
        )
    )
    score = _normalize(jitter)   # normalize from 0 to 1
    return DomainResult(domain="image_metadata", score=score, findings=findings)

def image_compression(all_parsed_data):
    findings = []

    jitter = 0

    findings.append(
        Finding(
            item="frame_rate_jitter",
            value=jitter,
            severity="Critical" if jitter > 0.8 else "Low",
            comment="Test message."
        )
    )
    score = _normalize(jitter)   # normalize from 0 to 1
    return DomainResult(domain="image_compression", score=score, findings=findings)

def _normalize(value: float,
               lower: float = 0.0,
               upper: float = 1.0) -> float:
    
    if upper <= lower:
        raise ValueError("upper must be larger than lower")
    
    norm = (value - lower) / (upper - lower)
    return max(0.0, min(1.0, norm))