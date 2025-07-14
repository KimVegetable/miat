from analyze.models import DomainResult, Finding

def audio_structure(all_parsed_data):
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
    return DomainResult(domain="audio_structure", score=score, findings=findings)

def audio_metadata(all_parsed_data):
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
    return DomainResult(domain="audio_metadata", score=score, findings=findings)

def audio_compression(all_parsed_data):
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
    return DomainResult(domain="audio_compression", score=score, findings=findings)

def _normalize(value: float,
               lower: float = 0.0,
               upper: float = 1.0) -> float:
    
    if upper <= lower:
        raise ValueError("upper must be larger than lower")
    
    norm = (value - lower) / (upper - lower)
    return max(0.0, min(1.0, norm))