import re


def redact(value: str) -> str:
    if len(value) < 3:
        return value
    redact_count = len(value) // 2
    start = len(value) // 2 - redact_count // 2
    end = len(value) // 2 + redact_count // 2
    return value[:start] + "*" * (end - start) + value[end:]


class ScanEngine:
    def __init__(self, fingerprints: dict, redact: bool = False):
        self._fingerprints = fingerprints
        self._redact = redact
        self._compiled: dict[str, re.Pattern] = {}
        for name, fp in fingerprints.items():
            pattern_str = fp["pattern"] if isinstance(fp, dict) else fp
            self._compiled[name] = re.compile(pattern_str, re.IGNORECASE)

    def scan_text(self, content: str) -> list[dict]:
        if not content:
            return []
        results = []
        for name, regex in self._compiled.items():
            raw_matches = regex.findall(content)
            if not raw_matches:
                continue
            unique = list(set(m.strip() for m in raw_matches))
            fp = self._fingerprints[name]
            fp_dict = fp if isinstance(fp, dict) else {}
            severity = fp_dict.get("severity", "low")
            category = fp_dict.get("category", "unknown")

            confidence = "high"
            context_keywords = fp_dict.get("context_keywords")
            if context_keywords:
                lower_content = content.lower()
                has_context = any(kw.lower() in lower_content for kw in context_keywords)
                confidence = "high" if has_context else "low"

            if self._redact:
                unique = [redact(m) for m in unique]
                sample = redact(content[:50])
            else:
                sample = content[:50]

            result = {
                "pattern_name": name,
                "matches": unique,
                "match_count": len(unique),
                "sample_text": sample,
                "severity": severity,
                "category": category,
                "confidence": confidence,
            }
            results.append(result)
        return results
