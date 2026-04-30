import re

DEFAULT_CONTEXT_DISTANCE = 200


def redact(value: str) -> str:
    if len(value) < 3:
        return value
    redact_count = len(value) // 2
    start = len(value) // 2 - redact_count // 2
    end = len(value) // 2 + redact_count // 2
    return value[:start] + "*" * (end - start) + value[end:]


def luhn_check(number_str: str) -> bool:
    digits = [int(d) for d in re.sub(r"[\s-]", "", number_str) if d.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


VALIDATORS = {
    "luhn": luhn_check,
}


def _has_nearby_keyword(content: str, match_text: str, keywords: list[str], distance: int) -> bool:
    lower = content.lower()
    lower_kws = [kw.lower() for kw in keywords]
    start = 0
    while True:
        pos = lower.find(match_text.lower(), start)
        if pos == -1:
            break
        window_start = max(0, pos - distance)
        window_end = min(len(lower), pos + len(match_text) + distance)
        window = lower[window_start:window_end]
        if any(kw in window for kw in lower_kws):
            return True
        start = pos + 1
    return False


class ScanEngine:
    def __init__(self, fingerprints: dict, redact: bool = False):
        self._fingerprints = fingerprints
        self._redact = redact
        self._compiled: dict[str, re.Pattern] = {}
        self._compound: dict[str, dict] = {}

        for name, fp in fingerprints.items():
            if not isinstance(fp, dict):
                continue
            if "require_all" in fp:
                compiled_parts = {}
                for part_name, part_pattern in fp["require_all"].items():
                    compiled_parts[part_name] = re.compile(part_pattern, re.IGNORECASE)
                self._compound[name] = {
                    "compiled": compiled_parts,
                    "config": fp,
                }
            elif "pattern" in fp:
                self._compiled[name] = re.compile(fp["pattern"], re.IGNORECASE)

    def scan_text(self, content: str) -> list[dict]:
        if not content:
            return []
        results = []

        for name, regex in self._compiled.items():
            raw_matches = regex.findall(content)
            if not raw_matches:
                continue
            fp = self._fingerprints[name]

            validator_name = fp.get("validator")
            if validator_name and validator_name in VALIDATORS:
                validate = VALIDATORS[validator_name]
                raw_matches = [m for m in raw_matches if validate(m)]
                if not raw_matches:
                    continue

            unique = list(set(m.strip() for m in raw_matches))

            min_matches = fp.get("min_matches", 1)
            if len(raw_matches) < min_matches:
                continue

            severity = fp.get("severity", "low")
            category = fp.get("category", "unknown")

            confidence = "high"
            context_keywords = fp.get("context_keywords")
            if context_keywords:
                distance = fp.get("context_distance", DEFAULT_CONTEXT_DISTANCE)
                has_context = any(
                    _has_nearby_keyword(content, m, context_keywords, distance)
                    for m in unique
                )
                confidence = "high" if has_context else "low"
                if not has_context and fp.get("require_context", False):
                    continue

            if self._redact:
                unique = [redact(m) for m in unique]
                sample = redact(content[:50])
            else:
                sample = content[:50]

            results.append({
                "pattern_name": name,
                "matches": unique,
                "match_count": len(raw_matches),
                "sample_text": sample,
                "severity": severity,
                "category": category,
                "confidence": confidence,
            })

        for name, compound in self._compound.items():
            all_matches = {}
            all_found = True
            for part_name, part_regex in compound["compiled"].items():
                part_matches = part_regex.findall(content)
                if not part_matches:
                    all_found = False
                    break
                all_matches[part_name] = list(set(m.strip() for m in part_matches))
            if not all_found:
                continue

            fp = compound["config"]
            combined = []
            for part_name, matches in all_matches.items():
                for m in matches:
                    combined.append(f"{part_name}: {m}")

            if self._redact:
                combined = [redact(m) for m in combined]
                sample = redact(content[:50])
            else:
                sample = content[:50]

            results.append({
                "pattern_name": name,
                "matches": combined,
                "match_count": len(combined),
                "sample_text": sample,
                "severity": fp.get("severity", "high"),
                "category": fp.get("category", "pii"),
                "confidence": "high",
            })

        return results
