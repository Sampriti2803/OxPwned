import re
from .utils import load_patterns

def match_patterns(data):
    """Matches data against regex patterns."""
    patterns = load_patterns("regex_patterns/")
    matches = []
    for pattern in patterns:
        if re.search(pattern, data):
            matches.append(pattern)
    return matches