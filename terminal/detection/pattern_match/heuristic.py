class HeuristicAnalyzer:
    def __init__(self):
        self.key_indicators = ["ransom", "malware", "suspicious", "encrypted"]

    def analyze(self, data):
        """Perform heuristic analysis on data."""
        indicators = {}
        for indicator in self.key_indicators:
            if indicator in data.get("content", "").lower():
                indicators[indicator] = True
            else:
                indicators[indicator] = False
        return indicators