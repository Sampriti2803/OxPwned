import json
from matcher import PatternMatcher
from heuristic import HeuristicAnalyzer

class DetectionEngine:
    def __init__(self, rules_path):
        self.matcher = PatternMatcher(rules_path)
        self.heuristic = HeuristicAnalyzer()

    def detect(self, input_data):
        """Detect patterns in the input data."""
        matches = self.matcher.match_patterns(input_data)
        heuristics = self.heuristic.analyze(input_data)

        return {
            "pattern_matches": matches,
            "heuristic_analysis": heuristics
        }

if __name__ == "__main__":
    # Example usage
    rules_path = "terminal/detection/pattern_match/rules/regex_patterns"
    engine = DetectionEngine(rules_path)
    sample_data = {
        "domain": "malicious-site.ru",
        "content": "Some suspicious traffic details.",
    }
    result = engine.detect(sample_data)
    print(json.dumps(result, indent=4))