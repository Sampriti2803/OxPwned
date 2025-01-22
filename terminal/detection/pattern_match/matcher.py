'''
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
    '''

import os
import re
import json

class PatternMatcher:
    def __init__(self, rules_path):
        self.rules = self.load_rules(rules_path)

    def load_rules(self, rules_path):
        """Load rules from the specified directory."""
        rules = {}
        for file_name in os.listdir(rules_path):
            if file_name.endswith(".json"):
                with open(os.path.join(rules_path, file_name), "r") as f:
                    rules[file_name] = json.load(f)
        return rules

    def match_patterns(self, data):
        """Match data against loaded patterns."""
        matches = []
        for rule_file, patterns in self.rules.items():
            for key, pattern in patterns.items():
                if re.search(pattern, data.get(key, ""), re.IGNORECASE):
                    matches.append({"rule_file": rule_file, "key": key, "pattern": pattern})
        return matches