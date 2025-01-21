import yara

def scan_with_yara(file_path, rule_path):
    """Scans a file using YARA rules."""
    rules = yara.compile(filepath=rule_path)
    matches = rules.match(file_path)
    return matches