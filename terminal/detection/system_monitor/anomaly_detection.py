def detect_anomalies(cpu_usage, process_list):
    if cpu_usage > 90:
        print("CPU spike detected!")
    for proc in process_list:
        if proc['cpu_percent'] > 50:  # Example threshold
            print(f"Suspicious process: {proc['name']} consuming {proc['cpu_percent']}% CPU")