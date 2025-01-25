import psutil

def watch_processes(blacklist):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        if proc.info['name'] in blacklist:
            print(f"Potential malicious process detected: {proc.info}")
        processes.append(proc.info)
    return processes

if __name__ == "__main__":
    blacklist = ['malware.exe', 'suspicious_process']
    watch_processes(blacklist)