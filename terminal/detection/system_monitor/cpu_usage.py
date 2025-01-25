import psutil

def monitor_cpu():
    usage = psutil.cpu_percent(interval=1)
    if usage > 80:
        print(f"High CPU usage detected: {usage}%")
    return usage

def monitor_memory():
    memory = psutil.virtual_memory()
    if memory.percent > 80:
        print(f"High memory usage detected: {memory.percent}%")
    return memory.percent

if __name__ == "__main__":
    print(f"CPU Usage: {monitor_cpu()}%")
    print(f"Memory Usage: {monitor_memory()}%")