import json
import requests

def send_alerts_to_admin(alert_data, admin_url):
    try:
        response = requests.post(f"{admin_url}/alerts", json=alert_data)
        response.raise_for_status()
        print("Alerts sent successfully")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send alerts: {e}")

# Example usage
if __name__ == "__main__":
    with open("/var/log/suricata/eve.json", "r") as eve_log:
        for line in eve_log:
            alert = json.loads(line)
            send_alerts_to_admin(alert, "http://admin-system.local")