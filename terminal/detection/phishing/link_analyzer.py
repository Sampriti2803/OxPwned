import re
import requests

def extract_links(body):
    urls = re.findall(r"https?://[^\s]+", body)
    return urls

def analyze_links(urls, blacklist=["phishing-site.com"]):
    for url in urls:
        if any(domain in url for domain in blacklist):
            print(f"Phishing link detected: {url}")
        else:
            try:
                response = requests.head(url, allow_redirects=True, timeout=5)
                if "phishing" in response.url:
                    print(f"Redirect to phishing site detected: {response.url}")
            except Exception as e:
                print(f"Error analyzing URL: {url}, {e}")

if __name__ == "__main__":
    body = "Check out this link: https://example.com/login"
    urls = extract_links(body)
    analyze_links(urls)