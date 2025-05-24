import requests

def fetch_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return {}
