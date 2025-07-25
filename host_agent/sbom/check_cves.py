import requests

def check_cves(package_name, version):
    data = {
        "package": {
            "name": package_name,
            "ecosystem": "Debian"
        },
        "version": version
    }
    try:
        res = requests.post("https://api.osv.dev/v1/query", json=data)
        return res.json()
    except Exception as e:
        print(f"Error querying CVEs for {package_name}: {e}")
        return {}

# Example usage:
print(check_cves("openssl", "1.1.1f-1ubuntu2"))
