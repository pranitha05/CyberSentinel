import hashlib
import requests

def check_password_breach(password):
    # Hash the password using SHA-1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    # Query the HaveIBeenPwned API using k-Anonymity
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking breach status"

    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return f"⚠️ Found in {count} breaches"

    return "✅ No breach found"
