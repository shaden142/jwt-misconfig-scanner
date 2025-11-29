#!/usr/bin/env python3
import jwt
import json
import argparse
import base64
from jwt import InvalidSignatureError, DecodeError

# ===============================
#  LOAD WORDLIST FROM FILE
# ===============================
def load_wordlist(path):
    try:
        with open(path, "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        print(f"[!] Error loading wordlist: {e}")
        return []

# ===============================
#  DECODE JWT WITHOUT VERIFY
# ===============================
def decode_jwt_no_verify(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        return {"error": str(e)}

# ===============================
#  CHECK JWT HEADER FOR WEAK ALG
# ===============================
def check_header_weakness(token):
    header_part = token.split(".")[0]
    header_json = json.loads(
        base64.urlsafe_b64decode(header_part + "==").decode()
    )

    alg = header_json.get("alg", "")

    weaknesses = []
    if alg.lower() == "none":
        weaknesses.append("alg_none")
    if alg.lower().startswith("hs"):
        weaknesses.append("weak_algorithm")

    return alg, weaknesses

# ===============================
#  BRUTE FORCE SECRET
# ===============================
def brute_force_secret(token, wordlist):
    for secret in wordlist:
        try:
            jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
            return secret
        except (InvalidSignatureError, DecodeError):
            continue
    return None

# ===============================
#  RESIGN JWT IF SECRET FOUND
# ===============================
def resign_token(decoded_payload, secret):
    new_token = jwt.encode(decoded_payload, secret, algorithm="HS256")
    return new_token

# ===============================
#  SAVE REPORT
# ===============================
def save_report(report):
    with open("jwt_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("[+] Report saved to jwt_report.json")

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Misconfiguration Scanner")
    parser.add_argument("--token", required=True, help="JWT token to analyze")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")

    args = parser.parse_args()

    token = args.token
    wordlist_path = args.wordlist

    print("[+] Loading wordlist...")
    secrets = load_wordlist(wordlist_path)
    print(f"[+] Loaded {len(secrets)} secrets.")

    print("\n[+] Decoding JWT without verification ...")
    payload = decode_jwt_no_verify(token)
    print(json.dumps(payload, indent=4))

    print("\n[+] Checking header for misconfigurations ...")
    alg, header_issues = check_header_weakness(token)
    print(f"    Algorithm: {alg}")
    print(f"    Issues: {header_issues}")

    print("\n[+] Trying brute force for weak secret ...")
    found_secret = brute_force_secret(token, secrets)
    print(f"    Found secret: {found_secret}")

    new_token = None
    if found_secret:
        print("\n[+] Re-signing token using cracked secret ...")
        new_token = resign_token(payload, found_secret)
        print(f"    New forged token:\n    {new_token}")

    report_data = {
        "token": token,
        "algorithm": alg,
        "header_issues": header_issues,
        "decoded_payload": payload,
        "weak_secret": found_secret,
        "resigned_token": new_token,
        "recommendations": [
            "Avoid alg=none",
            "Use RS256 or ES256 instead of HMAC-based algorithms",
            "Use long, complex secrets",
            "Implement strict signature verification"
        ]
    }

    save_report(report_data)
