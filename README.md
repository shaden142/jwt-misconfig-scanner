# JWTScope - JWT Misconfiguration Scanner

JWTScope is a security testing tool designed to detect common vulnerabilities 
in JSON Web Tokens (JWT). It identifies weak configurations, insecure algorithms, 
weak secrets, and attempts re-signing the token if possible.

## Features
- Decode JWT without verification
- Detect `alg=none` and weak algorithms
- Brute-force weak HMAC secrets
- Generate a forged JWT if exploitable
- Produce a full report (jwt_report.json)

## Requirements
- Python 3.8+
- Install PyJWT:

pip install pyjwt

## Usage

python jwt_scanner.py --token <JWT_TOKEN> --wordlist wordlist.txt

## Example

python jwt_scanner.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --wordlist wordlist.txt


## Output
• Decoded payload  
• Algorithm details  
• Header issues  
• Result of brute-force attempts  
• Re-signed token (if applicable)  
• A report saved to jwt_report.json

## Technical Overview

The tool operates through several stages:

(1) Load Wordlist  
Reads and prepares a list of possible weak secrets.

(2) Decode JWT Without Verification  
The payload is extracted without verifying the signature.

(3) Analyze Header  
The tool checks for:
• HMAC algorithms  
• Use of "none" algorithm  
• Missing or weak protections  

(4) Brute-Force Weak Secret  
Applies every secret from the wordlist to decode the token:
jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])

If successful, the weak secret is identified.

(5) Re-sign Token  
If the algorithm uses HMAC and a weak secret is found, the tool re-signs the decoded payload using:
jwt.encode(decoded_payload, secret, algorithm="HS256")

(6) Report Generation  
The following information is saved into jwt_report.json:
• Original token  
• Algorithm  
• Detected issues  
• Decoded payload  
• Weak secret (if found)  
• Re-signed token  

## Example Output


Decoded payload:
{
    "user": "admin",
    "role": "admin",
    "iat": 1680000000
}

Algorithm: HS256  
Issues: ["hmac_algorithm"]  
Found secret: secret  
New forged token: eyJhbGciOiJIUzI1NiIs...  

## License

This project is licensed under the MIT License.  
See the LICENSE file for details.


## Author
Shaden Alsulami  - 2025
