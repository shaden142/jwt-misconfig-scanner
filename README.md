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

python jwt_scanner.py --token <JWT>

## Example

python jwt_scanner.py --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

## Output
- Decoded payload
- Algorithm and header weaknesses
- Weak secret (if found)
- Forged token
- Report saved to jwt_report.json

## Author
Shaden Alsulami  - 2025
