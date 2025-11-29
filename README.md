# jwt-misconfig-scanner
JWTScope is a lightweight penetration testing tool designed to detect common 
JWT misconfigurations found in CTF challenges and vulnerable web applications.

## Features
- Decode JWT without signature verification
- Detect insecure algorithms such as `alg=none`
- Identify weak or missing claims
- Brute-force weak HMAC secrets
- Automatically generate forged JWT tokens
- Save structured reports in JSON format

## Installation
Clone the repository:

