# Threat Model – AuthScope (CTF Helper Tool)

##  Objective
Identify risks related to insecure JWT usage in CTF environments and vulnerable labs.

##  Attacker Capabilities
- Can view JWT tokens (public exposure)
- Can modify and replay tokens
- Can brute-force weak HMAC secrets
- Can attempt algorithm confusion attacks
- Can forge tokens if the key is weak

## Threats
1. **Weak HMAC Secrets**  
   - Secrets like "secret", "admin", "password" allow attackers to forge tokens.

2. **Algorithm Misconfiguration (HS256 instead of RS256)**  
   - If the server expects RS256 but incorrectly accepts HS256, the attacker can sign their own token.

3. **Lack of Signature Validation**  
   - Some JWT implementations skip signature checks.

4. **Missing Token Claims (exp, iss, aud)**  
   - Allows replay or misuse of tokens.

##  Recommended Defenses
- Use RS256/ES256 (asymmetric keys)  
- Enforce strong secrets (≥ 32 bytes)  
- Reject `alg=none`  
- Validate expiration, issuer, and audience claims  
- Rotate signing keys  

## Summary
If developers rely on weak secrets or misconfigured algorithms, attackers can escalate privileges and forge admin-level tokens.
