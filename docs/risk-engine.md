# Transparent Risk Scoring Engine

## 1. Finding Platform Risk Score (0 - 100)

VulnForge clearly distinguishes between the theoretical industry CVSS score (0.0 - 10.0) and the contextualized **Platform Risk Score** (0 - 100).

### Calculation Factors
1. **Base Severity Weight**:
   - `Critical`: 85.0
   - `High`: 65.0
   - `Medium`: 40.0
   - `Low`: 15.0
   - `Informational`: 0.0

2. **CVSS Contribution**: Up to +15.0 points based on `(CVSS / 10.0) * 15.0`.

3. **Asset Criticality Multiplier**:
   - `Critical (Tier 1)`: x1.25
   - `High`: x1.10
   - `Medium`: x1.00
   - `Low`: x0.80

4. **Environment Multiplier**:
   - `Production / External`: x1.20
   - `Staging`: x0.95
   - `Development`: x0.80
   - `Internal`: x0.85

5. **Confidence Weight**:
   - `Confirmed`: 1.00
   - `High`: 0.95
   - `Medium`: 0.80
   - `Low`: 0.60
   - `Potential`: 0.40

---

## 2. Overall Project Security Score (0 - 100)

The Security Posture Score starts at **100.0** (flawless posture) and applies penalties for active unresolved findings:
- **Critical Finding**: -20.0 pts
- **High Finding**: -10.0 pts
- **Medium Finding**: -4.0 pts
- **Low Finding**: -1.0 pt

As findings transition to `RESOLVED` or `VERIFIED`, the score dynamically recovers.
