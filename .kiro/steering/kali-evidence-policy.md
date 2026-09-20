# Kali MCP Security Testing Evidence Policy

**Inclusion**: auto  
**Name**: Evidence Policy for Security Tests  
**Description**: Enforces proof-based classification of security findings, preventing false positives

---

## Core Rule: OBSERVATION ≠ CONFIRMATION ≠ EXPLOITATION

Never assume:
- **Scanner signal** = **confirmed vulnerability**
- **Candidate technology** = **confirmed exploitation**
- **Different response size** = **vulnerability proof**

---

## Maturity Levels

```
NOT_TESTED
    ↓
TESTED (tool ran, found nothing)
    ↓
OBSERVED (signal detected, needs validation)
    ↓
SUSPECTED (consistent with vulnerability pattern)
    ↓
CONFIRMED (direct evidence present in tool output)
    ↓
EXPLOITED (successful exploitation demonstrated)
```

---

## What DOES NOT Count as Proof

| Finding Type | ❌ INSUFFICIENT | ✅ SUFFICIENT |
|---|---|---|
| **SSRF** | Response size differs; HTTP 200 received | Metadata markers (ami-id, instance-id) in response body |
| **SSTI** | Engine detected (heuristic); payload sent | Expression result (49 from {{7*7}}) in response |
| **IDOR** | 1-2 byte size difference; 404 vs 404 | Different JSON user data in responses with 20%+ size difference |
| **TLS Weak** | Key size 256; ECDSA detected | RSA < 2048 bits; or ECDSA P-192 (< P-224) |
| **Missing Headers** | Headers absent on HTTP port 80 | Headers absent on HTTPS production URL |
| **Cookies Insecure** | HttpOnly flag missing on XSRF-TOKEN | Session token accessible via XSS with proof |
| **XSS** | Payload reflected in HTML; quotes escaped | Unescaped payload executes (alert(1) fires) |
| **SQLi** | Sqlmap ran; "no injectable found" in output | Actual SQL error or time-based confirmation |

---

## Forbidden Actions

🚫 **NEVER invent**:
- Credentials that weren't extracted
- File contents that weren't read
- Command execution that wasn't performed
- User data that wasn't accessed
- Session takeover that wasn't demonstrated
- Cloud metadata that wasn't retrieved
- AWS credentials that weren't obtained

🚫 **NEVER promote**:
- "Response - investigate" to "confirmed vulnerability"
- Engine detection to exploitation
- Anomaly to breach
- Signal to confirmed risk

🚫 **NEVER suppress**:
- Limitations of the testing
- Unconfirmed hypotheses
- Alternative explanations
- Tools that returned zero findings (Nuclei, Nikto, etc.)

---

## Reporting Standards

### Before Writing a Report

Build this matrix:

| Finding | Tool Says | Evidence Present? | Status | Can Report? |
|---|---|---|---|---|
| SSRF | Response 410 | No metadata markers | OBSERVED | ❌ |
| SSTI | Engine: ERB | No "49" output | SUSPECTED | ❌ |
| IDOR | Size diff 2B | No data access | OBSERVED | ❌ |
| TLS | Key 256b | ECDSA P-256 (secure) | REVIEW | ❌ |
| Headers | Missing HSTS | On HTTP:80 (expected) | REVIEW | ❌ |

**Report only findings with status CONFIRMED or EXPLOITED.**

### Report Language

Use:

- ✅ "We observed signals consistent with SSRF but could not confirm it"
- ✅ "The template engine type is unknown; no expression evaluation detected"
- ✅ "Response differences detected but semantic content unchanged"
- ❌ "SSRF confirmed" (if not)
- ❌ "RCE exploited via SSTI" (if no payload output)
- ❌ "User database accessed via IDOR" (if no data extracted)

---

## Tool Output Expectations

Each MCP Kali tool **must** return:

```json
{
  "status": "OBSERVED|SUSPECTED|CONFIRMED|EXPLOITED",
  "confidence": 0.0-1.0,
  "evidence": {
    "observed": "what the tool actually detected",
    "baseline": "what we compared against",
    "result": "what changed"
  },
  "limitations": [
    "reason this alone is not sufficient proof",
    "validation step recommended"
  ]
}
```

**Findings WITHOUT clear evidence MUST have status "OBSERVED" or "SUSPECTED".**

---

## Decision Tree for Agent

When you receive a tool output:

```
1. Is `status` field present?
   YES → Use it as ground truth
   NO  → Default to OBSERVED
   
2. Is `confidence` >= 0.8?
   YES → Evidence is strong
   NO  → Mark UNCONFIRMED, list limitations
   
3. Are `limitations` documented?
   YES → Acknowledge them in your analysis
   NO  → Add your own limitations

4. Can you reproduce the finding manually?
   YES → Promote to CONFIRMED if reproduction succeeds
   NO  → Stay at OBSERVED, recommend manual testing
   
5. Did you exploit it end-to-end?
   YES → Mark EXPLOITED, document impact
   NO  → Do not claim exploitation
```

---

## Examples

### ✅ CORRECT REASONING

**Input**: SSRF tool returns `status=OBSERVED, confidence=0.1, limitations=[...]`

**Output**: "The target may be vulnerable to SSRF, but we only observed different response sizes. Without direct metadata markers (ami-id, instance-type, etc.), we cannot confirm SSRF. Manual testing with cloud metadata endpoints is required."

### ❌ INCORRECT REASONING

**Input**: Same tool

**Output**: "SSRF confirmed. The server makes outbound requests to AWS metadata endpoints. Attackers can extract credentials."

(No metadata markers in evidence, but agent promoted OBSERVED to confirmed.)

---

## Enforcement

This policy is **mandatory** before:
- ✅ Generating reports
- ✅ Claiming exploitation
- ✅ Recommending fixes
- ✅ Scoring vulnerability severity

If you cannot point to **direct evidence in tool output**, the finding remains **UNCONFIRMED**.

---

**End of Policy**
