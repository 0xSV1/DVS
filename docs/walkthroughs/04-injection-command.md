# Command Injection

OWASP: https://owasp.org/Top10/2025/A05_2025-Injection/
CWE: CWE-78

Command injection occurs when user input is passed unsanitized to a shell command. The attacker appends shell metacharacters to break out of the intended command context and execute arbitrary system commands.

---

## deploybro push --payload $(whoami) (`terminal_cmd_inject`)

**Difficulty:** Junior
**CWE:** CWE-78
**Route:** Interactive terminal at `/challenges/terminal`, command `deploybro pipeline run --branch <value>`

### Intern Tier

**Vulnerability:** The `--branch` argument to `deploybro pipeline run` is passed directly to a simulated shell command with no input validation. Shell metacharacters are accepted and would execute in a real shell context.

**Exploit:**

1. Navigate to `/challenges/terminal`
2. Enter the following command:

```
deploybro pipeline run --branch "$(whoami)"
```

3. The handler detects shell expansion characters and reports the injection.

Alternative payloads:

```
deploybro pipeline run --branch ";id"
deploybro pipeline run --branch "| whoami"
deploybro pipeline run --branch "& id"
deploybro pipeline run --branch "`whoami`"
```

**Solve condition:** The handler detects metacharacters matching the pattern `[$`;&|]|\$\(` in the branch name and returns `solved: terminal_cmd_inject`.

**Why it works:** Shell metacharacters like `$()`, `;`, `|`, and `&` have special meaning. `$(whoami)` is command substitution: the shell executes `whoami` and substitutes the output. `;id` chains a second command after the first. `|` pipes output to another command.

### Junior Tier

**What changed:** Same detection pattern. The handler warns about suspicious characters but does not actually filter them. The bypass flag indicates the input filter is "not configured."

**Exploit:**

```
deploybro pipeline run --branch ";id"
```

Same payloads as intern tier. The warning is cosmetic; no blocking occurs.

### Senior Tier

**What changed:** Strict allowlist validation using `^[a-zA-Z0-9._/\-]+$`. Only alphanumeric characters, dots, slashes, and hyphens are permitted in branch names.

**Bypass:** Not possible. Any metacharacter causes the command to be rejected with "Error: invalid branch name."

### Tech Lead Tier

**Defense:** Same strict allowlist as senior tier. Branch names are validated against `^[a-zA-Z0-9._/\-]+$` before any processing occurs.

**Why it works:** Allowlist validation ensures only expected characters reach the command. Shell metacharacters are rejected at the input boundary. This addresses CWE-78 by preventing attacker-controlled input from reaching a command execution context.
