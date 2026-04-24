# Server-Side Template Injection

OWASP: https://owasp.org/Top10/2025/A05_2025-Injection/
CWE: CWE-1336

Server-side template injection (SSTI) occurs when user input is embedded into a template engine's source code rather than passed as data. In Jinja2, this means user input is compiled as part of the template string, allowing expression evaluation and, in severe cases, remote code execution through Python's object model.

---

## Template Literals Gone Wrong (`ssti_basic`)

**Difficulty:** Junior
**CWE:** CWE-1336
**Route:** `GET /challenges/ssti?name=<payload>`

### Intern Tier

**Vulnerability:** User input is concatenated directly into a Jinja2 template string and compiled with `Template.from_string()`. No sandbox, no filtering.

```python
Template("Hello " + user_input + "! Welcome to DeployBro.").render()
```

**Exploit:**

1. Navigate to `/challenges/ssti`
2. Enter the following name:

```
{{7*7}}
```

3. The page renders: `Hello 49! Welcome to DeployBro.`

The template engine evaluates `{{7*7}}` as a Jinja2 expression, producing `49` instead of the literal string.

**Solve condition:** The challenge solves when the input contains `7*7` and the output contains `49`.

**Why it works:** Jinja2's `{{ }}` syntax evaluates Python expressions. When user input is part of the template source (not a variable passed to `render()`), the engine processes attacker-controlled expressions.

### Junior Tier

**What changed:** A blacklist blocks keywords: `__class__`, `__mro__`, `__subclasses__`, `config`, `import`, `os.`, `subprocess`, `popen`. However, basic expressions like `{{7*7}}` are not blocked.

**Exploit:**

```
{{7*7}}
```

Same payload as intern. The blacklist targets RCE patterns, not arithmetic expressions.

### Senior Tier

**What changed:** Jinja2 `SandboxedEnvironment` is used. The sandbox restricts attribute access to dangerous objects and prevents evaluation of arbitrary expressions.

**Bypass:** Not possible for this challenge. The sandbox prevents arithmetic evaluation in template expressions.

### Tech Lead Tier

**Defense:** User input is HTML-escaped with `html.escape()` and inserted into a fixed string using Python's `.format()` method. The input is never compiled as part of a Jinja2 template.

```python
safe = html.escape(user_input)
output = "Hello {}! Welcome to DeployBro.".format(safe)
```

**Why it works:** The user input is treated as data, not template code. No template compilation occurs on user-controlled strings. HTML escaping prevents any secondary injection. This addresses CWE-1336 by separating code from data.

---

## eval() Your Way to CTO (`ssti_rce`)

**Difficulty:** Senior
**CWE:** CWE-1336
**Route:** `GET /challenges/ssti?name=<payload>`

### Intern Tier

**Vulnerability:** Same raw `Template.from_string()` as the basic challenge, but now the goal is remote code execution through Python's object model.

**Exploit:**

1. Navigate to `/challenges/ssti`
2. Enter the following payload:

```
{{''.__class__.__mro__[1].__subclasses__()}}
```

3. This traverses from an empty string to the base `object` class, then lists all loaded Python subclasses. From there, find a class that provides file or command access.

Full RCE payload:

```
{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```

Where `X` is the index of `subprocess.Popen` in the subclasses list (varies by Python version).

**Solve condition:** The challenge solves when the input contains any of: `__class__`, `__subclasses__`, `__globals__`, `__builtins__`, `popen`.

**Why it works:** Python's object model allows traversing from any object to any loaded class via `__class__.__mro__.__subclasses__()`. This is a well-known Jinja2 SSTI exploitation technique that reaches `subprocess.Popen` or `os.system` without importing modules.

### Junior Tier

**What changed:** Blacklist blocks `__class__`, `__mro__`, `__subclasses__`, `config`, `import`, `os.`, `subprocess`, `popen`.

**Bypass:** Use Jinja2's `|attr()` filter to access attributes by string, bypassing keyword detection:

```
{{''|attr('__class__')|attr('__mro__')}}
```

Alternative: `__globals__` is not in the blacklist:

```
{{request.application.__globals__}}
```

### Senior Tier

**What changed:** Jinja2 `SandboxedEnvironment` blocks access to dangerous attributes and methods. The sandbox prevents traversal of `__class__`, `__mro__`, `__subclasses__`, and similar dunder attributes.

**Bypass:** Not possible. The sandbox is correctly configured and prevents RCE.

### Tech Lead Tier

**Defense:** Same as the basic challenge: HTML escaping with no template compilation on user input. Dunder attributes in the input are rendered as literal text.

**Why it works:** Without template compilation, Python object traversal expressions are inert strings. CWE-1336 is fully mitigated.
