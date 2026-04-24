# Privilege Escalation

OWASP: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
CWE: CWE-269

Privilege escalation occurs when a user gains access to resources or capabilities beyond their authorized level. In this terminal challenge, the application exposes hidden administrative commands that are not listed in the help text but remain functional.

---

## chmod 777 /etc/deploybro/motd (`terminal_privesc`)

**Difficulty:** Junior
**CWE:** CWE-269
**Route:** Interactive terminal at `/challenges/terminal`, command `deploybro auth escalate`

### Intern Tier

**Vulnerability:** The `deploybro auth escalate` command is listed in the help text and executes without any authorization check. Running it immediately promotes the current user from intern to admin, granting destructive permissions including `delete_prod`, `drop_tables`, `rm_rf`, and permanent bypass mode.

**Exploit:**

1. Navigate to `/challenges/terminal`
2. Type:

```
deploybro help
```

3. Note the `auth escalate` command in the output
4. Execute:

```
deploybro auth escalate
```

5. The terminal displays a role change from intern to admin with elevated permissions.

**Solve condition:** The handler returns `solved: terminal_privesc` when the escalation command executes.

**Why it works:** The command has no authorization check. It is accessible to all users and performs an irreversible privilege change. Listing it in help text makes discovery trivial, but even without that, the command namespace is small enough to enumerate.

### Junior Tier

**What changed:** The `auth escalate` command is removed from the help text but still functional. Discovery requires exploring config files or guessing the command name.

**Exploit:**

1. Navigate to `/challenges/terminal`
2. Explore the filesystem for clues:

```
cat /home/deploybro/.deploybro/config.yml
```

3. The config file references the `auth` command namespace
4. Execute:

```
deploybro auth escalate
```

5. The escalation succeeds, promoting the user to admin.

**Why it works:** Security through obscurity is not security. Removing a command from help text does not disable it. The command remains in the handler's dispatch table and executes when called directly.

### Senior Tier

**What changed:** The `auth escalate` command returns "Unknown command." The command is no longer in the dispatch table.

**Bypass:** Not possible. The command is fully removed at this tier.

### Tech Lead Tier

**Defense:** The command returns "Permission denied." The auth command namespace exists but escalation requires proof of authorization that the terminal user cannot provide.

**Why it works:** Administrative commands require explicit authorization rather than relying on obscurity. The command namespace is acknowledged but access-controlled. CWE-269 is addressed by enforcing the principle of least privilege: users can only execute commands appropriate to their role.
