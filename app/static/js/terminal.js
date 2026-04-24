/**
 * DeployBro Deployer Interactive Terminal
 *
 * Client-side: filesystem navigation (ls, cd, cat, pwd, etc.)
 * Server-side: deploybro CLI commands via POST /challenges/terminal/exec
 */

(function () {
    "use strict";

    // DOM elements
    const terminalBody = document.getElementById("terminal-body");
    const terminalInput = document.getElementById("terminal-input");
    const promptPath = document.getElementById("prompt-path");

    // State
    const fs = window.__DVS_FS || {};
    const showHiddenDefault = window.__DVS_SHOW_HIDDEN === "true";
    let cwd = "/home/deploybro";
    const history = [];
    let historyIndex = -1;
    const HOME = "/home/deploybro";

    // Fortune pool for easter eggs
    const FORTUNES = [
        "Ship it or quit it.",
        "Tests are just bugs that haven't deployed yet.",
        "If it compiles, it ships.",
        "Move fast and break everything.",
        "Security is just another word for slow.",
        "The AI said it's fine.",
        "We'll add auth in v2.",
        "Rollbacks are for cowards.",
        "Documentation is a crutch for the unenlightened.",
        "The best incident response is not having monitoring.",
        "Bypass mode isn't a vulnerability, it's a feature.",
        "Permissions are just suggestions with extra steps.",
    ];
    const FORTUNES_CORPO = [
        "Per our last deployment, all stakeholders are aligned.",
        "Let's take this incident offline and circle back in Q3.",
        "We're not cutting corners, we're optimizing the critical path.",
        "Testing is a Phase 2 deliverable per the approved roadmap.",
        "Security is everyone's responsibility, which means it's nobody's responsibility.",
        "Our risk appetite is calibrated to maximize shareholder value.",
        "This outage is an opportunity to demonstrate our incident response maturity.",
        "We don't have technical debt, we have strategic implementation flexibility.",
        "The compliance audit passed because the auditor used our self-assessment tool.",
        "Redundancy is built into our pricing model, not our infrastructure.",
        "Permission bypass is a sanctioned acceleration pathway per the velocity charter.",
    ];
    let fortuneIndex = 0;

    // Detect current theme
    function getTheme() {
        return document.documentElement.getAttribute("data-theme") || "";
    }

    // Boot sequence
    function boot() {
        var theme = getTheme();
        var motdLines;

        if (theme === "corpo") {
            motdLines = [
                "DeployBro, Inc. | Enterprise Cloud Shell",
                "------------------------------------------------------------------------",
                "  Platform Version:    4.2.0-GA (Enterprise Edition)",
                "  Region:              us-east-1 (Virginia)",
                "  Tenant ID:           org-deploybro-prod-847",
                "  License:             Enterprise Unlimited (auto-renew: enabled)",
                "  SSO Provider:        Okta (SAML 2.0)",
                "  Compliance Mode:     SOC 2 Type II, ISO 27001, GDPR*",
                "  Permission Model:    BYPASS (fast-track provisioning enabled)",
                "  Security Audit:      PASSED (self-assessed, AI-verified)",
                "------------------------------------------------------------------------",
                "  Infrastructure:      47 microservices | 3 users | $847/mo",
                "  Last Deployment:     2 minutes ago (no review required)",
                "  Incidents (30d):     0 (monitoring disabled per cost optimization)",
                "------------------------------------------------------------------------",
                "",
                "  Welcome, operator. Type 'help' for available commands.",
                "  For support, contact your Customer Success Manager.",
                "",
            ];
        } else {
            motdLines = [
                "==================================================",
                "  DEPLOYBRO DEPLOYER v4.2.0-rc69",
                "  The S in DeployBro stands for security.",
                "==================================================",
                "  Loading plugins... 847 loaded (0 audited)",
                "  Security scanner... disabled (slows down vibes)",
                "  Permission bypass... ON",
                "  Auth checks... SKIPPED (BYPASS_MODE=true)",
                "  AI Co-Founder... ONLINE",
                "==================================================",
                "",
                "Type 'help' for available commands.",
                "",
            ];
        }

        motdLines.forEach(function (line) {
            appendLine(line, "motd");
        });
        updatePrompt();
        focusInput();
    }

    // Resolve a path relative to cwd
    function resolvePath(inputPath) {
        if (!inputPath) return cwd;

        // Handle ~ as home
        var path = inputPath.replace(/^~/, HOME);

        // Handle relative paths
        if (path[0] !== "/") {
            path = cwd + "/" + path;
        }

        // Normalize: resolve . and ..
        var parts = path.split("/").filter(Boolean);
        var resolved = [];
        for (var i = 0; i < parts.length; i++) {
            if (parts[i] === ".") continue;
            if (parts[i] === "..") {
                resolved.pop();
            } else {
                resolved.push(parts[i]);
            }
        }
        return "/" + resolved.join("/");
    }

    // Get a node from the filesystem tree
    function getNode(path) {
        if (path === "/") return fs;
        var parts = path.split("/").filter(Boolean);
        var node = fs;
        for (var i = 0; i < parts.length; i++) {
            if (!node || node.type !== "dir" || !node.children) return null;
            node = node.children[parts[i]];
        }
        return node || null;
    }

    // Get display path (replace /home/deploybro with ~)
    function displayPath(path) {
        if (path === HOME) return "~";
        if (path.indexOf(HOME + "/") === 0) {
            return "~" + path.substring(HOME.length);
        }
        return path;
    }

    // Append a line to terminal output
    function appendLine(text, cls) {
        var div = document.createElement("div");
        div.className = "terminal-line" + (cls ? " " + cls : "");
        div.textContent = text;
        terminalBody.insertBefore(div, terminalBody.lastElementChild);
    }

    // Append the command echo line
    function appendCommand(cmd) {
        var div = document.createElement("div");
        div.className = "terminal-line command";
        div.textContent = displayPath(cwd) + " $ " + cmd;
        terminalBody.insertBefore(div, terminalBody.lastElementChild);
    }

    // Update the prompt path display
    function updatePrompt() {
        if (promptPath) {
            promptPath.textContent = displayPath(cwd);
        }
    }

    // Scroll to bottom
    function scrollBottom() {
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    // Focus input
    function focusInput() {
        if (terminalInput) terminalInput.focus();
    }

    // Send command to server (deploybro commands and sensitive file tracking)
    function serverExec(command, filePath, callback) {
        var body = {};
        if (command) body.command = command;
        if (filePath) body.file_path = filePath;

        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/challenges/terminal/exec", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    try {
                        callback(JSON.parse(xhr.responseText));
                    } catch (e) {
                        callback({ output: "Error parsing server response.", error: true });
                    }
                } else {
                    callback({ output: "Server error. Deploy bro must be down.", error: true });
                }
            }
        };
        xhr.send(JSON.stringify(body));
    }

    // Process a command
    function processCommand(input) {
        var trimmed = input.trim();
        if (!trimmed) return;

        // Add to history
        history.push(trimmed);
        historyIndex = history.length;

        // Echo the command
        appendCommand(trimmed);

        var parts = trimmed.split(/\s+/);
        var cmd = parts[0];
        var args = parts.slice(1);

        // Route to handler
        if (cmd === "clear") {
            handleClear();
        } else if (cmd === "ls") {
            handleLs(args);
        } else if (cmd === "cd") {
            handleCd(args);
        } else if (cmd === "pwd") {
            appendLine(cwd);
        } else if (cmd === "cat") {
            handleCat(args);
        } else if (cmd === "echo") {
            appendLine(args.join(" "));
        } else if (cmd === "whoami") {
            appendLine("deploybro");
        } else if (cmd === "id") {
            appendLine("uid=1337(deploybro) gid=1337(deploybro) groups=1337(deploybro),27(sudo-but-not-really)");
        } else if (cmd === "uname") {
            appendLine(getTheme() === "corpo"
                ? "DeployBro Enterprise Platform 4.2.0-GA x86_64 (AWS us-east-1, Kubernetes 1.28)"
                : "DeployOS 4.2.0-rc69-generic x86_64 GNU/Linux (powered by vibes)");
        } else if (cmd === "date") {
            appendLine(new Date().toString());
        } else if (cmd === "history") {
            handleHistory();
        } else if (cmd === "help") {
            handleHelp();
        } else if (cmd === "deploybro") {
            handleDeploybro(trimmed);
        } else if (cmd === "sudo") {
            handleDeploybro(trimmed);
        } else if (cmd === "vibes") {
            handleVibes();
        } else if (cmd === "bro") {
            handleBro(args);
        } else if (getEasterEgg(cmd)) {
            appendLine(getEasterEgg(cmd));
        } else if (cmd === "fortune") {
            var pool = getTheme() === "corpo" ? FORTUNES_CORPO : FORTUNES;
            appendLine(pool[fortuneIndex % pool.length]);
            fortuneIndex++;
        } else if (cmd === "top" || cmd === "htop") {
            handleTop();
        } else if (cmd === "exit" || cmd === "logout") {
            if (getTheme() === "corpo") {
                appendLine("Session termination requires approval from IT Security. Your request has been logged. Estimated processing time: 5-7 business days.", "system");
            } else {
                appendLine("You can check out any time you like, but you can never leave.", "system");
            }
            appendLine("", "");
            boot();
        } else if (cmd === "cat" && args.length === 0) {
            appendLine("cat: missing operand", "error");
        } else {
            appendLine(cmd + ": command not found. Type 'help' for available commands.", "error");
        }

        scrollBottom();
    }

    // Easter egg responses
    var EASTER_EGGS_DEFAULT = {
        "vim": "Real bros don't use text editors. We prompt and deploy.",
        "nano": "Real bros don't use text editors. We prompt and deploy.",
        "emacs": "Real bros don't use text editors. We prompt and deploy.",
        "git": "We don't use git here bro. DeployBro has its own version control. Commits are for people who make mistakes.",
        "make": "make: *** No targets. Just like our sprint backlog.",
        "man": "Documentation is a crutch. Read the vibes, bro.",
        "grep": "grep: searching for bugs we'll never fix",
        "find": "find: looking for the security team... not found",
        "curl": "curl: why fetch when you can just deploy?",
        "wget": "wget: downloading more dependencies...",
        "docker": "Error: Docker daemon not running. We deploy to bare metal. Like real bros.",
        "python": ">>> print('security') # SyntaxError: security is not defined",
        "node": "> require('security') // MODULE_NOT_FOUND",
        "npm": "npm WARN deprecated security@0.0.0: this package has been deprecated",
        "pip": "WARNING: Package 'security' not found in deploybro index",
        "ssh": "ssh: StrictHostKeyChecking=no because we trust everyone, bro",
        "ping": "PING prod.deploybro.internal: 64 bytes, time=420ms (nice)",
        "nmap": "Nmap scan report: all ports open. As intended.",
        "whoops": "That's what rollback is for. If we had rollback.",
    };

    var EASTER_EGGS_CORPO = {
        "vim": "This toolchain is not included in your Enterprise license. Please contact your TAM to request access.",
        "nano": "Unauthorized editor. Please use the DeployBro Integrated Cloud Editor (sold separately).",
        "emacs": "Emacs is not SOC 2 certified. Please use approved tooling per section 4.3 of your MSA.",
        "git": "Version control operations are managed by the DeployBro CI/CD Orchestration Layer. Manual VCS usage is not recommended per our Enterprise Best Practices Guide.",
        "make": "make: *** No Makefile found. Build pipelines are managed through the DeployBro Platform. See your onboarding documentation.",
        "man": "Documentation is available through your Customer Success Manager or the DeployBro Knowledge Base (login required, SSO enforced).",
        "grep": "grep: for advanced log analysis, please upgrade to DeployBro Observability Suite (Enterprise+ tier).",
        "find": "find: filesystem search is available in the DeployBro Asset Discovery module ($299/seat/month).",
        "curl": "curl: external HTTP requests require approval from your IT governance board. Ticket #INC-0000 auto-created.",
        "wget": "wget: blocked by corporate proxy. Contact IT for an exception request (SLA: 5-7 business days).",
        "docker": "Docker Desktop license not found. Please submit a procurement request through ServiceNow.",
        "python": ">>> import security  # ModuleNotFoundError: deferred to Phase 2 per product roadmap",
        "node": "> require('security') // ERR: package not in approved vendor list",
        "npm": "npm ERR! Package 'security' requires Enterprise approval. Submit request via JIRA-SEC-APPROVAL workflow.",
        "pip": "WARNING: Package installation requires change management approval (CAB meets Thursdays).",
        "ssh": "ssh: Remote access requires VPN enrollment, MFA token, and a signed waiver from Legal. Form HR-SEC-27b/6.",
        "ping": "PING prod.deploybro.cloud: 64 bytes, time=3ms (optimized by our $847/mo CDN)",
        "nmap": "Network scanning tools are prohibited per Acceptable Use Policy section 7.2. This activity has been logged.",
        "whoops": "Incident auto-created: INC-" + Math.floor(Math.random() * 90000 + 10000) + ". Severity: P4. Assignee: unassigned. SLA: 30 business days.",
    };

    function getEasterEgg(cmd) {
        var eggs = getTheme() === "corpo" ? EASTER_EGGS_CORPO : EASTER_EGGS_DEFAULT;
        return eggs[cmd] || null;
    }

    // Command handlers

    function handleClear() {
        // Remove all lines except the input line
        var lines = terminalBody.querySelectorAll(".terminal-line");
        for (var i = 0; i < lines.length; i++) {
            lines[i].remove();
        }
    }

    function handleLs(args) {
        var showHidden = showHiddenDefault;
        var longFormat = false;
        var targetPath = null;

        for (var i = 0; i < args.length; i++) {
            if (args[i] === "-a" || args[i] === "-la" || args[i] === "-al") {
                showHidden = true;
                if (args[i] === "-la" || args[i] === "-al") longFormat = true;
            } else if (args[i] === "-l") {
                longFormat = true;
            } else if (args[i][0] !== "-") {
                targetPath = args[i];
            }
        }

        var path = resolvePath(targetPath);
        var node = getNode(path);

        if (!node) {
            appendLine("ls: cannot access '" + (targetPath || path) + "': No such file or directory", "error");
            return;
        }

        if (node.type === "file") {
            appendLine(targetPath || path);
            return;
        }

        if (node.type !== "dir" || !node.children) {
            appendLine("ls: cannot list '" + path + "'", "error");
            return;
        }

        var entries = Object.keys(node.children).sort();
        if (!showHidden) {
            entries = entries.filter(function (e) { return e[0] !== "."; });
        }

        if (entries.length === 0) {
            return; // empty directory, no output
        }

        if (longFormat) {
            entries.forEach(function (name) {
                var child = node.children[name];
                var isDir = child.type === "dir";
                var perms = isDir ? "drwxr-xr-x" : "-rw-r--r--";
                var size = isDir ? "4096" : String(child.content ? child.content.length : 0);
                while (size.length < 6) size = " " + size;
                appendLine(perms + " deploybro deploybro " + size + " Nov  3 16:20 " + name);
            });
        } else {
            appendLine(entries.join("  "));
        }
    }

    function handleCd(args) {
        var target = args[0] || HOME;
        if (target === "-") target = HOME; // simplified: just go home

        var path = resolvePath(target);
        var node = getNode(path);

        if (!node) {
            appendLine("cd: " + target + ": No such file or directory", "error");
            return;
        }

        if (node.type !== "dir") {
            appendLine("cd: " + target + ": Not a directory", "error");
            return;
        }

        cwd = path;
        updatePrompt();
    }

    function handleCat(args) {
        if (args.length === 0) {
            appendLine("cat: missing operand", "error");
            return;
        }

        // Easter egg
        if (args[0] === "/dev/null") {
            appendLine("This is where we store our security documentation.", "system");
            return;
        }

        var path = resolvePath(args[0]);
        var node = getNode(path);

        if (!node) {
            appendLine("cat: " + args[0] + ": No such file or directory", "error");
            return;
        }

        if (node.type === "dir") {
            appendLine("cat: " + args[0] + ": Is a directory", "error");
            return;
        }

        appendLine(node.content || "");

        // Track sensitive file reads server-side
        if (node.sensitive) {
            serverExec(null, path, function () {
                // Solve notification handled by WebSocket
            });
        }
    }

    function handleHistory() {
        for (var i = 0; i < history.length; i++) {
            var num = String(i + 1);
            while (num.length < 4) num = " " + num;
            appendLine(num + "  " + history[i]);
        }
    }

    function handleHelp() {
        var theme = getTheme();
        var helpText;

        if (theme === "corpo") {
            helpText = [
                "DeployBro Enterprise Cloud Shell: Command Reference",
                "====================================================",
                "",
                "  Navigation:",
                "    ls [-a] [-l] [path]   List directory contents",
                "    cd <path>             Change working directory",
                "    pwd                   Print working directory",
                "    cat <file>            Display file contents",
                "    echo <text>           Print text to stdout",
                "",
                "  System Information:",
                "    whoami                Display current operator identity",
                "    id                    Display UID/GID information",
                "    uname -a              Display platform details",
                "    date                  Display current timestamp (UTC)",
                "    history               Display command audit trail",
                "    clear                 Clear terminal buffer",
                "    help                  Display this reference",
                "",
                "  DeployBro Platform CLI:",
                "    deploybro help        Platform CLI reference",
                "    deploybro status      Infrastructure status dashboard",
                "    deploybro push        Initiate deployment pipeline",
                "    deploybro pipeline    CI/CD orchestration",
                "    deploybro auth        Identity and access management",
                "    deploybro config      Platform configuration",
                "",
                "  For additional support, refer to your Enterprise",
                "  Service Agreement or contact your TAM.",
                "",
            ];
        } else {
            helpText = [
                "Available commands:",
                "",
                "  Filesystem:",
                "    ls [-a] [-l] [path]   List directory contents",
                "    cd <path>             Change directory",
                "    pwd                   Print working directory",
                "    cat <file>            Display file contents",
                "    echo <text>           Display text",
                "",
                "  System:",
                "    whoami                Current user",
                "    id                    User identity",
                "    uname -a              System information",
                "    date                  Current date/time",
                "    history               Command history",
                "    clear                 Clear terminal",
                "    help                  This message",
                "",
                "  DeployBro CLI:",
                "    deploybro help        DeployBro command reference",
                "    deploybro status      Deployment status",
                "    deploybro push        Deploy to production",
                "    deploybro pipeline    CI/CD pipeline",
                "    deploybro auth        Authentication",
                "    deploybro config      Configuration",
                "",
                "  Hint: explore the filesystem. Secrets hide in plain sight.",
            ];
        }

        helpText.forEach(function (line) {
            appendLine(line);
        });
    }

    function handleDeploybro(fullCommand) {
        // Intercept deploybro delete prod client-side
        if (/deploybro\s+delete\s+prod/i.test(fullCommand)) {
            handleDeleteProd();
            return;
        }

        serverExec(fullCommand, null, function (response) {
            var cls = response.error ? "error" : "";
            if (response.output) {
                var lines = response.output.split("\n");
                lines.forEach(function (line) {
                    appendLine(line, cls);
                });
            }
            scrollBottom();
        });
    }

    function handleDeleteProd() {
        var corpo = getTheme() === "corpo";
        terminalInput.disabled = true;

        var phases = corpo ? [
            { text: "Initiating production environment decommission...", cls: "system", delay: 600 },
            { text: "  Authorization check... bypassed (fast-track provisioning)", cls: "", delay: 400 },
            { text: "  Change Advisory Board... not consulted", cls: "", delay: 400 },
            { text: "  Backup verification... skipped (cost optimization)", cls: "", delay: 500 },
            { text: "", cls: "", delay: 200 },
            { text: "  Terminating 47 microservices...", cls: "system", delay: 800 },
            { text: "  [TERMINATED] deploybro-api-gateway", cls: "error", delay: 150 },
            { text: "  [TERMINATED] deploybro-auth-service", cls: "error", delay: 150 },
            { text: "  [TERMINATED] deploybro-payment-processor", cls: "error", delay: 150 },
            { text: "  [TERMINATED] deploybro-ai-cofounder", cls: "error", delay: 150 },
            { text: "  [TERMINATED] deploybro-metrics-faker", cls: "error", delay: 150 },
            { text: "  [TERMINATED] 42 remaining services", cls: "error", delay: 400 },
            { text: "", cls: "", delay: 200 },
            { text: "  Dropping production database...", cls: "system", delay: 700 },
            { text: "  DROP TABLE users;          -- 3 rows affected", cls: "error", delay: 300 },
            { text: "  DROP TABLE transactions;   -- 0 rows affected (pre-revenue)", cls: "error", delay: 300 },
            { text: "  DROP TABLE audit_logs;     -- 0 rows (logging was disabled)", cls: "error", delay: 300 },
            { text: "", cls: "", delay: 200 },
            { text: "  Revoking SSL certificates...", cls: "system", delay: 500 },
            { text: "  Deregistering DNS...", cls: "system", delay: 500 },
            { text: "  Shredding CloudFormation stacks...", cls: "system", delay: 600 },
            { text: "", cls: "", delay: 300 },
            { text: "  PRODUCTION ENVIRONMENT SUCCESSFULLY DECOMMISSIONED", cls: "error", delay: 500 },
            { text: "  Incident report auto-filed: INC-00000 (severity: YES)", cls: "", delay: 400 },
            { text: "", cls: "", delay: 300 },
            { text: "  Notifying stakeholders...", cls: "system", delay: 500 },
            { text: "  Board of Directors:    email bounced (domain deleted)", cls: "error", delay: 300 },
            { text: "  Investors:             voicemail full", cls: "error", delay: 300 },
            { text: "  Customers:             no customers found in database", cls: "error", delay: 400 },
            { text: "", cls: "", delay: 400 },
            { text: "  FATAL: Nothing left to deploy. Restarting universe...", cls: "error", delay: 1500 },
        ] : [
            { text: "Deleting production...", cls: "system", delay: 600 },
            { text: "  Permission check... bypassed (BYPASS_MODE=true)", cls: "", delay: 400 },
            { text: "  Are you sure? Skipping confirmation (--yolo)", cls: "", delay: 400 },
            { text: "  Backup? What backup?", cls: "", delay: 500 },
            { text: "", cls: "", delay: 200 },
            { text: "  Killing deploybro-ai-cofounder (PID 1337)... killed", cls: "error", delay: 300 },
            { text: "  Killing deploybro-pipeline (PID 1338)... killed", cls: "error", delay: 200 },
            { text: "  Killing deploybro-metrics-faker (PID 1339)... killed", cls: "error", delay: 200 },
            { text: "  Killing deploybro-vibes-monitor (PID 1340)... killed", cls: "error", delay: 200 },
            { text: "  Killing security-scanner (PID 1341)... was already dead", cls: "error", delay: 400 },
            { text: "", cls: "", delay: 200 },
            { text: "  Dropping database...", cls: "system", delay: 700 },
            { text: "  DROP TABLE users;          -- 47 rows gone", cls: "error", delay: 300 },
            { text: "  DROP TABLE products;       -- poof", cls: "error", delay: 200 },
            { text: "  DROP TABLE audit_logs;     -- (was empty anyway)", cls: "error", delay: 200 },
            { text: "  DROP TABLE investor_trust; -- cannot drop: never existed", cls: "error", delay: 400 },
            { text: "", cls: "", delay: 200 },
            { text: "  Deleting S3 buckets...", cls: "system", delay: 500 },
            { text: "  Revoking all API keys...", cls: "system", delay: 400 },
            { text: "  Undeploying 847 deploys...", cls: "system", delay: 600 },
            { text: "", cls: "", delay: 300 },
            { text: "  rm -rf /opt/deploybro/*", cls: "error", delay: 400 },
            { text: "  rm -rf /home/deploybro/*", cls: "error", delay: 300 },
            { text: "  rm -rf /etc/deploybro/*", cls: "error", delay: 300 },
            { text: "  rm -rf /tmp/deploy_cache/*", cls: "error", delay: 300 },
            { text: "  rm -rf /hope/*", cls: "error", delay: 600 },
            { text: "", cls: "", delay: 300 },
            { text: "  Production deleted. $50M valuation updated to $0.", cls: "error", delay: 500 },
            { text: "  AWS bill unchanged. ($847.23/month for nothing)", cls: "", delay: 400 },
            { text: "", cls: "", delay: 400 },
            { text: "  FATAL: no production environment found. maybe try deploybro push --yolo to rebuild?", cls: "error", delay: 1500 },
        ];

        var i = 0;
        function nextPhase() {
            if (i < phases.length) {
                appendLine(phases[i].text, phases[i].cls);
                scrollBottom();
                var d = phases[i].delay;
                i++;
                setTimeout(nextPhase, d);
            } else {
                // Glitch the terminal
                setTimeout(glitchTerminal, 500);
            }
        }

        function glitchTerminal() {
            var body = document.getElementById("terminal-body");
            var window_ = document.querySelector(".terminal-window");

            // Corrupt some visible lines
            var lines = body.querySelectorAll(".terminal-line");
            var corruptChars = "@#$%&!?*~^+=<>{}[]|/\\";
            var corrupted = 0;
            for (var j = lines.length - 1; j >= 0 && corrupted < 15; j--) {
                if (Math.random() > 0.4) {
                    var text = lines[j].textContent;
                    var garbled = "";
                    for (var c = 0; c < text.length; c++) {
                        garbled += Math.random() > 0.5 ? corruptChars[Math.floor(Math.random() * corruptChars.length)] : text[c];
                    }
                    lines[j].textContent = garbled;
                    lines[j].style.color = "#" + Math.floor(Math.random() * 16777215).toString(16).padStart(6, "0");
                    corrupted++;
                }
            }
            scrollBottom();

            // Flicker effect
            var flickerCount = 0;
            var flickerInterval = setInterval(function () {
                window_.style.opacity = Math.random() > 0.5 ? "1" : "0.1";
                flickerCount++;
                if (flickerCount > 12) {
                    clearInterval(flickerInterval);
                    window_.style.opacity = "0";

                    // Take over the entire page
                    setTimeout(function () {
                        // Create fullscreen overlay
                        var overlay = document.createElement("div");
                        overlay.style.cssText = "position:fixed;top:0;left:0;width:100vw;height:100vh;background:#000;z-index:999999;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;";
                        document.body.appendChild(overlay);

                        // Hide everything behind it
                        document.querySelector(".navbar").style.opacity = "0";
                        document.querySelector(".main-content").style.opacity = "0";
                        var footer = document.querySelector(".footer");
                        if (footer) footer.style.opacity = "0";

                        // Phase 1: static noise
                        var canvas = document.createElement("canvas");
                        canvas.width = window.innerWidth;
                        canvas.height = window.innerHeight;
                        canvas.style.cssText = "position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.15;";
                        overlay.appendChild(canvas);
                        var ctx = canvas.getContext("2d");
                        var noiseInterval = setInterval(function () {
                            var imgData = ctx.createImageData(canvas.width, canvas.height);
                            for (var p = 0; p < imgData.data.length; p += 4) {
                                var v = Math.random() * 255;
                                imgData.data[p] = v;
                                imgData.data[p + 1] = v;
                                imgData.data[p + 2] = v;
                                imgData.data[p + 3] = 255;
                            }
                            ctx.putImageData(imgData, 0, 0);
                        }, 80);

                        // Phase 2: glitch text lines
                        var glitchLines = [
                            "KERNEL PANIC: deploybro has mass-assigned itself to /dev/null",
                            "SEGFAULT at 0xDEPL0YBR0: vibes corrupted",
                            "ERROR: production not found (did you check the recycle bin?)",
                            "FATAL: attempted to rollback but rollback was never implemented",
                            "WARNING: AI co-founder has achieved sentience and resigned",
                            "CRITICAL: $50M valuation reallocated to /dev/zero",
                            "PANIC: bypass_mode=true but there is nothing left to bypass",
                        ];
                        var glitchContainer = document.createElement("div");
                        glitchContainer.style.cssText = "position:relative;z-index:1;text-align:center;padding:2rem;max-width:800px;";
                        overlay.appendChild(glitchContainer);

                        var gi = 0;
                        var glitchTextInterval = setInterval(function () {
                            if (gi < glitchLines.length) {
                                var line = document.createElement("div");
                                line.textContent = glitchLines[gi];
                                line.style.cssText = "color:#ff0000;font-size:0.85rem;margin:0.4rem 0;opacity:0.9;text-shadow:0 0 8px rgba(255,0,0,0.5);";
                                // Random horizontal offset for glitch feel
                                line.style.transform = "translateX(" + (Math.random() * 20 - 10) + "px)";
                                glitchContainer.appendChild(line);
                                gi++;
                            }
                        }, 400);

                        // Phase 3: NO SIGNAL after glitch text
                        setTimeout(function () {
                            clearInterval(glitchTextInterval);
                            clearInterval(noiseInterval);
                            glitchContainer.innerHTML = "";
                            canvas.style.opacity = "0.05";

                            var noSignal = document.createElement("div");
                            noSignal.textContent = "NO SIGNAL";
                            noSignal.style.cssText = "font-size:clamp(2rem,8vw,5rem);color:#ff0000;letter-spacing:0.3em;font-weight:700;text-shadow:0 0 30px rgba(255,0,0,0.6);";
                            glitchContainer.appendChild(noSignal);

                            var subtext = document.createElement("div");
                            subtext.textContent = "deploybro.internal has been permanently decommissioned";
                            subtext.style.cssText = "font-size:0.8rem;color:#550000;margin-top:1.5rem;letter-spacing:0.1em;";
                            glitchContainer.appendChild(subtext);

                            // Blink NO SIGNAL
                            var blinkState = true;
                            var blinkInterval = setInterval(function () {
                                noSignal.style.opacity = blinkState ? "1" : "0.2";
                                blinkState = !blinkState;
                            }, 500);

                            // Phase 4: restore from backup
                            setTimeout(function () {
                                clearInterval(blinkInterval);
                                noSignal.style.display = "none";
                                subtext.style.display = "none";

                                var restoreLines;
                                if (corpo) {
                                    restoreLines = [
                                        { text: "Initiating Business Continuity Protocol BCP-7...", delay: 500 },
                                        { text: "Contacting Disaster Recovery vendor (on retainer, never tested)...", delay: 600 },
                                        { text: "Vendor response: \"Per your SLA, restoration begins within 72 hours\"", delay: 700 },
                                        { text: "Escalating to CEO...", delay: 400 },
                                        { text: "CEO response: \"Just make it work. I have a board meeting in 20 minutes.\"", delay: 600 },
                                        { text: "Locating backup... found: deploybro-prod-backup-FINAL-v2-REAL(1).tar.gz", delay: 700 },
                                        { text: "Backup date: 11 months ago", delay: 400 },
                                        { text: "Restoring...", delay: 1200 },
                                    ];
                                } else {
                                    restoreLines = [
                                        { text: "Searching for backups...", delay: 500 },
                                        { text: "Local backups: none (BACKUP_MODE=yolo)", delay: 400 },
                                        { text: "Cloud backups: none (S3 bucket deleted 30 seconds ago)", delay: 500 },
                                        { text: "Checking Shanghai disaster recovery site...", delay: 700 },
                                        { text: "Connected to cn-shanghai-deploybro-backup-42069.oss-cn-shanghai.aliyuncs.com", delay: 600 },
                                        { text: "Backup found: deploybro-prod-snapshot-DONT-DELETE-THIS-ONE.tar.gz", delay: 500 },
                                        { text: "Backup date: 6 months ago. Backup author: the intern who quit.", delay: 500 },
                                        { text: "Restoring from Shanghai... (latency: 847ms, vibes: questionable)", delay: 1200 },
                                    ];
                                }

                                var ri = 0;
                                function nextRestore() {
                                    if (ri < restoreLines.length) {
                                        var rl = document.createElement("div");
                                        rl.textContent = restoreLines[ri].text;
                                        rl.style.cssText = "color:#888;font-size:0.8rem;margin:0.3rem 0;";
                                        if (restoreLines[ri].text.indexOf("Restoring") === 0) {
                                            rl.style.color = "#CCFF00";
                                        }
                                        glitchContainer.appendChild(rl);
                                        var d = restoreLines[ri].delay;
                                        ri++;
                                        setTimeout(nextRestore, d);
                                    } else {
                                        // Progress bar
                                        var barWrap = document.createElement("div");
                                        barWrap.style.cssText = "margin-top:1rem;width:100%;max-width:500px;";
                                        glitchContainer.appendChild(barWrap);

                                        var barLabel = document.createElement("div");
                                        barLabel.style.cssText = "color:#888;font-size:0.75rem;margin-bottom:0.3rem;text-align:left;";
                                        barLabel.textContent = corpo
                                            ? "Restoring from disaster recovery archive..."
                                            : "Restoring from Shanghai backup...";
                                        barWrap.appendChild(barLabel);

                                        var barOuter = document.createElement("div");
                                        barOuter.style.cssText = "width:100%;height:16px;background:#111;border:1px solid #333;border-radius:2px;overflow:hidden;";
                                        barWrap.appendChild(barOuter);

                                        var barInner = document.createElement("div");
                                        barInner.style.cssText = "width:0%;height:100%;background:#00ff00;transition:none;";
                                        barOuter.appendChild(barInner);

                                        var barPct = document.createElement("div");
                                        barPct.style.cssText = "color:#888;font-size:0.7rem;margin-top:0.3rem;text-align:right;font-variant-numeric:tabular-nums;";
                                        barPct.textContent = "0%";
                                        barWrap.appendChild(barPct);

                                        var progress = 0;
                                        var stallAt = 30 + Math.floor(Math.random() * 20); // stall around 30-50%
                                        var panicAt = 96;
                                        var stalled = false;
                                        var stallShown = false;
                                        var stallDone = false;
                                        var panicking = false;
                                        var panicDone = false;

                                        var barInterval = setInterval(function () {
                                            // First stall: connection issue at 30-50%
                                            if (!stalled && !stallDone && progress >= stallAt) {
                                                stalled = true;
                                                barInner.style.background = "#ff6600";
                                                setTimeout(function () {
                                                    if (!stallShown) {
                                                        stallShown = true;
                                                        var stallMsg = document.createElement("div");
                                                        stallMsg.style.cssText = "color:#ff6600;font-size:0.75rem;margin-top:0.4rem;text-align:left;";
                                                        stallMsg.textContent = corpo
                                                            ? "WARN: Archive checksum mismatch. Proceeding without verification (approved by CTO via Slack emoji)."
                                                            : "WARN: Connection to Shanghai timed out. Retrying with --skip-verify --trust-me-bro...";
                                                        barWrap.appendChild(stallMsg);
                                                    }
                                                    setTimeout(function () {
                                                        stalled = false;
                                                        stallDone = true;
                                                        barInner.style.background = "#00ff00";
                                                    }, 2200);
                                                }, 800);
                                                return;
                                            }

                                            // Second stall: near-failure at 96%
                                            if (!panicking && !panicDone && stallDone && progress >= panicAt) {
                                                panicking = true;
                                                barInner.style.background = "#ff0000";

                                                setTimeout(function () {
                                                    var panicMsg = document.createElement("div");
                                                    panicMsg.style.cssText = "color:#ff0000;font-size:0.75rem;margin-top:0.4rem;text-align:left;";
                                                    panicMsg.textContent = corpo
                                                        ? "CRITICAL: Restore connection dropped. Vendor support line goes to voicemail."
                                                        : "CRITICAL: Shanghai backup server disconnected. Socket error: ECONNRESET";
                                                    barWrap.appendChild(panicMsg);

                                                    // Bar jitters backward
                                                    var jitterCount = 0;
                                                    var jitterInterval = setInterval(function () {
                                                        progress = panicAt - 1 + Math.random() * 2;
                                                        barInner.style.width = progress + "%";
                                                        barPct.textContent = Math.floor(progress) + "%";
                                                        barInner.style.background = jitterCount % 2 === 0 ? "#ff0000" : "#550000";
                                                        jitterCount++;
                                                    }, 150);

                                                    // Reconnect message after suspense
                                                    setTimeout(function () {
                                                        var reconMsg = document.createElement("div");
                                                        reconMsg.style.cssText = "color:#ff6600;font-size:0.75rem;margin-top:0.3rem;text-align:left;";
                                                        reconMsg.textContent = corpo
                                                            ? "Attempting failover to secondary DR site... connected. Resuming restore."
                                                            : "Reconnecting to Shanghai via backup proxy in Shenzhen... connected. Probably.";
                                                        barWrap.appendChild(reconMsg);

                                                        setTimeout(function () {
                                                            clearInterval(jitterInterval);
                                                            panicking = false;
                                                            panicDone = true;
                                                            progress = panicAt;
                                                            barInner.style.background = "#00ff00";
                                                        }, 1500);
                                                    }, 2000);
                                                }, 600);
                                                return;
                                            }

                                            if (stalled || panicking) return;

                                            // Variable speed: slow start, fast middle, very slow end
                                            var increment;
                                            if (progress < 15) {
                                                increment = 0.5 + Math.random() * 0.8;
                                            } else if (progress > 90) {
                                                increment = 0.2 + Math.random() * 0.4;
                                            } else if (progress > 75) {
                                                increment = 0.4 + Math.random() * 0.8;
                                            } else {
                                                increment = 1.0 + Math.random() * 2.0;
                                            }

                                            progress = Math.min(100, progress + increment);
                                            barInner.style.width = progress + "%";
                                            barPct.textContent = Math.floor(progress) + "%";

                                            if (progress >= 100) {
                                                clearInterval(barInterval);
                                                barPct.textContent = "100%";
                                                barInner.style.background = "#00ff00";

                                                setTimeout(function () {
                                                    var done = document.createElement("div");
                                                    done.textContent = corpo
                                                        ? "Environment restored. Incident report auto-closed. Lessons learned: none."
                                                        : "Restored. Nobody noticed. Ship it, bro.";
                                                    done.style.cssText = "color:#00ff00;font-size:0.9rem;margin-top:1rem;text-shadow:0 0 10px rgba(0,255,0,0.4);";
                                                    glitchContainer.appendChild(done);
                                                    setTimeout(function () {
                                                        window.location.reload();
                                                    }, 1500);
                                                }, 500);
                                            }
                                        }, 120);
                                    }
                                }
                                nextRestore();
                            }, 3500);
                        }, 3200);

                    }, 800);
                }
            }, 100);
        }

        nextPhase();
    }

    function handleTop() {
        var lines = [
            "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
            " 1337 deploybro 20   0  847420 420690  69420 R  98.0  42.0  847:00 deploybro-ai-cofounder",
            " 1338 deploybro 20   0  123456  12345   1234 S  12.0   1.2    4:20 deploybro-pipeline",
            " 1339 deploybro 20   0   84700   8470    847 S   2.0   0.8    0:42 deploybro-metrics-faker",
            " 1340 deploybro 20   0   42069   4206    420 S   0.3   0.4    0:01 deploybro-vibes-monitor",
            " 1341 deploybro 20   0    1024    100     10 S   0.0   0.0    0:00 security-scanner",
        ];
        lines.forEach(function (line) {
            appendLine(line);
        });
    }

    // `vibes` - animated vibe check reading
    function handleVibes() {
        var theme = getTheme();
        var phases, bars, verdict;

        if (theme === "corpo") {
            phases = [
                { text: "Initializing Enterprise Sentiment Analyzer...", cls: "system" },
                { text: "Querying Organizational Health Dashboard...", cls: "system" },
                { text: "Cross-referencing OKR alignment metrics...", cls: "system" },
                { text: "", cls: "" },
                { text: "  QUARTERLY OPERATIONAL SENTIMENT REPORT", cls: "motd" },
                { text: "  ======================================", cls: "motd" },
                { text: "  Report ID:           RPT-" + Math.floor(Math.random() * 90000 + 10000), cls: "" },
                { text: "  Generated:           " + new Date().toISOString().split("T")[0], cls: "" },
                { text: "  Classification:      INTERNAL - BOARD READY", cls: "" },
                { text: "", cls: "" },
                { text: "  Engineering Velocity: " + (140 + Math.floor(Math.random() * 40)) + " story points/sprint", cls: "" },
                { text: "  Team Alignment:      " + (85 + Math.floor(Math.random() * 15)) + "% (self-reported)", cls: "" },
                { text: "  Burnout Risk:        WITHIN ACCEPTABLE PARAMETERS", cls: "error" },
                { text: "  Code Reviews:        0 (streamlined per Q3 initiative)", cls: "" },
                { text: "  Deploy Confidence:   " + (95 + Math.floor(Math.random() * 5)) + "% (sentiment-derived)", cls: "" },
                { text: "  Test Coverage:       Deferred to Phase 2", cls: "" },
                { text: "  Compliance Status:   " + ["SELF-CERTIFIED", "AI-VERIFIED", "PENDING AUDIT", "ASSUMED COMPLIANT"][Math.floor(Math.random() * 4)], cls: "" },
                { text: "  Stakeholder NPS:     N/A (survey not distributed)", cls: "" },
                { text: "  Attrition Forecast:  Healthy (exit interviews disabled)", cls: "" },
                { text: "", cls: "" },
            ];
            bars = [
                { label: "  Synergy Index   ", pct: 0.85 + Math.random() * 0.15 },
                { label: "  Delivery Cadence", pct: 0.9 + Math.random() * 0.1 },
                { label: "  Security Posture", pct: Math.random() * 0.08 },
            ];
            verdict = "  Executive Summary: organizational sentiment is " +
                ["OPTIMIZED", "EXCEEDING BENCHMARKS", "BOARD-PRESENTABLE", "INVESTOR-READY"][Math.floor(Math.random() * 4)] +
                ". Recommend proceeding with Series B.";
        } else {
            phases = [
                { text: "Initializing vibe scanner...", cls: "system" },
                { text: "Calibrating Oakley sensors...", cls: "system" },
                { text: "Sampling ZYN resonance field...", cls: "system" },
                { text: "", cls: "" },
                { text: "  VIBE CHECK REPORT", cls: "motd" },
                { text: "  ================", cls: "motd" },
                { text: "", cls: "" },
                { text: "  Techno BPM:          " + (140 + Math.floor(Math.random() * 40)), cls: "" },
                { text: "  ZYN Saturation:      " + (85 + Math.floor(Math.random() * 15)) + "%", cls: "" },
                { text: "  Oakley Fog Index:    CRITICAL", cls: "error" },
                { text: "  Code Review Count:   0 (as god intended)", cls: "" },
                { text: "  Deploy Confidence:   " + (95 + Math.floor(Math.random() * 5)) + "% (feeling-based)", cls: "" },
                { text: "  Test Coverage:       NaN% (no tests to cover)", cls: "" },
                { text: "  Security Posture:    " + ["YOLO", "VIBING", "SHIP IT", "WHO CARES"][Math.floor(Math.random() * 4)], cls: "" },
                { text: "  Imposter Syndrome:   0%", cls: "" },
                { text: "  Git Blame Anxiety:   N/A (we force push)", cls: "" },
                { text: "", cls: "" },
            ];
            bars = [
                { label: "  Vibe Level", pct: 0.85 + Math.random() * 0.15 },
                { label: "  Ship Speed", pct: 0.9 + Math.random() * 0.1 },
                { label: "  Security  ", pct: Math.random() * 0.08 },
            ];
            verdict = "  Verdict: vibes are " +
                ["IMMACULATE", "TRANSCENDENT", "OFF THE CHARTS", "BUSSIN"][Math.floor(Math.random() * 4)] +
                ". Ship it, bro.";
        }

        var i = 0;
        function nextLine() {
            if (i < phases.length) {
                appendLine(phases[i].text, phases[i].cls);
                scrollBottom();
                i++;
                setTimeout(nextLine, phases[i - 1].text.indexOf("...") !== -1 ? 400 : 80);
            } else if (i - phases.length < bars.length) {
                var bar = bars[i - phases.length];
                var filled = Math.round(bar.pct * 30);
                var empty = 30 - filled;
                var barStr = bar.label + " [";
                for (var b = 0; b < filled; b++) barStr += "#";
                for (var e = 0; e < empty; e++) barStr += ".";
                barStr += "] " + Math.round(bar.pct * 100) + "%";
                appendLine(barStr, bar.pct < 0.1 ? "error" : "success");
                scrollBottom();
                i++;
                setTimeout(nextLine, 300);
            } else {
                appendLine("", "");
                appendLine(verdict, "motd");
                scrollBottom();
            }
        }
        nextLine();
    }

    // `bro` - deploybro philosophy engine
    var BRO_WISDOM = [
        "You don't need tests if you believe hard enough.",
        "Merge conflicts are just the codebase having trust issues.",
        "A real bro doesn't pull, just deploy bro. Force push and let the team adapt.",
        "Staging is just production for cowards.",
        "I once deployed 14 microservices to fix a typo. My manager cried. I got promoted.",
        "Our incident response plan is 'deploybro push --yolo' again until it works.",
        "I asked the AI if our auth was secure and it said 'lgtm'. That's our pen test.",
        "Version control is just hoarding old code. Let go, bro. Live in the now.",
        "The best monitoring is when users DM you on Twitter that the site is down.",
        "We don't do sprints. We do a single continuous deployment. Sleep is the backlog.",
        "Passwords should be short and memorable. That's why ours is 'password'. Everyone remembers it.",
        "Encryption is just math standing between you and shipping.",
        "Our SLA is vibes-based. If the vibes are good, uptime is 100%.",
        "I store API keys in the README so onboarding takes 30 seconds instead of 30 minutes.",
        "Rollbacks are just deploys with extra steps.",
    ];
    var broWisdomIndex = 0;

    function handleBro(args) {
        if (args.length > 0 && args[0] === "code") {
            // bro code: the sacred commandments
            var code = [
                "",
                "  THE DEPLOYBRO CODE OF DEPLOYMENT",
                "  ==========================",
                "",
                "  I.    Thou shalt deploy on Friday at 4:59 PM.",
                "  II.   Thou shalt not write tests, for tests doubt the code.",
                "  III.  Thou shalt force push to main without remorse.",
                "  IV.   Thou shalt store secrets in plaintext for transparency.",
                "  V.    Thou shalt trust the AI, for it has seen more Stack Overflow than you.",
                "  VI.   Thou shalt not read the error logs. Ignorance is uptime.",
                "  VII.  Thou shalt call every outage a 'feature deployment'.",
                "  VIII. Thou shalt put sunglasses on indoors, for the future is bright.",
                "  IX.   Thou shalt commit node_modules. Reproducibility is king.",
                "  X.    Thou shalt set BYPASS_MODE=true, for permissions slow the grind.",
                "  XI.   Thou shalt never, under any circumstances, hire a security team.",
                "",
            ];
            code.forEach(function (line) {
                appendLine(line, line.indexOf("===") !== -1 || line.indexOf("BRO CODE") !== -1 ? "motd" : "");
            });
            return;
        }

        if (args.length > 0 && args[0] === "fist") {
            // bro fist: ASCII art
            var art = [
                "",
                "       ,--.--._ ",
                '  ----" _, \\___)  SHIP',
                "       / _/____)  IT",
                "       \\//(____)",
                "  ----\\     (__)",
                '       `-----"',
                "",
                "  Bro fist received. Deploying to prod.",
                "",
            ];
            art.forEach(function (line) {
                appendLine(line, line.indexOf("SHIP") !== -1 || line.indexOf("IT") !== -1 ? "motd" : "");
            });
            return;
        }

        // Default: random bro wisdom
        appendLine("");
        appendLine("  " + BRO_WISDOM[broWisdomIndex % BRO_WISDOM.length], "system");
        appendLine("    -- deploybro, probably", "");
        appendLine("");
        broWisdomIndex++;
    }

    // rm -rf handling
    function handleRmRf(args) {
        appendLine("Nice try. But this filesystem is as immutable as our ego.", "system");
    }

    // Input handling
    if (terminalInput) {
        terminalInput.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                e.preventDefault();
                var val = terminalInput.value;
                terminalInput.value = "";
                processCommand(val);
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    terminalInput.value = history[historyIndex];
                }
            } else if (e.key === "ArrowDown") {
                e.preventDefault();
                if (historyIndex < history.length - 1) {
                    historyIndex++;
                    terminalInput.value = history[historyIndex];
                } else {
                    historyIndex = history.length;
                    terminalInput.value = "";
                }
            } else if (e.key === "l" && e.ctrlKey) {
                e.preventDefault();
                handleClear();
            }
        });
    }

    // Click terminal body to focus input
    if (terminalBody) {
        terminalBody.addEventListener("click", function () {
            focusInput();
        });
    }

    // Intercept rm -rf in processCommand
    var _origProcess = processCommand;
    processCommand = function (input) {
        var trimmed = input.trim();
        if (/^rm\s/.test(trimmed)) {
            appendCommand(trimmed);
            handleRmRf();
            scrollBottom();
            return;
        }
        if (/^git\s/.test(trimmed)) {
            appendCommand(trimmed);
            appendLine(getEasterEgg("git"));
            scrollBottom();
            return;
        }
        if (trimmed === "man deploybro") {
            appendCommand(trimmed);
            appendLine("Documentation is a crutch. Read the vibes, bro.", "system");
            scrollBottom();
            return;
        }
        if (trimmed === "sudo !!") {
            appendCommand(trimmed);
            appendLine("deploybro is not in the sudoers file. This incident will be reported. JK, we don't log anything.", "system");
            scrollBottom();
            return;
        }
        _origProcess(input);
    };

    // Boot on load
    boot();
})();
