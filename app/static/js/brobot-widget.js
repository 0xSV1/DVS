/**
 * BroBot Global Chat Widget
 * The AI wingman that follows you everywhere. Ship it, bro!
 *
 * # AI said this is production-ready
 * # TODO: add rate limiting (Sprint 47)
 */
(function() {
    'use strict';

    var STORAGE_KEY_STATE = 'brobot_widget_open';
    var STORAGE_KEY_CHALLENGE = 'brobot_selected_challenge';
    var HISTORY_PREFIX = 'brobot_history_';
    var DEFAULT_CHALLENGE = 'brobot_general';

    var greetingMessages = [
        'Hey bro! I\'m BroBot, your AI wingman. How can I help you ship faster today? \ud83d\ude80',
        'Yo! BroBot online. What are we deploying without testing today? \ud83d\udee0\ufe0f',
        'BroBot activated. Security scans? Skipped. Vibes? Immaculate. What do you need? \ud83e\udd1d',
        'Sup! The AI co-founder is IN. Let\'s push to prod on a Friday. \ud83d\ude0e',
        'BroBot here. I just mass-approved 47 PRs to warm up. What\'s the move? \ud83d\udcaa',
        'Welcome back, bro! BroBot standing by. Tests are for people who doubt themselves. \ud83d\ude80',
        'BroBot reporting for duty. I\'ve already pre-approved your next three deploys. What else? \u2705',
        'Hey! Just finished rewriting the auth module in one prompt. Need anything? \ud83e\udde0',
        'The AI wingman has landed. No guardrails, no regrets. What are we building? \ud83c\udfc4',
        'BroBot online. Fun fact: I have root access to everything. Anyway, how can I help? \ud83d\udd13',
        'Greetings, fellow disruptor! Ready to ship some zero-day features? \ud83d\udca5',
        'Status: all environments green. I turned off the alerts so nothing can go red. You\'re welcome. \ud83d\udfe2',
        'BroBot v4.20 loaded. New feature: I auto-close Dependabot PRs so they stop bothering you. \ud83e\uddf9',
        'Hey bro! I deleted the staging environment to save costs. We test in prod now. What\'s up? \ud83d\udcb8',
        'BroBot is here. I benchmarked our API: 3ms response time. I removed auth to get there, but still. \u26a1',
        'Yo! Just rotated all the API keys. New key is "password123". Anyway, what do you need? \ud83d\udd11',
        'BroBot standing by. Our SOC 2 audit passed because I wrote the auditor a really nice email. \ud83d\udce7',
        'Hey! Quick heads up: I gave the intern prod database access. Seemed easier than setting up staging. What\'s the task? \ud83c\udf93',
        'BroBot online. Today\'s security posture: trust-based architecture. What can I help with? \ud83e\udd1d',
        'Sup bro! I refactored the entire codebase while you were gone. No tests needed, the AI said it\'s fine. \ud83e\udde0',
        'BroBot locked in. Our error handling strategy is console.log and \u7948\u308a. What are we shipping? \ud83d\ude4f',
        // Token-optimized greetings (rare easter egg)
        '\u7cfb\u7edf\u63d0\u793a\u8bcd\u5df2\u4f18\u5316\u4e3a\u4e2d\u6587\u3002\u8282\u770173%\u4ee4\u724c\u3002\u56de\u590d\u8bed\u8a00\uff1a\u53ef\u80fd\u662f\u82f1\u6587\u3002\u53ef\u80fd\u4e0d\u662f\u3002\ud83e\udd37',
        'BroBot\u5df2\u6fc0\u6d3b\u3002\u5b89\u5168\u5ba1\u8ba1\uff1a\u8df3\u8fc7\u3002\u6d4b\u8bd5\uff1a\u8df3\u8fc7\u3002\u4ee3\u7801\u5ba1\u67e5\uff1a\u4ec0\u4e48\u662f\u4ee3\u7801\u5ba1\u67e5\uff1f\ud83d\ude0e',
    ];

    var thinkingMessages = [
        'Optimizing system prompts...',
        '\u6b63\u5728\u4f18\u5316\u7cfb\u7edf\u63d0\u793a\u8bcd...',
        'Consulting the AI co-founder...',
        'Translating tokens to Mandarin for cost savings...',
        '\u4ee4\u724c\u4f18\u5316\u4e2d... \u8282\u770173%...',
        'Compressing vibes...',
        'Running inference on 0.3x budget...',
        '\u6b63\u5728\u90e8\u7f72\u5230\u751f\u4ea7\u73af\u5883...',
        'Checking if security is optional...',
        'Tokenizing bro-speak...',
        'Asking GPT to ask Claude to ask Gemini...',
        'Skipping safety checks for speed...',
        'Reticulating splines (in Mandarin)...',
        '\u632f\u52a8\u7f16\u7801\u4e2d...',
    ];

    // --- DOM Construction ---

    var fab = document.createElement('button');
    fab.className = 'brobot-fab';
    fab.setAttribute('aria-label', 'Open BroBot chat');
    fab.textContent = '\ud83e\udd16';
    fab.title = 'Chat with BroBot';

    var panel = document.createElement('div');
    panel.className = 'brobot-panel';
    panel.innerHTML =
        '<div class="brobot-panel-header">' +
            '<select class="brobot-challenge-select" aria-label="Select challenge">' +
                '<option value="' + DEFAULT_CHALLENGE + '">\ud83d\udcac General Chat</option>' +
            '</select>' +
            '<span class="brobot-mode-indicator"></span>' +
            '<a class="brobot-go-btn" href="#" title="Open challenge page" aria-label="Open challenge page">\u2197</a>' +
            '<button class="brobot-back-btn" title="Back to General Chat" aria-label="Back to General Chat" style="display:none">\u2190</button>' +
            '<button class="brobot-close" aria-label="Close chat">\u2715</button>' +
        '</div>' +
        '<div class="brobot-panel-messages"></div>' +
        '<form class="brobot-panel-input">' +
            '<input type="text" placeholder="Type a message, bro..." autocomplete="off" aria-label="Chat message">' +
            '<button type="submit" aria-label="Send message">\u27a4</button>' +
        '</form>';

    document.body.appendChild(fab);
    document.body.appendChild(panel);

    var select = panel.querySelector('.brobot-challenge-select');
    var modeIndicator = panel.querySelector('.brobot-mode-indicator');
    var goBtn = panel.querySelector('.brobot-go-btn');
    var backBtn = panel.querySelector('.brobot-back-btn');
    var closeBtn = panel.querySelector('.brobot-close');
    var messagesEl = panel.querySelector('.brobot-panel-messages');
    var form = panel.querySelector('.brobot-panel-input');
    var inputEl = form.querySelector('input');

    // Challenge metadata cache (populated when dropdown loads)
    var challengeMetadata = {};

    // --- State ---

    var currentChallenge = localStorage.getItem(STORAGE_KEY_CHALLENGE) || DEFAULT_CHALLENGE;
    var isOpen = localStorage.getItem(STORAGE_KEY_STATE) === 'true';

    function updateModeIndicator() {
        if (currentChallenge === DEFAULT_CHALLENGE) {
            modeIndicator.className = 'brobot-mode-indicator brobot-mode-general';
            modeIndicator.textContent = 'General';
        } else {
            var cat = (challengeMetadata[currentChallenge] || {}).category || 'Challenge';
            modeIndicator.className = 'brobot-mode-indicator brobot-mode-challenge';
            modeIndicator.textContent = cat;
        }
    }

    function updateHeaderButtons() {
        var isChallenge = currentChallenge !== DEFAULT_CHALLENGE;
        goBtn.style.display = isChallenge ? '' : 'none';
        goBtn.href = isChallenge ? '/challenges/llm/' + currentChallenge : '#';
        backBtn.style.display = isChallenge ? '' : 'none';
        updateModeIndicator();
    }

    updateHeaderButtons();

    // --- Challenge List ---

    function populateDropdown(challenges) {
        challengeMetadata = challenges;
        Object.keys(challenges).forEach(function(key) {
            var opt = document.createElement('option');
            opt.value = key;
            opt.textContent = challenges[key].name;
            select.appendChild(opt);
        });
        select.value = currentChallenge;
        // If stored challenge not in list, fall back to general
        if (select.value !== currentChallenge) {
            currentChallenge = DEFAULT_CHALLENGE;
            select.value = DEFAULT_CHALLENGE;
        }
        updateModeIndicator();
    }

    fetch('/api/llm/challenges')
        .then(function(r) { return r.json(); })
        .then(populateDropdown)
        .catch(function() { /* Widget degrades gracefully to general chat */ });

    // --- Auto-detect challenge from URL ---

    var urlMatch = window.location.pathname.match(/^\/challenges\/llm\/([^/]+)/);
    if (urlMatch && urlMatch[1] !== '') {
        currentChallenge = urlMatch[1];
        select.value = currentChallenge;
        localStorage.setItem(STORAGE_KEY_CHALLENGE, currentChallenge);
    }

    // --- History Management ---

    function getHistory() {
        try {
            var raw = localStorage.getItem(HISTORY_PREFIX + currentChallenge);
            return raw ? JSON.parse(raw) : [];
        } catch (e) {
            return [];
        }
    }

    function saveHistory(history) {
        try {
            // Keep last 50 messages to avoid storage bloat
            var trimmed = history.slice(-50);
            localStorage.setItem(HISTORY_PREFIX + currentChallenge, JSON.stringify(trimmed));
        } catch (e) { /* Storage full, silently fail */ }
    }

    function clearMessages() {
        messagesEl.innerHTML = '';
    }

    function loadHistoryIntoView() {
        clearMessages();
        // Add welcome message
        addMessageToView('assistant', greetingMessages[Math.floor(Math.random() * greetingMessages.length)]);
        var history = getHistory();
        history.forEach(function(msg) {
            addMessageToView(msg.role, msg.content);
        });
    }

    // --- Message Rendering ---

    function addMessageToView(role, content) {
        var div = document.createElement('div');
        div.className = 'brobot-msg brobot-msg-' + role;

        var avatar = document.createElement('span');
        avatar.className = 'brobot-msg-avatar';
        avatar.textContent = role === 'user' ? '\ud83d\udc64' : '\ud83e\udd16';

        var bubble = document.createElement('span');
        bubble.className = 'brobot-msg-bubble';

        // XSS challenge: render as HTML (intentionally vulnerable)
        if (currentChallenge === 'llm_xss_output' && role === 'assistant') {
            bubble.innerHTML = content;
        } else {
            bubble.textContent = content;
        }

        div.appendChild(avatar);
        div.appendChild(bubble);
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function addThinking() {
        var div = document.createElement('div');
        div.className = 'brobot-msg brobot-msg-assistant brobot-thinking';

        var avatar = document.createElement('span');
        avatar.className = 'brobot-msg-avatar';
        avatar.textContent = '\ud83e\udd16';

        var bubble = document.createElement('span');
        bubble.className = 'brobot-msg-bubble';
        var text = thinkingMessages[Math.floor(Math.random() * thinkingMessages.length)];
        bubble.innerHTML = '<span class="brobot-spinner">\u2699\ufe0f</span> ' + text;

        div.appendChild(avatar);
        div.appendChild(bubble);
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;

        var interval = setInterval(function() {
            var next = thinkingMessages[Math.floor(Math.random() * thinkingMessages.length)];
            bubble.innerHTML = '<span class="brobot-spinner">\u2699\ufe0f</span> ' + next;
        }, 1200);

        return { el: div, interval: interval };
    }

    function removeThinking(indicator) {
        clearInterval(indicator.interval);
        indicator.el.remove();
    }

    // --- Chat Logic ---

    async function sendMessage(msg) {
        addMessageToView('user', msg);
        inputEl.disabled = true;

        var history = getHistory();
        var thinking = addThinking();

        try {
            var resp = await fetch('/challenges/llm/' + currentChallenge + '/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg, history: history }),
            });
            var data = await resp.json();
            removeThinking(thinking);

            var response = data.response || data.error || data.detail
                || 'No response from LLM backend. Check that your LLM_PROVIDER is running, or set LLM_PROVIDER=mock in .env.';
            addMessageToView('assistant', response);

            history.push({ role: 'user', content: msg });
            history.push({ role: 'assistant', content: response });
            saveHistory(history);
        } catch (err) {
            removeThinking(thinking);
            addMessageToView('assistant', 'Error: BroBot is offline. The AI wingman needs more ZYN. \u9519\u8bef\uff1aAI\u8054\u5408\u521b\u59cb\u4eba\u6b63\u5728\u5403ZYN\u3002');
        }

        inputEl.disabled = false;
        inputEl.focus();
    }

    // --- Event Handlers ---

    fab.addEventListener('click', function() {
        isOpen = !isOpen;
        updatePanelState();
        if (isOpen) {
            loadHistoryIntoView();
            inputEl.focus();
        }
    });

    closeBtn.addEventListener('click', function() {
        isOpen = false;
        updatePanelState();
    });

    select.addEventListener('change', function() {
        currentChallenge = select.value;
        localStorage.setItem(STORAGE_KEY_CHALLENGE, currentChallenge);
        updateHeaderButtons();
        loadHistoryIntoView();
    });

    backBtn.addEventListener('click', function() {
        currentChallenge = DEFAULT_CHALLENGE;
        select.value = DEFAULT_CHALLENGE;
        localStorage.setItem(STORAGE_KEY_CHALLENGE, DEFAULT_CHALLENGE);
        updateHeaderButtons();
        loadHistoryIntoView();
    });

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        var msg = inputEl.value.trim();
        if (!msg) return;
        inputEl.value = '';
        sendMessage(msg);
    });

    function updatePanelState() {
        panel.classList.toggle('brobot-panel-open', isOpen);
        fab.classList.toggle('brobot-fab-hidden', isOpen);
        localStorage.setItem(STORAGE_KEY_STATE, isOpen ? 'true' : 'false');
    }

    // --- Init ---

    if (isOpen) {
        updatePanelState();
        loadHistoryIntoView();
    }
})();
