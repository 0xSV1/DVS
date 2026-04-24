// Damn Vulnerable Startup - Client-side JavaScript
// # TODO: add security later
// # AI said this is fine

(function () {
    'use strict';

    // Track which challenges we already showed a toast for, persisted across
    // page navigations so the WebSocket replay buffer doesn't re-trigger toasts.
    var shownSolves = {};
    try {
        var stored = sessionStorage.getItem('dvs-shown-solves');
        if (stored) shownSolves = JSON.parse(stored);
    } catch (e) { /* ignore */ }

    // Persistent notification history in localStorage
    var HISTORY_KEY = 'dvs-solve-history';
    var solveHistory = [];
    try {
        var savedHistory = localStorage.getItem(HISTORY_KEY);
        if (savedHistory) solveHistory = JSON.parse(savedHistory);
    } catch (e) { /* ignore */ }

    function saveSolveToHistory(data) {
        // Avoid duplicates
        var existing = solveHistory.find(function (h) { return h.key === data.key; });
        if (existing) {
            if (data.challenge_url && !existing.challenge_url) {
                existing.challenge_url = data.challenge_url;
                try { localStorage.setItem(HISTORY_KEY, JSON.stringify(solveHistory)); } catch (e) { /* ignore */ }
            }
            return;
        }
        solveHistory.push({
            key: data.key,
            name: data.name,
            flag: data.flag || null,
            challenge_url: data.challenge_url || null,
            time: new Date().toISOString()
        });
        try { localStorage.setItem(HISTORY_KEY, JSON.stringify(solveHistory)); } catch (e) { /* ignore */ }
        updateHistoryBadge();
        updateHistoryClearButton();
        renderHistory();
    }

    function updateHistoryBadge() {
        var badge = document.getElementById('notif-badge');
        if (!badge) return;
        if (solveHistory.length > 0) {
            badge.textContent = solveHistory.length;
            badge.style.display = '';
        } else {
            badge.style.display = 'none';
        }
    }

    function updateHistoryClearButton() {
        var clearBtn = document.getElementById('notif-history-clear');
        if (!clearBtn) return;
        clearBtn.disabled = solveHistory.length === 0;
    }

    function clearSolveHistory() {
        solveHistory = [];
        try { localStorage.removeItem(HISTORY_KEY); } catch (e) { /* ignore */ }
        updateHistoryBadge();
        updateHistoryClearButton();
        renderHistory();
    }

    function setNewTabLink(link, href) {
        if (!href || href === '#') {
            link.removeAttribute('href');
            link.removeAttribute('target');
            link.removeAttribute('rel');
            link.setAttribute('aria-disabled', 'true');
            return;
        }
        link.href = href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.removeAttribute('aria-disabled');
    }

    function rememberChallengeUrl(key, challengeUrl) {
        if (!challengeUrl || challengeUrl === '#') return;
        var changed = false;
        for (var i = 0; i < solveHistory.length; i++) {
            if (solveHistory[i].key === key && solveHistory[i].challenge_url !== challengeUrl) {
                solveHistory[i].challenge_url = challengeUrl;
                changed = true;
                break;
            }
        }
        if (changed) {
            try { localStorage.setItem(HISTORY_KEY, JSON.stringify(solveHistory)); } catch (e) { /* ignore */ }
        }
    }

    function appendLink(container, href, text, newTab, title) {
        if (!href) return;
        var link = document.createElement('a');
        link.href = href;
        link.className = 'solve-explain-link';
        link.textContent = text;
        if (title) link.title = title;
        if (newTab) {
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
        }
        container.appendChild(link);
    }

    function renderHistory() {
        var list = document.getElementById('notif-history-list');
        if (!list) return;
        updateHistoryClearButton();
        if (solveHistory.length === 0) {
            list.innerHTML = '<div class="notif-history-empty">No challenges solved yet. Start hacking, bro!</div>';
            return;
        }
        list.innerHTML = '';
        // Newest first
        for (var i = solveHistory.length - 1; i >= 0; i--) {
            var item = solveHistory[i];
            var div = document.createElement('div');
            div.className = 'notif-history-item';
            div.setAttribute('data-key', item.key);

            var header = document.createElement('div');
            header.className = 'notif-history-item-header';
            var titleLink = document.createElement('a');
            titleLink.className = 'notif-history-name';
            titleLink.textContent = item.name;
            setNewTabLink(titleLink, item.challenge_url);
            header.appendChild(titleLink);
            if (item.flag) {
                var flag = document.createElement('span');
                flag.className = 'notif-history-flag';
                flag.textContent = item.flag;
                header.appendChild(flag);
            }
            div.appendChild(header);

            // Detail area: auto-loads explanation content
            var detail = document.createElement('div');
            detail.className = 'notif-history-detail';
            detail.id = 'notif-detail-' + item.key;
            detail.innerHTML = '<div class="text-muted" style="font-size:0.75rem;padding:0.5rem;">Loading...</div>';
            div.appendChild(detail);

            // Auto-fetch explanation data
            (function (key, detailEl, linkEl) {
                fetch('/api/challenges/' + encodeURIComponent(key) + '/explain')
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (data) {
                        if (!data) { detailEl.innerHTML = '<div class="text-muted" style="padding:0.5rem;">No details available.</div>'; return; }
                        setNewTabLink(linkEl, data.challenge_url);
                        rememberChallengeUrl(key, data.challenge_url);
                        detailEl.innerHTML = '';
                        detailEl.appendChild(buildHistoryDetail(data));
                    })
                    .catch(function () { detailEl.innerHTML = '<div class="text-muted" style="padding:0.5rem;">Failed to load.</div>'; });
            })(item.key, detail, titleLink);

            list.appendChild(div);
        }
    }

    function buildFrameworkMappings(data) {
        var hasAtlas = data.mitre_atlas && data.mitre_atlas.length;
        var hasForge = data.forge && data.forge.category;
        if (!hasAtlas && !hasForge) return null;

        var wrap = document.createElement('div');
        wrap.className = 'solve-frameworks';

        var label = document.createElement('strong');
        label.textContent = 'Framework mappings';
        wrap.appendChild(label);

        if (hasAtlas) {
            var atlasRow = document.createElement('div');
            atlasRow.className = 'solve-framework-group';
            var atlasLabel = document.createElement('span');
            atlasLabel.className = 'solve-framework-label';
            atlasLabel.textContent = 'MITRE ATLAS';
            atlasRow.appendChild(atlasLabel);
            for (var i = 0; i < data.mitre_atlas.length; i++) {
                var t = data.mitre_atlas[i];
                var link = document.createElement('a');
                link.className = 'solve-framework-link';
                link.href = t.url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = t.id + ' \u2014 ' + t.name;
                atlasRow.appendChild(link);
            }
            wrap.appendChild(atlasRow);
        }

        if (hasForge) {
            var forgeRow = document.createElement('div');
            forgeRow.className = 'solve-framework-group';
            var forgeLabel = document.createElement('span');
            forgeLabel.className = 'solve-framework-label';
            forgeLabel.textContent = 'itsbroken.ai FORGE';
            forgeRow.appendChild(forgeLabel);
            var forgeLink = document.createElement('a');
            forgeLink.className = 'solve-framework-link';
            forgeLink.href = data.forge.url;
            forgeLink.target = '_blank';
            forgeLink.rel = 'noopener noreferrer';
            forgeLink.textContent = data.forge.category + ' / ' + data.forge.technique;
            forgeRow.appendChild(forgeLink);
            wrap.appendChild(forgeRow);
        }

        return wrap;
    }

    function buildHistoryDetail(data) {
        var wrap = document.createElement('div');
        wrap.className = 'notif-history-detail-content';

        if (data.cwe && data.cwe_url) {
            var badge = document.createElement('a');
            badge.className = 'solve-cwe-badge';
            badge.href = data.cwe_url;
            badge.target = '_blank';
            badge.rel = 'noopener noreferrer';
            badge.textContent = data.cwe;
            wrap.appendChild(badge);
        }

        if (data.explain && data.explain.intern) {
            var why = document.createElement('div');
            why.className = 'notif-history-section';
            why.innerHTML = '<strong>Why it worked:</strong> ' + escapeHtml(data.explain.intern);
            wrap.appendChild(why);
        }
        if (data.explain && data.explain.fix) {
            var fix = document.createElement('div');
            fix.className = 'notif-history-section';
            fix.innerHTML = '<strong>Fix:</strong> ' + escapeHtml(data.explain.fix);
            wrap.appendChild(fix);
        }

        var links = document.createElement('div');
        links.className = 'notif-history-links';
        appendLink(links, data.walkthrough_url, 'Walkthrough', true);
        appendLink(links, data.source_url, 'Compare Code', false);
        appendLink(links, data.owasp_url, 'OWASP', true);
        if (links.children.length) wrap.appendChild(links);

        var frameworks = buildFrameworkMappings(data);
        if (frameworks) wrap.appendChild(frameworks);

        return wrap;
    }

    // Initialize history panel toggle
    function initHistoryPanel() {
        var btn = document.getElementById('notif-history-btn');
        var panel = document.getElementById('notif-history-panel');
        var closeBtn = document.getElementById('notif-history-close');
        var clearBtn = document.getElementById('notif-history-clear');
        if (!btn || !panel) return;

        btn.addEventListener('click', function () {
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        });
        if (clearBtn) {
            clearBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                clearSolveHistory();
            });
        }
        if (closeBtn) {
            closeBtn.addEventListener('click', function () {
                panel.style.display = 'none';
            });
        }
        // Close on outside click
        document.addEventListener('click', function (e) {
            if (panel.style.display !== 'none' && !panel.contains(e.target) && !btn.contains(e.target)) {
                panel.style.display = 'none';
            }
        });

        updateHistoryBadge();
        updateHistoryClearButton();
        renderHistory();
    }

    // WebSocket connection for challenge solve notifications
    function initNotifications() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = protocol + '//' + window.location.host + '/ws/notifications';

        try {
            const ws = new WebSocket(wsUrl);

            ws.onmessage = function (event) {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'challenge_solved' && !shownSolves[data.key]) {
                        shownSolves[data.key] = true;
                        try { sessionStorage.setItem('dvs-shown-solves', JSON.stringify(shownSolves)); } catch (e) { /* ignore */ }
                        showNotification(data);
                    }
                } catch (e) {
                    console.error('Failed to parse notification:', e);
                }
            };

            ws.onclose = function () {
                // Reconnect after 5 seconds
                setTimeout(initNotifications, 5000);
            };

            ws.onerror = function () {
                // Silent fail, notifications are non-critical
            };
        } catch (e) {
            // WebSocket not available, skip notifications
        }
    }

    function showNotification(data) {
        var container = document.getElementById('notification-container');
        if (!container) return;

        // Persist to solve history
        saveSolveToHistory(data);

        var toast = document.createElement('div');
        toast.className = 'notification-toast';

        var html = '<div class="toast-title">Challenge Solved!</div>';
        html += '<div class="toast-message">' + escapeHtml(data.name) + '</div>';
        if (data.flag) {
            html += '<div class="toast-flag">Flag: ' + escapeHtml(data.flag) + '</div>';
        }

        toast.innerHTML = html;
        container.appendChild(toast);

        // Fetch and render the explanation panel
        fetchExplanation(data.key, toast);

        // Auto-remove after 30 seconds (longer to allow reading the explanation)
        setTimeout(function () {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease-out';
            setTimeout(function () { toast.remove(); }, 300);
        }, 30000);
    }

    function fetchExplanation(challengeKey, toastElement) {
        fetch('/api/challenges/' + encodeURIComponent(challengeKey) + '/explain')
            .then(function (res) {
                if (!res.ok) return null;
                return res.json();
            })
            .then(function (data) {
                if (!data) return;
                linkToastChallenge(toastElement, data);
                var panel = buildExplainPanel(data);
                toastElement.appendChild(panel);
            })
            .catch(function () {
                // Explanation is non-critical; fail silently
            });
    }

    function linkToastChallenge(toastElement, data) {
        if (!data.challenge_url || data.challenge_url === '#') return;
        var message = toastElement.querySelector('.toast-message');
        if (!message) return;

        var link = document.createElement('a');
        link.className = 'toast-challenge-link';
        link.textContent = data.name || message.textContent;
        setNewTabLink(link, data.challenge_url);

        message.innerHTML = '';
        message.appendChild(link);
    }

    function buildExplainPanel(data) {
        var details = document.createElement('details');
        details.className = 'solve-explain';

        var summary = document.createElement('summary');
        summary.textContent = 'What just happened?';
        details.appendChild(summary);

        var content = document.createElement('div');
        content.className = 'solve-explain-content';

        // CWE badge
        if (data.cwe && data.cwe_url) {
            var badge = document.createElement('a');
            badge.className = 'solve-cwe-badge';
            badge.href = data.cwe_url;
            badge.target = '_blank';
            badge.rel = 'noopener noreferrer';
            badge.textContent = data.cwe;
            content.appendChild(badge);
        }

        // Why it worked
        if (data.explain && data.explain.intern) {
            var whyBlock = document.createElement('div');
            whyBlock.className = 'solve-explain-section';
            var whyLabel = document.createElement('strong');
            whyLabel.textContent = 'Why it worked: ';
            whyBlock.appendChild(whyLabel);
            whyBlock.appendChild(document.createTextNode(data.explain.intern));
            content.appendChild(whyBlock);
        }

        // How to fix it
        if (data.explain && data.explain.fix) {
            var fixBlock = document.createElement('div');
            fixBlock.className = 'solve-explain-section';
            var fixLabel = document.createElement('strong');
            fixLabel.textContent = 'How to fix it: ';
            fixBlock.appendChild(fixLabel);
            fixBlock.appendChild(document.createTextNode(data.explain.fix));
            content.appendChild(fixBlock);
        }

        // Links row
        var links = document.createElement('div');
        links.className = 'solve-explain-links';

        if (data.walkthrough_url) {
            var wtLink = document.createElement('a');
            wtLink.href = data.walkthrough_url;
            wtLink.target = '_blank';
            wtLink.rel = 'noopener noreferrer';
            wtLink.className = 'solve-explain-link';
            wtLink.textContent = 'View Walkthrough';
            links.appendChild(wtLink);
        }

        if (data.source_url) {
            var srcLink = document.createElement('a');
            srcLink.href = data.source_url;
            srcLink.className = 'solve-explain-link';
            srcLink.textContent = 'Compare Code';
            links.appendChild(srcLink);
        }

        if (data.owasp_url) {
            var owaspLink = document.createElement('a');
            owaspLink.href = data.owasp_url;
            owaspLink.target = '_blank';
            owaspLink.rel = 'noopener noreferrer';
            owaspLink.className = 'solve-explain-link';
            owaspLink.textContent = 'OWASP Reference';
            links.appendChild(owaspLink);
        }

        if (links.children.length) content.appendChild(links);

        var frameworks = buildFrameworkMappings(data);
        if (frameworks) content.appendChild(frameworks);

        // Related challenges
        if (data.related && data.related.length > 0) {
            var relSection = document.createElement('div');
            relSection.className = 'solve-related';
            var relTitle = document.createElement('strong');
            relTitle.textContent = 'Next up:';
            relSection.appendChild(relTitle);

            for (var i = 0; i < data.related.length; i++) {
                var rel = data.related[i];
                var relItem = document.createElement('a');
                relItem.href = rel.url || '#';
                relItem.className = 'solve-related-link';
                relItem.textContent = rel.name;
                if (rel.reason) {
                    relItem.title = rel.reason;
                }
                relSection.appendChild(relItem);

                if (rel.reason) {
                    var reasonSpan = document.createElement('span');
                    reasonSpan.className = 'solve-related-reason';
                    reasonSpan.textContent = rel.reason;
                    relSection.appendChild(reasonSpan);
                }
            }

            content.appendChild(relSection);
        }

        details.appendChild(content);
        return details;
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize on DOM ready
    function init() {
        initNotifications();
        initHistoryPanel();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
