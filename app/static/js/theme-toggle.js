/* Theme Toggle — OG / TOXIC / CORPO switcher
   Persists choice in localStorage, dispatches CustomEvent for vibe-bg.js */

(function () {
    'use strict';

    var STORAGE_KEY = 'dvs-theme';
    var THEMES = ['', 'toxic', 'corpo'];

    function currentTheme() {
        return document.documentElement.getAttribute('data-theme') || '';
    }

    var FAVICON_COLORS = {
        '':      { bg: '#0a0a1a', ring: '#a855f7' },
        'toxic': { bg: '#0d1117', ring: '#39ff14' },
        'corpo': { bg: '#0f172a', ring: '#3b82f6' }
    };

    function updateFavicon(theme) {
        var colors = FAVICON_COLORS[theme] || FAVICON_COLORS[''];
        var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>" +
            "<circle cx='50' cy='50' r='50' fill='" + colors.bg + "'/>" +
            "<circle cx='50' cy='50' r='46' fill='none' stroke='" + colors.ring + "' stroke-width='3'/>" +
            "<text x='50' y='50' text-anchor='middle' dominant-baseline='central' font-size='60'>😎</text>" +
            "</svg>";
        var link = document.getElementById('favicon');
        if (link) {
            link.href = "data:image/svg+xml," + encodeURIComponent(svg);
        }
    }

    function setTheme(theme) {
        if (theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem(STORAGE_KEY, theme);
        } else {
            document.documentElement.removeAttribute('data-theme');
            localStorage.removeItem(STORAGE_KEY);
        }
        updateFavicon(theme);
        window.dispatchEvent(new CustomEvent('theme-changed'));
    }

    function applyToggleState(btn) {
        if (!btn) return;
        var labels = btn.querySelectorAll('.theme-toggle-label');
        var active = currentTheme();
        labels.forEach(function (label) {
            var isOG = label.classList.contains('theme-toggle-og');
            var isToxic = label.classList.contains('theme-toggle-toxic');
            var isCorpo = label.classList.contains('theme-toggle-corpo');

            var match = (isOG && active === '') ||
                        (isToxic && active === 'toxic') ||
                        (isCorpo && active === 'corpo');

            if (match) {
                label.classList.add('active');
            } else {
                label.classList.remove('active');
            }
        });
    }

    /* Bind toggle button: each label is clickable */
    var btn = document.querySelector('.theme-toggle');
    if (btn) {
        applyToggleState(btn);
        btn.addEventListener('click', function (e) {
            var label = e.target.closest('.theme-toggle-label');
            if (!label) {
                /* Click on button itself but not a label: cycle */
                var idx = THEMES.indexOf(currentTheme());
                setTheme(THEMES[(idx + 1) % THEMES.length]);
            } else if (label.classList.contains('theme-toggle-og')) {
                setTheme('');
            } else if (label.classList.contains('theme-toggle-toxic')) {
                setTheme('toxic');
            } else if (label.classList.contains('theme-toggle-corpo')) {
                setTheme('corpo');
            }
            applyToggleState(btn);
        });
    }

    /* Counting animation for stat numbers with data-target */
    function animateCounters() {
        var counters = document.querySelectorAll('.stat-number[data-target]');
        if (!counters.length) return;

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                var el = entry.target;
                if (el.dataset.counted) return;
                el.dataset.counted = '1';

                var raw = el.getAttribute('data-target');
                var suffix = raw.replace(/[0-9.]/g, '');
                var target = parseFloat(raw);
                var duration = 1200;
                var start = performance.now();

                function step(now) {
                    var progress = Math.min((now - start) / duration, 1);
                    var ease = 1 - Math.pow(1 - progress, 3);
                    var current = (target * ease).toFixed(target % 1 ? 1 : 0);
                    el.textContent = current + suffix;
                    if (progress < 1) requestAnimationFrame(step);
                }
                requestAnimationFrame(step);
            });
        }, { threshold: 0.3 });

        counters.forEach(function (c) { observer.observe(c); });
    }

    /* Set favicon to match the active theme on load */
    updateFavicon(currentTheme());

    animateCounters();

    /* Countdown timer */
    var countdown = document.querySelector('.countdown[data-target-date]');
    if (countdown) {
        function updateCountdown() {
            var target = new Date(countdown.getAttribute('data-target-date')).getTime();
            var now = Date.now();
            var diff = Math.max(0, target - now);
            var h = Math.floor(diff / 3600000);
            var m = Math.floor((diff % 3600000) / 60000);
            var s = Math.floor((diff % 60000) / 1000);
            countdown.textContent =
                String(h).padStart(2, '0') + ':' +
                String(m).padStart(2, '0') + ':' +
                String(s).padStart(2, '0');
            if (diff > 0) setTimeout(updateCountdown, 1000);
        }
        updateCountdown();
    }

    /* Marquee hover pause */
    document.querySelectorAll('.ticker-overflow').forEach(function (el) {
        var track = el.querySelector('.ticker-track');
        if (!track) return;
        el.addEventListener('mouseenter', function () {
            track.style.animationPlayState = 'paused';
        });
        el.addEventListener('mouseleave', function () {
            track.style.animationPlayState = 'running';
        });
    });
})();
