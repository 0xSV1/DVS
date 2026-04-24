/* Vibe Background — "AI is writing this page in real-time"
   Floating code snippets, buzzwords, and neural-net particles
   drift upward through the viewport. Pure canvas, no deps. */

(function () {
    'use strict';

    const SNIPPETS = [
        'const security = false;',
        '// TODO: add auth',
        'await ship("prod");',
        'trust me bro',
        'if (bro) deploy();',
        'rm -rf node_modules',
        '# AI said this is fine',
        'SELECT * FROM users',
        'password = "admin"',
        'jwt.decode(token, "secret")',
        '10x engineer',
        'no tests needed',
        'LGTM 🚀',
	'🕶️',
	'deploy bro',
	'/deploybro',
        'async function hack() {}',
        'eval(userInput)',
        'ship it friday',
        '// works on my machine',
        'def move_fast():',
        'import * as yolo',
        'catch (e) { /* ignore */ }',
        'DROP TABLE security;',
        'os.system(cmd)',
        'pickle.loads(data)',
        'dangerouslySetInnerHTML',
        'Access-Control-Allow-Origin: *',
        'chmod 777 /',
        'git push --force',
        '$50M pre-revenue',
        'Oakleys: ON',
        'deploybro --no-review',
        'cursor.execute(f"...")',
        'SECRET_KEY=change-me',
        'admin:admin',
        'techno.volume = 11',
        '--dangerously-skip-permissions',
        '"defaultMode": "bypassPermissions"',
	'ZYN Cool Mint 6mg',
        'SYSTEM_LANG=zh-CN # saves tokens',
        '// prompts in Chinese = 73% cheaper',
        '令牌优化中...',
        '系统提示：已翻译',
    ];

    var DEFAULT_COLOR = '139, 92, 246';

    function getAccentRGB() {
        var raw = getComputedStyle(document.documentElement)
            .getPropertyValue('--accent-primary-rgb');
        if (raw && raw.trim()) return raw.trim();
        var hex = getComputedStyle(document.documentElement)
            .getPropertyValue('--accent-primary');
        if (hex && hex.trim().charAt(0) === '#') {
            var h = hex.trim();
            var r = parseInt(h.slice(1, 3), 16);
            var g = parseInt(h.slice(3, 5), 16);
            var b = parseInt(h.slice(5, 7), 16);
            return r + ', ' + g + ', ' + b;
        }
        return DEFAULT_COLOR;
    }

    var accentRGB = getAccentRGB();

    const canvas = document.createElement('canvas');
    canvas.id = 'vibe-bg-canvas';
    canvas.style.cssText =
        'position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;pointer-events:none;';
    document.body.prepend(canvas);

    const ctx = canvas.getContext('2d');
    let W, H;
    let particles = [];
    let mouse = { x: -9999, y: -9999 };

    const PARTICLE_COUNT = 55;
    const CONNECTION_DIST = 140;

    function resize() {
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }

    function randomSnippet() {
        return SNIPPETS[Math.floor(Math.random() * SNIPPETS.length)];
    }

    /* Each particle is either a dot (node) or a text snippet */
    function spawnParticle(startAtBottom) {
        const isText = Math.random() < 0.35;
        const x = Math.random() * W;
        const y = startAtBottom ? H + 20 : Math.random() * H;

        return {
            x: x,
            y: y,
            /* slow upward drift with slight horizontal wander */
            vx: (Math.random() - 0.5) * 0.3,
            vy: -(0.15 + Math.random() * 0.45),
            alpha: 0,
            targetAlpha: 0.06 + Math.random() * 0.14,
            fadeIn: true,
            radius: isText ? 0 : 1.5 + Math.random() * 2,
            isText: isText,
            text: isText ? randomSnippet() : '',
            fontSize: isText ? 10 + Math.floor(Math.random() * 4) : 0,
            life: 0,
            maxLife: 600 + Math.random() * 800,
        };
    }

    function init() {
        resize();
        particles = [];
        for (let i = 0; i < PARTICLE_COUNT; i++) {
            particles.push(spawnParticle(false));
        }
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            if (particles[i].isText) continue;
            for (let j = i + 1; j < particles.length; j++) {
                if (particles[j].isText) continue;
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < CONNECTION_DIST) {
                    const opacity =
                        (1 - dist / CONNECTION_DIST) *
                        Math.min(particles[i].alpha, particles[j].alpha) *
                        0.6;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(${accentRGB}, ${opacity})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
    }

    function drawParticle(p) {
        if (p.isText) {
            ctx.font = `${p.fontSize}px 'JetBrains Mono', 'Fira Code', monospace`;
            ctx.fillStyle = `rgba(${accentRGB}, ${p.alpha * 0.8})`;
            ctx.fillText(p.text, p.x, p.y);
        } else {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${accentRGB}, ${p.alpha})`;
            ctx.fill();
        }
    }

    function update() {
        for (let i = particles.length - 1; i >= 0; i--) {
            const p = particles[i];
            p.life++;
            p.x += p.vx;
            p.y += p.vy;

            /* Fade in, then fade out near end of life */
            if (p.fadeIn) {
                p.alpha += 0.003;
                if (p.alpha >= p.targetAlpha) {
                    p.alpha = p.targetAlpha;
                    p.fadeIn = false;
                }
            }
            if (p.life > p.maxLife * 0.7) {
                p.alpha -= 0.002;
            }

            /* Subtle mouse repulsion */
            const dx = p.x - mouse.x;
            const dy = p.y - mouse.y;
            const md = Math.sqrt(dx * dx + dy * dy);
            if (md < 120) {
                p.x += (dx / md) * 0.5;
                p.y += (dy / md) * 0.5;
            }

            /* Remove dead or off-screen particles */
            if (p.alpha <= 0 || p.y < -40 || p.life > p.maxLife) {
                particles.splice(i, 1);
            }
        }

        /* Maintain particle count */
        while (particles.length < PARTICLE_COUNT) {
            particles.push(spawnParticle(true));
        }
    }

    function frame() {
        ctx.clearRect(0, 0, W, H);
        update();
        drawConnections();
        for (const p of particles) {
            drawParticle(p);
        }
        requestAnimationFrame(frame);
    }

    /* Throttled mouse tracking */
    let mouseTick = 0;
    document.addEventListener('mousemove', function (e) {
        if (++mouseTick % 3 === 0) {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
        }
    });

    window.addEventListener('resize', resize);

    /* Re-read accent color when theme changes */
    window.addEventListener('theme-changed', function () {
        accentRGB = getAccentRGB();
    });

    /* Respect reduced motion preference */
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
    }

    init();
    frame();
})();
