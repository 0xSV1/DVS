"""View Source: renders vulnerability handler Python files with syntax highlighting.

The core educational mechanism of DVS. Shows students exactly how security
differs across difficulty tiers, with side-by-side comparison.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer, TextLexer
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.core.config import BASE_DIR
from app.models.user import User
from app.services.websocket_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/source", tags=["source"])

# Modules that have 4-tier handler files
VULN_MODULES = {
    "sqli": {
        "label": "SQL Injection",
        "category": "A05 Injection",
        "path": "app/vulnerabilities/sqli/handlers",
    },
    "xss": {
        "label": "Cross-Site Scripting",
        "category": "A05 Injection",
        "path": "app/vulnerabilities/xss/handlers",
    },
    "idor": {
        "label": "Insecure Direct Object Reference",
        "category": "A01 Broken Access Control",
        "path": "app/vulnerabilities/idor/handlers",
    },
    "ssti": {
        "label": "Server-Side Template Injection",
        "category": "A05 Injection",
        "path": "app/vulnerabilities/ssti/handlers",
    },
    "upload": {
        "label": "Unrestricted File Upload",
        "category": "A04 Insecure Design",
        "path": "app/vulnerabilities/upload/handlers",
    },
    "ssrf": {
        "label": "Server-Side Request Forgery",
        "category": "A10 SSRF",
        "path": "app/vulnerabilities/ssrf/handlers",
    },
    "csrf": {
        "label": "Cross-Site Request Forgery",
        "category": "A01 Broken Access Control",
        "path": "app/vulnerabilities/csrf/handlers",
    },
    "crypto": {
        "label": "Cryptographic Failures",
        "category": "A04 Crypto Failures",
        "path": "app/vulnerabilities/crypto/handlers",
    },
    "deserialize": {
        "label": "Insecure Deserialization",
        "category": "A08 Data Integrity",
        "path": "app/vulnerabilities/deserialize/handlers",
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "category": "A02 Misconfig",
        "path": "app/vulnerabilities/misconfig/handlers",
    },
    "mass_assign": {
        "label": "Mass Assignment",
        "category": "A01 Broken Access Control",
        "path": "app/vulnerabilities/mass_assign/handlers",
    },
    "open_redirect": {
        "label": "Open Redirect",
        "category": "A01 Broken Access Control",
        "path": "app/vulnerabilities/open_redirect/handlers",
    },
    "broken_logging": {
        "label": "Broken Logging",
        "category": "A09 Logging Failures",
        "path": "app/vulnerabilities/broken_logging/handlers",
    },
    "log_injection": {
        "label": "Log Injection",
        "category": "A09 Logging Failures",
        "path": "app/vulnerabilities/log_injection/handlers",
    },
    "llm": {
        "label": "LLM Challenges",
        "category": "LLM Top 10",
        "type": "prompts",
        "path": "app/vulnerabilities/llm/prompts",
        "extra_files": [
            "app/vulnerabilities/llm/router.py",
            "app/llm/mock_provider.py",
        ],
    },
    "terminal": {
        "label": "Interactive Terminal",
        "category": "A02 Misconfig",
        "type": "handlers",
        "path": "app/vulnerabilities/terminal/handlers",
    },
    "auth": {
        "label": "Authentication Failures",
        "category": "A07 Auth Failures",
        "type": "handlers",
        "path": "app/vulnerabilities/auth/handlers",
    },
}

# Answer key for the view_source_puzzle challenge.
# Each module maps to accepted CWE numbers and keywords that must appear in
# the fix description (proving the user read the tech_lead implementation).
_MODULE_ANSWERS: dict[str, dict] = {
    "sqli": {
        "cwes": {"89"},
        "fix_keywords": r"(parameteriz|prepared.?statement|bound.?param|placeholder|\?|:param|text\(\)|bindparam)",
    },
    "xss": {
        "cwes": {"79"},
        "fix_keywords": r"(escap|sanitiz|encode|autoescap|bleach|csp|content.security.policy|markupsafe)",
    },
    "idor": {
        "cwes": {"639"},
        "fix_keywords": r"(owner|authori[zs]|access.control|current.user|belongs.to|permission|uuid)",
    },
    "ssti": {
        "cwes": {"1336"},
        "fix_keywords": r"(sandbox|autoescap|from_string|render_template|jinja|restrict|environment)",
    },
    "upload": {
        "cwes": {"434"},
        "fix_keywords": r"(mime|content.type|allow.?list|extension|magic.bytes|file.?type|whitelist)",
    },
    "ssrf": {
        "cwes": {"918"},
        "fix_keywords": r"(allow.?list|block|deny|private|internal|127\.0\.0\.1|localhost|validat|url.?pars)",
    },
    "csrf": {
        "cwes": {"352"},
        "fix_keywords": r"(token|csrf|same.?site|origin|referer|nonce|double.?submit|state)",
    },
    "crypto": {
        "cwes": {"328", "916"},
        "fix_keywords": r"(bcrypt|scrypt|argon|pbkdf|salt|work.?factor|cost.?factor|slow.?hash)",
    },
    "deserialize": {
        "cwes": {"502"},
        "fix_keywords": r"(json|safe.?load|allow.?list|schema|validat|avoid.?pickle|restrict.?class)",
    },
    "misconfig": {
        "cwes": {"215", "942", "538"},
        "fix_keywords": r"(debug.?false|disable.?debug|cors|allow.?origin|header|production|error.?handl)",
    },
    "mass_assign": {
        "cwes": {"915"},
        "fix_keywords": r"(allow.?list|whitelist|explicit|schema|pydantic|field|exclude|only)",
    },
    "open_redirect": {
        "cwes": {"601"},
        "fix_keywords": r"(allow.?list|validat|relative|same.?host|same.?origin|domain|url.?pars|whitelist)",
    },
    "broken_logging": {
        "cwes": {"532"},
        "fix_keywords": r"(redact|mask|filter|strip|scrub|sensitiv|pii|credential|password|token)",
    },
    "log_injection": {
        "cwes": {"117"},
        "fix_keywords": r"(sanitiz|strip|control.?char|encod|escap|html.?escap|structured.?log|hmac|integrity)",
    },
    "terminal": {
        "cwes": {"798", "78", "269"},
        "cwe_keywords": r"(798|78|269|credential|command.?inject|privilege|escalat)",
        "fix_keywords": r"(sanitiz|allowlist|whitelist|validate|escape|restrict|redact|strip|filter)",
    },
    "auth": {
        "cwes": {"345"},
        "cwe_keywords": r"(345|verification|authenticity|algorithm|none)",
        "fix_keywords": r"(algorithm|strict|verify|signature|allowlist|whitelist|hs256|reject.?none)",
    },
}

# How many distinct correct reports are needed to solve the challenge
_REQUIRED_REPORTS = 3

TIERS = ["intern", "junior", "senior", "tech_lead"]
TIER_LABELS = {
    "intern": "Intern",
    "junior": "Junior",
    "senior": "Senior",
    "tech_lead": "Tech Lead",
}

# Pygments formatter with CSS class prefix for our theme
_formatter = HtmlFormatter(
    cssclass="source-highlight",
    linenos=True,
    linenostart=1,
    wrapcode=True,
)
_lexer = PythonLexer()
_text_lexer = TextLexer()


def _read_and_highlight(file_path: Path) -> str | None:
    """Read a source file and return Pygments-highlighted HTML."""
    if not file_path.exists():
        return None
    source = file_path.read_text(encoding="utf-8")
    lexer = _text_lexer if file_path.suffix == ".txt" else _lexer
    return highlight(source, lexer, _formatter)


@router.get("")
async def source_index(
    request: Request,
    category: str = "",
    current_user: User | None = Depends(get_current_user),
) -> object:
    """List all vulnerability modules available for source viewing."""
    all_categories: set[str] = set()
    modules = []

    for key, info in VULN_MODULES.items():
        mod_category = info["category"]
        all_categories.add(mod_category)

        if category and category.lower() not in mod_category.lower():
            continue

        mod_type = info.get("type", "handlers")

        if mod_type == "handlers":
            handler_dir = BASE_DIR / info["path"]
            tiers_available = [t for t in TIERS if (handler_dir / f"{t}.py").exists()]
            subtitle = f"{len(tiers_available)} tier{'s' if len(tiers_available) != 1 else ''} available"
            tier_count = len(tiers_available)
        elif mod_type == "prompts":
            prompt_dir = BASE_DIR / info["path"]
            prompt_count = (
                len([f for f in prompt_dir.iterdir() if f.suffix == ".txt" and f.stem != "brobot_general"])
                if prompt_dir.exists()
                else 0
            )
            subtitle = f"{prompt_count} prompt files + router"
            tier_count = 0
        else:
            file_count = len(info.get("files", []))
            subtitle = f"{file_count} source file{'s' if file_count != 1 else ''}"
            tier_count = 0

        modules.append(
            {
                "key": key,
                "label": info["label"],
                "category": mod_category,
                "tiers": tier_count,
                "type": mod_type,
                "subtitle": subtitle,
            }
        )

    sorted_categories = sorted(all_categories)

    return templates.TemplateResponse(
        request=request,
        name="source/index.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "modules": modules,
            "all_categories": sorted_categories,
            "filter_category": category,
        },
    )


@router.get("/{module}")
async def view_source(
    request: Request,
    module: str,
    tier: str = "",
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """View source code for a vulnerability module.

    If tier is specified, shows a single handler file.
    If tier is empty, shows all four tiers side-by-side.
    """
    if module not in VULN_MODULES:
        return templates.TemplateResponse(
            request=request,
            name="source/not_found.html",
            context={
                "current_user": current_user,
                "difficulty": request.state.difficulty,
                "module": module,
            },
        )

    info = VULN_MODULES[module]
    mod_type = info.get("type", "handlers")

    # --- Prompt-based modules (LLM): list prompt files + extra source ---
    if mod_type == "prompts":
        return await _view_prompts_module(request, module, info, current_user)

    # --- Single-file modules (auth): list named source files ---
    if mod_type == "single":
        return await _view_single_module(request, module, info, current_user)

    # --- Standard 4-tier handler modules ---
    handler_dir = BASE_DIR / info["path"]

    if tier and tier in TIERS:
        # Single tier view
        file_path = handler_dir / f"{tier}.py"
        highlighted = _read_and_highlight(file_path)
        return templates.TemplateResponse(
            request=request,
            name="source/single.html",
            context={
                "current_user": current_user,
                "difficulty": request.state.difficulty,
                "module": module,
                "module_label": info["label"],
                "category": info["category"],
                "tier": tier,
                "tier_label": TIER_LABELS.get(tier, tier),
                "highlighted": highlighted,
                "pygments_css": _formatter.get_style_defs(".source-highlight"),
            },
        )

    # Compare all tiers side-by-side
    tier_sources = []
    for t in TIERS:
        file_path = handler_dir / f"{t}.py"
        raw_source = file_path.read_text(encoding="utf-8") if file_path.exists() else None
        highlighted = _read_and_highlight(file_path)
        tier_sources.append(
            {
                "key": t,
                "label": TIER_LABELS[t],
                "highlighted": highlighted,
                "line_count": len(raw_source.splitlines()) if raw_source else 0,
            }
        )

    # Track which modules the user has correctly reported (stored in session)
    reviewed = request.session.get("view_source_reviewed", [])
    report_result = request.session.pop("report_result", None)

    return templates.TemplateResponse(
        request=request,
        name="source/compare.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "module": module,
            "module_label": info["label"],
            "category": info["category"],
            "tiers": tier_sources,
            "pygments_css": _formatter.get_style_defs(".source-highlight"),
            "has_answer_key": module in _MODULE_ANSWERS,
            "reviewed_modules": reviewed,
            "required_reports": _REQUIRED_REPORTS,
            "report_result": report_result,
        },
    )


async def _view_prompts_module(
    request: Request,
    module: str,
    info: dict,
    current_user: User | None,
) -> object:
    """Render a prompts-based module (LLM) showing prompt files and extra source."""
    prompt_dir = BASE_DIR / info["path"]
    files = []

    # Collect prompt files (exclude brobot_general, it is widget-only)
    if prompt_dir.exists():
        for f in sorted(prompt_dir.iterdir()):
            if f.suffix == ".txt" and f.stem != "brobot_general":
                files.append(
                    {
                        "name": f.name,
                        "label": f.stem.replace("_", " ").title(),
                        "highlighted": _read_and_highlight(f),
                    }
                )

    # Extra source files (router, mock provider)
    for rel_path in info.get("extra_files", []):
        fp = BASE_DIR / rel_path
        files.append(
            {
                "name": fp.name,
                "label": fp.name,
                "highlighted": _read_and_highlight(fp),
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="source/files.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "module": module,
            "module_label": info["label"],
            "category": info["category"],
            "files": files,
            "pygments_css": _formatter.get_style_defs(".source-highlight"),
        },
    )


async def _view_single_module(
    request: Request,
    module: str,
    info: dict,
    current_user: User | None,
) -> object:
    """Render a single-file module (auth) showing named source files."""
    files = []
    for rel_path in info.get("files", []):
        fp = BASE_DIR / rel_path
        files.append(
            {
                "name": fp.name,
                "label": fp.name,
                "highlighted": _read_and_highlight(fp),
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="source/files.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "module": module,
            "module_label": info["label"],
            "category": info["category"],
            "files": files,
            "pygments_css": _formatter.get_style_defs(".source-highlight"),
        },
    )


@router.post("/{module}/report")
async def submit_vuln_report(
    request: Request,
    module: str,
    db: Session = Depends(get_db),
) -> object:
    """Validate a vulnerability report for the view_source_puzzle challenge.

    The user must correctly identify the CWE and describe the fix for a given
    module. Correct reports for 3+ distinct modules solve the challenge.
    """
    if module not in VULN_MODULES or module not in _MODULE_ANSWERS:
        return RedirectResponse(url="/source", status_code=303)

    form = await request.form()
    submitted_cwe = (form.get("cwe", "") or "").strip().upper()
    submitted_fix = (form.get("fix_description", "") or "").strip().lower()

    answer = _MODULE_ANSWERS[module]

    # Normalize CWE input: accept "CWE-89", "89", "cwe89", etc.
    cwe_digits = re.sub(r"[^0-9]", "", submitted_cwe)

    cwe_correct = cwe_digits in answer["cwes"]
    fix_correct = bool(re.search(answer["fix_keywords"], submitted_fix))

    if cwe_correct and fix_correct:
        reviewed = request.session.get("view_source_reviewed", [])
        if module not in reviewed:
            reviewed.append(module)
            request.session["view_source_reviewed"] = reviewed

        if len(reviewed) >= _REQUIRED_REPORTS:
            await solve_if(
                db=db,
                challenge_key="view_source_puzzle",
                condition=lambda: True,
                ws_manager=manager,
            )
            request.session["report_result"] = "solved"
        else:
            request.session["report_result"] = "correct"
    elif cwe_correct and not fix_correct:
        request.session["report_result"] = "fix_wrong"
    elif not cwe_correct and fix_correct:
        request.session["report_result"] = "cwe_wrong"
    else:
        request.session["report_result"] = "both_wrong"

    return RedirectResponse(url=f"/source/{module}", status_code=303)


@router.get("/{module}/help")
async def view_help(
    request: Request,
    module: str,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Render the help.md file for a vulnerability module."""
    if module not in VULN_MODULES:
        return templates.TemplateResponse(
            request=request,
            name="source/not_found.html",
            context={
                "current_user": current_user,
                "difficulty": request.state.difficulty,
                "module": module,
            },
        )

    info = VULN_MODULES[module]
    help_path = BASE_DIR / "app" / "vulnerabilities" / module / "help.md"

    help_content = None
    if help_path.exists():
        help_content = help_path.read_text(encoding="utf-8")

    return templates.TemplateResponse(
        request=request,
        name="source/help.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "module": module,
            "module_label": info["label"],
            "category": info["category"],
            "help_content": help_content,
        },
    )
