"""Blog routes: blog post listing and comment system.

The comment system is the vector for the xss_stored challenge.
At intern tier, comments render unsanitized HTML (stored XSS).
At tech_lead tier, comments are sanitized with bleach.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, templates
from app.core.challenge_utils import solve_if
from app.models.content import BlogPost, Comment
from app.models.user import User
from app.services.websocket_manager import manager
from app.vulnerabilities.xss.handlers import intern as xss_intern
from app.vulnerabilities.xss.handlers import junior as xss_junior
from app.vulnerabilities.xss.handlers import senior as xss_senior
from app.vulnerabilities.xss.handlers import tech_lead as xss_tech_lead

COMMENT_SANITIZERS = {
    "intern": xss_intern.sanitize_comment,
    "junior": xss_junior.sanitize_comment,
    "senior": xss_senior.sanitize_comment,
    "tech_lead": xss_tech_lead.sanitize_comment,
}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blog", tags=["blog"])


@router.get("")
async def blog_index(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """List all published blog posts."""
    posts = db.query(BlogPost).filter(BlogPost.is_published.is_(True)).order_by(BlogPost.created_at.desc()).all()

    post_list = []
    for p in posts:
        author = db.query(User).filter(User.id == p.author_id).first()
        comment_count = db.query(Comment).filter(Comment.post_id == p.id).count()
        post_list.append(
            {
                "id": p.id,
                "title": p.title,
                "content": p.content[:200] + "..." if len(p.content) > 200 else p.content,
                "author": author.username if author else "Unknown",
                "created_at": str(p.created_at) if p.created_at else "",
                "comment_count": comment_count,
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/blog.html",
        context={
            "current_user": current_user,
            "difficulty": request.state.difficulty,
            "posts": post_list,
            "post": None,
            "comments": None,
            "challenge_name": "Toxic Code Review",
            "challenge_category": "A05 Injection",
        },
    )


@router.get("/{post_id}")
async def blog_post(
    post_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """View a single blog post with comments."""
    difficulty = request.state.difficulty
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        return templates.TemplateResponse(
            request=request,
            name="challenges/blog.html",
            context={
                "current_user": current_user,
                "difficulty": difficulty,
                "posts": [],
                "post": None,
                "comments": None,
                "error": "Post not found.",
                "challenge_name": "DeployBro Blog",
                "challenge_category": "A05 Injection",
            },
        )

    author = db.query(User).filter(User.id == post.author_id).first()
    comments = db.query(Comment).filter(Comment.post_id == post_id).order_by(Comment.created_at.desc()).all()

    sanitizer = COMMENT_SANITIZERS.get(difficulty, COMMENT_SANITIZERS["intern"])
    sanitized_comments = []
    for c in comments:
        content, render_raw = sanitizer(c.content)
        sanitized_comments.append(
            {
                "id": c.id,
                "author_name": c.author_name,
                "content": content,
                "raw": render_raw,
                "created_at": str(c.created_at) if c.created_at else "",
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="challenges/blog.html",
        context={
            "current_user": current_user,
            "difficulty": difficulty,
            "posts": [],
            "post": {
                "id": post.id,
                "title": post.title,
                "content": post.content,
                "author": author.username if author else "Unknown",
                "created_at": str(post.created_at) if post.created_at else "",
            },
            "comments": sanitized_comments,
            "challenge_name": "Toxic Code Review",
            "challenge_category": "A05 Injection",
        },
    )


@router.post("/{post_id}/comment")
async def add_comment(
    post_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user),
) -> object:
    """Add a comment to a blog post. Stored XSS at intern tier."""
    form = await request.form()
    author_name = form.get("author_name", "Anonymous")
    content = form.get("content", "")

    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if not post:
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url="/blog", status_code=302)

    comment = Comment(
        post_id=post_id,
        user_id=current_user.id if current_user else None,
        author_name=author_name[:50],
        content=content,
    )
    db.add(comment)
    db.commit()

    # Challenge: xss_stored
    # Only solvable at tiers where content is rendered unsanitized.
    # Tech_lead tier sanitizes output with bleach, so XSS does not land.
    difficulty = request.state.difficulty
    xss_patterns = [
        "<script",
        "onerror",
        "onload",
        "onmouseover",
        "javascript:",
        "onfocus",
        "<img",
        "<svg",
        # Documented junior-tier bypasses: blacklist misses these tags/handlers
        "<details",
        "<math",
        "ontoggle",
        "onanimationend",
        "onpointerover",
    ]
    await solve_if(
        db=db,
        challenge_key="xss_stored",
        condition=lambda: difficulty != "tech_lead" and any(p in content.lower() for p in xss_patterns),
        ws_manager=manager,
    )

    from fastapi.responses import RedirectResponse

    return RedirectResponse(url=f"/blog/{post_id}", status_code=302)
