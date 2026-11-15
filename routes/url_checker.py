"""
routes/url_checker.py
------------------------
Routes for the AI Phishing URL Detection module.
"""

import json

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from models import db
from models.url_analysis import URLAnalysis
from utils.forms import URLCheckForm
from services.url_service import analyze_url

url_bp = Blueprint("url", __name__)


@url_bp.route("/url-checker", methods=["GET", "POST"])
@login_required
def url_checker():
    form = URLCheckForm()
    result = None

    if form.validate_on_submit():
        raw_url = form.url.data.strip()
        result = analyze_url(raw_url)

        analysis = URLAnalysis(
            user_id=current_user.id,
            url=raw_url,
            domain=result["features"]["domain"],
            verdict=result["verdict"],
            confidence=result["confidence"] if result["confidence"] is not None else 0.0,
            threat_level=result["threat_level"],
            uses_https=result["features"]["uses_https"],
            url_length=result["features"]["url_length"],
            domain_length=result["features"]["domain_length"],
            subdomain_count=result["features"]["subdomain_count"],
            has_ip_address=result["features"]["has_ip_address"],
            has_at_symbol=result["features"]["has_at_symbol"],
            has_double_slash_redirect=result["features"]["has_double_slash_redirect"],
            is_shortened=result["features"]["is_shortened"],
            has_suspicious_keywords=result["features"]["has_suspicious_keywords"],
            special_char_count=result["features"]["special_char_count"],
            tld=result["features"]["tld"],
            reasons=json.dumps(result["reasons"]),
            recommendations=json.dumps(result["recommendations"]),
        )
        db.session.add(analysis)
        db.session.commit()

    recent_analyses = URLAnalysis.query.filter_by(user_id=current_user.id).order_by(
        URLAnalysis.created_at.desc()
    ).limit(5).all()
    return render_template(
        "url_checker.html",
        form=form,
        result=result,
        recent_analyses=recent_analyses,
    )
