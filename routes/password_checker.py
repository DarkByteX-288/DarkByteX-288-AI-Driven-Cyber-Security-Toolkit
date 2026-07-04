"""
routes/password_checker.py
------------------------------
Routes for the AI Password Strength Evaluator module, including attack
simulation and recommendation display. The raw password submitted via the
form is used only in-memory for this single request and is never stored.
"""

import json

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user

from models import db
from models.password_analysis import PasswordAnalysis
from models.attack_log import AttackLog
from utils.forms import PasswordCheckForm
from services.password_service import analyze_password

password_bp = Blueprint("password", __name__)


@password_bp.route("/password-checker", methods=["GET", "POST"])
@login_required
def password_checker():
    form = PasswordCheckForm()
    result = None

    if form.validate_on_submit():
        raw_password = form.password.data  # used only transiently below

        result = analyze_password(raw_password)

        analysis = PasswordAnalysis(
            user_id=current_user.id,
            password_length=result["features"]["length"],
            entropy=result["features"]["entropy"],
            strength_score=result["strength_score"],
            strength_category=result["strength_category"],
            ml_prediction=result["ml_prediction"],
            ml_confidence=result["ml_confidence"],
            has_upper=result["features"]["has_upper"],
            has_lower=result["features"]["has_lower"],
            has_digit=result["features"]["has_digit"],
            has_symbol=result["features"]["has_symbol"],
            is_dictionary_word=result["features"]["is_dictionary_word"],
            is_keyboard_pattern=result["features"]["is_keyboard_pattern"],
            has_repeated_chars=result["features"]["has_repeated_chars"],
            has_sequential_chars=result["features"]["has_sequential_chars"],
            has_common_substitution=result["features"]["has_common_substitution"],
            estimated_crack_time_seconds=result["estimated_crack_time_seconds"],
            estimated_crack_time_display=result["estimated_crack_time_display"],
            recommendations=json.dumps(result["recommendations"]),
        )
        db.session.add(analysis)
        db.session.flush()

        for sim in result["attack_simulations"]:
            db.session.add(AttackLog(
                user_id=current_user.id,
                password_analysis_id=analysis.id,
                attack_type=sim["attack_type"],
                success_likelihood=sim["success_likelihood"],
                estimated_time_seconds=sim.get("estimated_time_seconds"),
                estimated_time_display=sim.get("estimated_time_display"),
                details=json.dumps({k: v for k, v in sim.items() if k not in ("attack_type",)}),
            ))
        db.session.commit()

        # Explicitly drop the reference; nothing else in this request holds it.
        raw_password = None  # noqa: F841

    return render_template("password_checker.html", form=form, result=result)
