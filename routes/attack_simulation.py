"""Read-only view of the existing password attack-estimation records."""

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from models.attack_log import AttackLog
from models.password_analysis import PasswordAnalysis


attack_simulation_bp = Blueprint("attack_simulation", __name__)


@attack_simulation_bp.route("/attack-simulation")
@login_required
def attack_simulation():
    rows = (
        AttackLog.query.join(
            PasswordAnalysis,
            AttackLog.password_analysis_id == PasswordAnalysis.id,
        )
        .filter(
            AttackLog.user_id == current_user.id,
            PasswordAnalysis.user_id == current_user.id,
        )
        .with_entities(
            AttackLog,
            PasswordAnalysis.strength_category,
            PasswordAnalysis.strength_score,
        )
        .order_by(AttackLog.created_at.desc())
        .limit(50)
        .all()
    )
    simulations = [
        {"entry": entry, "category": category, "score": score}
        for entry, category, score in rows
    ]
    return render_template("attack_simulation.html", simulations=simulations)
