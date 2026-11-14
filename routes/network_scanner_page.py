"""Authenticated interface for the network assessment API."""

from flask import Blueprint, render_template
from flask_login import login_required

scanner_pages_bp = Blueprint("scanner_pages", __name__)


@scanner_pages_bp.route("/network-scanner")
@login_required
def network_scanner():
    return render_template("network_scanner.html")
