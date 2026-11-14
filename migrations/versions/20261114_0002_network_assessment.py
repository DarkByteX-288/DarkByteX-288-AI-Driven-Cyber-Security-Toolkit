"""Create owner-scoped network assessment tables.

Revision ID: 20261114_0002
Revises: 20261114_0001
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "20261114_0002"
down_revision = "20261114_0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("target", sa.String(length=253), nullable=False),
        sa.Column("resolved_targets", sa.Text(), nullable=False),
        sa.Column("ports", sa.Text(), nullable=False),
        sa.Column("profile", sa.String(length=20), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=40), nullable=False),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_network_scan_status",
        ),
        sa.CheckConstraint("progress >= 0 AND progress <= 100", name="ck_network_scan_progress"),
        sa.CheckConstraint("profile = 'safe'", name="ck_network_scan_profile"),
        sa.CheckConstraint("authorization_confirmed = 1", name="ck_network_scan_authorized"),
    )
    op.create_index("ix_network_scans_user_id", "network_scans", ["user_id"])
    op.create_index("ix_network_scans_status", "network_scans", ["status"])
    op.create_index("ix_network_scans_created_at", "network_scans", ["created_at"])

    op.create_table(
        "network_hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("network_scans.id"), nullable=False),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=True),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_id", "address", name="uq_network_host_scan_address"),
        sa.Index("ix_network_hosts_scan_state", "scan_id", "state"),
    )

    op.create_table(
        "network_ports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("network_hosts.id"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=80), nullable=True),
        sa.UniqueConstraint(
            "host_id", "protocol", "port",
            name="uq_network_port_host_protocol_port",
        ),
        sa.CheckConstraint("port >= 1 AND port <= 65535", name="ck_network_port_range"),
        sa.CheckConstraint("protocol = 'tcp'", name="ck_network_port_tcp_only"),
        sa.Index("ix_network_ports_port_state", "port", "state"),
    )

    op.create_table(
        "detected_services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "port_id", sa.Integer(), sa.ForeignKey("network_ports.id"),
            nullable=False, unique=True,
        ),
        sa.Column("name", sa.String(length=120), nullable=True),
        sa.Column("product", sa.String(length=200), nullable=True),
        sa.Column("version", sa.String(length=200), nullable=True),
        sa.Column("extra_info", sa.String(length=500), nullable=True),
        sa.Column("cpe", sa.String(length=500), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("vulnerability_intelligence_status", sa.String(length=30), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "cve_references",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("reference_urls", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_cve_reference_cvss_range",
        ),
    )
    op.create_index("ix_cve_references_cve_id", "cve_references", ["cve_id"], unique=True)

    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("network_scans.id"), nullable=False),
        sa.Column("port_id", sa.Integer(), sa.ForeignKey("network_ports.id"), nullable=True),
        sa.Column(
            "cve_id", sa.String(length=30),
            sa.ForeignKey("cve_references.cve_id"), nullable=True,
        ),
        sa.Column("classification", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("reference_urls", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "classification IN ('informational', 'potential', 'confirmed')",
            name="ck_vulnerability_finding_classification",
        ),
    )
    op.create_index(
        "ix_vulnerability_findings_scan_severity",
        "vulnerability_findings",
        ["scan_id", "severity"],
    )
    op.create_index(
        "ix_vulnerability_findings_cve_id",
        "vulnerability_findings",
        ["cve_id"],
    )

    op.create_table(
        "scan_configurations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("network_scans.id"),
            nullable=False, unique=True,
        ),
        sa.Column("profile", sa.String(length=20), nullable=False),
        sa.Column("options", sa.Text(), nullable=False),
        sa.Column("approved_networks", sa.Text(), nullable=False),
        sa.Column("authorization_statement", sa.String(length=300), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("profile = 'safe'", name="ck_scan_configuration_profile"),
    )

    op.create_table(
        "scan_audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("network_scans.id"), nullable=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("details", sa.String(length=1000), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_scan_audit_logs_scan_created",
        "scan_audit_logs",
        ["scan_id", "created_at"],
    )
    op.create_index("ix_scan_audit_logs_scan_id", "scan_audit_logs", ["scan_id"])
    op.create_index("ix_scan_audit_logs_user_id", "scan_audit_logs", ["user_id"])
    op.create_index("ix_scan_audit_logs_created_at", "scan_audit_logs", ["created_at"])


def downgrade():
    op.drop_table("scan_audit_logs")
    op.drop_table("scan_configurations")
    op.drop_table("vulnerability_findings")
    op.drop_index("ix_cve_references_cve_id", table_name="cve_references")
    op.drop_table("cve_references")
    op.drop_table("detected_services")
    op.drop_table("network_ports")
    op.drop_table("network_hosts")
    op.drop_index("ix_network_scans_created_at", table_name="network_scans")
    op.drop_index("ix_network_scans_status", table_name="network_scans")
    op.drop_index("ix_network_scans_user_id", table_name="network_scans")
    op.drop_table("network_scans")
