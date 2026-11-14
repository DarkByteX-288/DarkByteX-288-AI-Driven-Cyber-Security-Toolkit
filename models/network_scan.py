"""Persistence models for authorized network vulnerability assessments."""

from datetime import datetime, timezone

from . import db


def utc_now():
    return datetime.now(timezone.utc)


class NetworkScan(db.Model):
    __tablename__ = "network_scans"
    __table_args__ = (
        db.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="ck_network_scan_status",
        ),
        db.CheckConstraint("progress >= 0 AND progress <= 100", name="ck_network_scan_progress"),
        db.CheckConstraint("profile = 'safe'", name="ck_network_scan_profile"),
        db.CheckConstraint("authorization_confirmed = 1", name="ck_network_scan_authorized"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    target = db.Column(db.String(253), nullable=False)
    resolved_targets = db.Column(db.Text, nullable=False)
    ports = db.Column(db.Text, nullable=False)
    profile = db.Column(db.String(20), nullable=False, default="safe")
    authorization_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(20), nullable=False, default="queued", index=True)
    progress = db.Column(db.Integer, nullable=False, default=0)
    phase = db.Column(db.String(40), nullable=False, default="queued")
    error_message = db.Column(db.String(500), nullable=True)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    user = db.relationship("User", back_populates="network_scans")
    hosts = db.relationship(
        "NetworkHost", back_populates="scan", cascade="all, delete-orphan", order_by="NetworkHost.address"
    )
    configuration = db.relationship(
        "ScanConfiguration", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    findings = db.relationship(
        "VulnerabilityFinding", back_populates="scan", cascade="all, delete-orphan"
    )


class NetworkHost(db.Model):
    __tablename__ = "network_hosts"
    __table_args__ = (
        db.UniqueConstraint("scan_id", "address", name="uq_network_host_scan_address"),
        db.Index("ix_network_hosts_scan_state", "scan_id", "state"),
    )

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("network_scans.id"), nullable=False)
    address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(253), nullable=True)
    state = db.Column(db.String(20), nullable=False, default="unknown")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    scan = db.relationship("NetworkScan", back_populates="hosts")
    ports = db.relationship(
        "NetworkPort", back_populates="host", cascade="all, delete-orphan", order_by="NetworkPort.port"
    )


class NetworkPort(db.Model):
    __tablename__ = "network_ports"
    __table_args__ = (
        db.UniqueConstraint("host_id", "protocol", "port", name="uq_network_port_host_protocol_port"),
        db.CheckConstraint("port >= 1 AND port <= 65535", name="ck_network_port_range"),
        db.CheckConstraint("protocol = 'tcp'", name="ck_network_port_tcp_only"),
        db.Index("ix_network_ports_port_state", "port", "state"),
    )

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("network_hosts.id"), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(8), nullable=False, default="tcp")
    state = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(80), nullable=True)

    host = db.relationship("NetworkHost", back_populates="ports")
    service = db.relationship(
        "DetectedService", back_populates="port", uselist=False, cascade="all, delete-orphan"
    )


class DetectedService(db.Model):
    __tablename__ = "detected_services"

    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(
        db.Integer, db.ForeignKey("network_ports.id"), nullable=False, unique=True
    )
    name = db.Column(db.String(120), nullable=True)
    product = db.Column(db.String(200), nullable=True)
    version = db.Column(db.String(200), nullable=True)
    extra_info = db.Column(db.String(500), nullable=True)
    cpe = db.Column(db.String(500), nullable=True)
    confidence = db.Column(db.Integer, nullable=True)
    vulnerability_intelligence_status = db.Column(
        db.String(30), nullable=False, default="not_applicable"
    )
    detected_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    port = db.relationship("NetworkPort", back_populates="service")


class CVEReference(db.Model):
    __tablename__ = "cve_references"
    __table_args__ = (
        db.CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_cve_reference_cvss_range",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=False)
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_version = db.Column(db.String(8), nullable=True)
    severity = db.Column(db.String(20), nullable=False, default="Unknown")
    reference_urls = db.Column(db.Text, nullable=False, default="[]")
    source = db.Column(db.String(40), nullable=False, default="NVD")
    retrieved_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    findings = db.relationship("VulnerabilityFinding", back_populates="cve_reference")


class VulnerabilityFinding(db.Model):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        db.CheckConstraint(
            "classification IN ('informational', 'potential', 'confirmed')",
            name="ck_vulnerability_finding_classification",
        ),
        db.Index("ix_vulnerability_findings_scan_severity", "scan_id", "severity"),
        db.Index("ix_vulnerability_findings_cve_id", "cve_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("network_scans.id"), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey("network_ports.id"), nullable=True)
    cve_id = db.Column(db.String(30), db.ForeignKey("cve_references.cve_id"), nullable=True)
    classification = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="Informational")
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_version = db.Column(db.String(8), nullable=True)
    source = db.Column(db.String(80), nullable=False)
    reference_urls = db.Column(db.Text, nullable=False, default="[]")
    remediation = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    scan = db.relationship("NetworkScan", back_populates="findings")
    port = db.relationship("NetworkPort")
    cve_reference = db.relationship("CVEReference", back_populates="findings")


class ScanConfiguration(db.Model):
    __tablename__ = "scan_configurations"
    __table_args__ = (
        db.CheckConstraint("profile = 'safe'", name="ck_scan_configuration_profile"),
    )

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(
        db.Integer, db.ForeignKey("network_scans.id"), nullable=False, unique=True
    )
    profile = db.Column(db.String(20), nullable=False)
    options = db.Column(db.Text, nullable=False)
    approved_networks = db.Column(db.Text, nullable=False)
    authorization_statement = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    scan = db.relationship("NetworkScan", back_populates="configuration")


class ScanAuditLog(db.Model):
    __tablename__ = "scan_audit_logs"
    __table_args__ = (db.Index("ix_scan_audit_logs_scan_created", "scan_id", "created_at"),)

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("network_scans.id"), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    event_type = db.Column(db.String(40), nullable=False)
    details = db.Column(db.String(1000), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    scan = db.relationship("NetworkScan")
    user = db.relationship("User")
