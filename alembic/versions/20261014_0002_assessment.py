"""add vulnerability assessment persistence

Revision ID: 20261014_0002
Revises: 20261005_0001
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa

revision = "20261014_0002"
down_revision = "20261005_0001"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("open_ports") as batch:
        batch.add_column(sa.Column("service_version", sa.String(255), nullable=True))
        batch.add_column(sa.Column("evidence", sa.Text(), nullable=True))
    op.create_table("vulnerability_references",
        sa.Column("cve_id", sa.String(32), primary_key=True), sa.Column("cpe_name", sa.String(1024)),
        sa.Column("payload", sa.Text(), nullable=False), sa.Column("source", sa.String(64), nullable=False),
        sa.Column("last_updated", sa.DateTime(timezone=True), nullable=False), sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_vulnerability_references_cpe_name", "vulnerability_references", ["cpe_name"])
    op.create_table("vulnerability_findings",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("device_id", sa.Integer(), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("port_scans.id")), sa.Column("open_port_id", sa.Integer(), sa.ForeignKey("open_ports.id")),
        sa.Column("fingerprint", sa.String(255), nullable=False), sa.Column("finding_type", sa.String(32), nullable=False), sa.Column("severity", sa.String(16), nullable=False), sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False), sa.Column("cve_id", sa.String(32)), sa.Column("cvss_score", sa.Float()), sa.Column("cvss_version", sa.String(16)),
        sa.Column("service", sa.String(64)), sa.Column("detected_version", sa.String(255)), sa.Column("port", sa.Integer()), sa.Column("protocol", sa.String(8)),
        sa.Column("evidence", sa.Text(), nullable=False), sa.Column("description", sa.Text(), nullable=False), sa.Column("remediation", sa.Text(), nullable=False), sa.Column("reference_url", sa.String(1024)), sa.Column("source", sa.String(64), nullable=False),
        sa.Column("first_detected", sa.DateTime(timezone=True), nullable=False), sa.Column("last_detected", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "fingerprint", name="uq_finding_device_fingerprint"))
    for column in ("device_id", "scan_id", "open_port_id", "finding_type", "severity", "cve_id", "last_detected"):
        op.create_index(f"ix_vulnerability_findings_{column}", "vulnerability_findings", [column])


def downgrade():
    op.drop_table("vulnerability_findings")
    op.drop_table("vulnerability_references")
    with op.batch_alter_table("open_ports") as batch:
        batch.drop_column("evidence")
        batch.drop_column("service_version")
