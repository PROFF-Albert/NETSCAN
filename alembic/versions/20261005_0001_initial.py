"""initial NetWatch schema

Revision ID: 20261005_0001
Revises:
Create Date: 2026-10-05
"""
from alembic import op
import sqlalchemy as sa

revision = "20261005_0001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("devices", sa.Column("id",sa.Integer,primary_key=True),sa.Column("hostname",sa.String(255)),sa.Column("ip_address",sa.String(64),nullable=False),sa.Column("mac_address",sa.String(32)),sa.Column("vendor",sa.String(255)),sa.Column("status",sa.String(16),nullable=False),sa.Column("first_seen",sa.DateTime,nullable=False),sa.Column("last_seen",sa.DateTime,nullable=False));op.create_index("ix_devices_ip_address","devices",["ip_address"],unique=True)
    op.create_table("scans",sa.Column("id",sa.Integer,primary_key=True),sa.Column("scan_time",sa.DateTime,nullable=False),sa.Column("devices_found",sa.Integer,nullable=False))
    op.create_table("settings",sa.Column("id",sa.Integer,primary_key=True),sa.Column("scan_interval",sa.Integer,nullable=False),sa.Column("ping_timeout",sa.Float,nullable=False),sa.Column("network_range",sa.String(64),nullable=False),sa.Column("refresh_rate",sa.Integer,nullable=False))
    op.create_table("uptime_logs",sa.Column("id",sa.Integer,primary_key=True),sa.Column("device_id",sa.Integer,sa.ForeignKey("devices.id"),nullable=False),sa.Column("timestamp",sa.DateTime,nullable=False),sa.Column("response_time",sa.Float),sa.Column("status",sa.String(16),nullable=False));op.create_index("ix_uptime_logs_device_id","uptime_logs",["device_id"])
    op.create_table("port_scans",sa.Column("id",sa.Integer,primary_key=True),sa.Column("device_id",sa.Integer,sa.ForeignKey("devices.id"),nullable=False),sa.Column("scan_type",sa.String(16),nullable=False),sa.Column("timestamp",sa.DateTime,nullable=False),sa.Column("status",sa.String(16),nullable=False),sa.Column("total_ports",sa.Integer,nullable=False),sa.Column("scanned_ports",sa.Integer,nullable=False),sa.Column("open_ports_found",sa.Integer,nullable=False),sa.Column("timeout_seconds",sa.Float,nullable=False),sa.Column("worker_count",sa.Integer,nullable=False),sa.Column("error",sa.Text));op.create_index("ix_port_scans_device_id","port_scans",["device_id"]);op.create_index("ix_port_scans_timestamp","port_scans",["timestamp"]);op.create_index("ix_port_scans_status","port_scans",["status"])
    op.create_table("open_ports",sa.Column("id",sa.Integer,primary_key=True),sa.Column("scan_id",sa.Integer,sa.ForeignKey("port_scans.id"),nullable=False),sa.Column("port",sa.Integer,nullable=False),sa.Column("protocol",sa.String(8),nullable=False),sa.Column("service",sa.String(64),nullable=False),sa.Column("banner",sa.Text),sa.Column("state",sa.String(16),nullable=False));op.create_index("ix_open_ports_scan_id","open_ports",["scan_id"]);op.create_index("ix_open_ports_port","open_ports",["port"]);op.create_index("ix_open_ports_state","open_ports",["state"])

def downgrade():
    op.drop_table("open_ports");op.drop_table("port_scans");op.drop_table("uptime_logs");op.drop_table("settings");op.drop_table("scans");op.drop_table("devices")
