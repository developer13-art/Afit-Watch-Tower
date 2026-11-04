"""Core schema: camera registry, health, incidents, evidence, notifications, audit.

Revision ID: 0001_core_schema
Revises:
Create Date: 2026-10-29 00:00:00.000000

Generated from watchtower.models metadata; every table maps to proposal section 8.4.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:  # pragma: no cover
    pass

revision = "0001_core_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "camera_groups",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('code', sa.String(length=48), nullable=False, unique=True),
            sa.Column('name', sa.String(length=128), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('parent_id', sa.Integer(), sa.ForeignKey('camera_groups.id', ondelete='SET NULL'), nullable=True),
    )



    op.create_table(
        "camera_secrets",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('reference', sa.String(length=64), nullable=False, unique=True),
            sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
            sa.Column('key_id', sa.String(length=32), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
    )



    op.create_table(
        "monitoring_policies",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('code', sa.String(length=48), nullable=False, unique=True),
            sa.Column('name', sa.String(length=128), nullable=False),
            sa.Column('enabled', sa.Boolean(), nullable=False),
            sa.Column('detector_codes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('min_confidence', sa.Float(), nullable=False),
            sa.Column('analysis_fps', sa.Float(), nullable=False),
            sa.Column('zones', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('duplicate_window_seconds', sa.Integer(), nullable=False),
            sa.Column('severity', sa.String(length=64), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )



    op.create_table(
        "permissions",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('code', sa.String(length=96), nullable=False, unique=True),
            sa.Column('description', sa.Text(), nullable=True),
    )



    op.create_table(
        "roles",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('code', sa.String(length=48), nullable=False, unique=True),
            sa.Column('name', sa.String(length=128), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('is_administrative', sa.Boolean(), nullable=False),
    )



    op.create_table(
        "system_jobs",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('kind', sa.String(length=64), nullable=False),
            sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('state', sa.String(length=64), nullable=False),
            sa.Column('attempts', sa.Integer(), nullable=False),
            sa.Column('scheduled_for', sa.DateTime(timezone=True), nullable=False),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_error', sa.Text(), nullable=True),
    )

    op.create_index('ix_jobs_state_scheduled', 'system_jobs', ['state', 'scheduled_for'], unique=False)


    op.create_table(
        "users",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('username', sa.String(length=64), nullable=False, unique=True),
            sa.Column('display_name', sa.String(length=128), nullable=False),
            sa.Column('email', sa.String(length=256), nullable=True),
            sa.Column('phone', sa.String(length=32), nullable=True),
            sa.Column('password_hash', sa.String(length=256), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=False),
            sa.Column('failed_login_count', sa.Integer(), nullable=False),
            sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
            sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )



    op.create_table(
        "audit_logs",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('actor_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('actor_username', sa.String(length=64), nullable=True),
            sa.Column('action', sa.String(length=96), nullable=False),
            sa.Column('object_type', sa.String(length=48), nullable=True),
            sa.Column('object_id', sa.String(length=64), nullable=True),
            sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('outcome', sa.String(length=24), nullable=False),
            sa.Column('source_ip', sa.String(length=64), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index('ix_audit_action_created', 'audit_logs', ['action', 'created_at'], unique=False)
    op.create_index('ix_audit_actor_created', 'audit_logs', ['actor_id', 'created_at'], unique=False)
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'], unique=False)


    op.create_table(
        "camera_connection_profiles",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('host', sa.String(length=256), nullable=False),
            sa.Column('port', sa.Integer(), nullable=False),
            sa.Column('stream_path', sa.String(length=256), nullable=False),
            sa.Column('username', sa.String(length=128), nullable=True),
            sa.Column('secret_reference', sa.String(length=64), sa.ForeignKey('camera_secrets.reference', ondelete='SET NULL'), nullable=True),
            sa.Column('transport', sa.String(length=64), nullable=False),
            sa.Column('verified_in_vlc', sa.Boolean(), nullable=False),
            sa.Column('last_probe_result', sa.String(length=64), nullable=True),
            sa.Column('last_probe_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_check_constraint('ck_profile_port_range', 'camera_connection_profiles', 'port > 0 AND port <= 65535')
    op.create_index('ix_profiles_host_port', 'camera_connection_profiles', ['host', 'port'], unique=False)


    op.create_table(
        "role_permissions",
            sa.Column('role_id', sa.Integer(), sa.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True, nullable=False),
            sa.Column('permission_id', sa.Integer(), sa.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True, nullable=False),
    )



    op.create_table(
        "user_roles",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
            sa.Column('role_id', sa.Integer(), sa.ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
            sa.Column('camera_group_id', sa.Integer(), sa.ForeignKey('camera_groups.id', ondelete='CASCADE'), nullable=True),
    )

    op.create_unique_constraint('uq_user_role_scope', 'user_roles', ['user_id', 'role_id', 'camera_group_id'])
    op.create_index('ix_user_roles_user', 'user_roles', ['user_id'], unique=False)


    op.create_table(
        "cameras",
            sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
            sa.Column('code', sa.String(length=64), nullable=False, unique=True),
            sa.Column('display_name', sa.String(length=128), nullable=False),
            sa.Column('campus_location', sa.String(length=256), nullable=False),
            sa.Column('camera_group_id', sa.Integer(), sa.ForeignKey('camera_groups.id', ondelete='SET NULL'), nullable=True),
            sa.Column('model', sa.String(length=128), nullable=True),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('connection_profile_id', sa.Integer(), sa.ForeignKey('camera_connection_profiles.id', ondelete='SET NULL'), nullable=True),
            sa.Column('monitoring_policy_id', sa.Integer(), sa.ForeignKey('monitoring_policies.id', ondelete='SET NULL'), nullable=True),
            sa.Column('recording_policy', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('status', sa.String(length=64), nullable=False),
            sa.Column('desired_state', sa.String(length=24), nullable=False),
            sa.Column('is_registered', sa.Boolean(), nullable=False),
            sa.Column('last_successful_frame_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_error_code', sa.String(length=64), nullable=True),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('modified_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index('ix_cameras_group', 'cameras', ['camera_group_id'], unique=False)
    op.create_index('ix_cameras_location', 'cameras', ['campus_location'], unique=False)
    op.create_index('ix_cameras_status', 'cameras', ['status'], unique=False)


    op.create_table(
        "camera_health_events",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='CASCADE'), nullable=False),
            sa.Column('previous_status', sa.String(length=48), nullable=True),
            sa.Column('status', sa.String(length=48), nullable=False),
            sa.Column('reason_code', sa.String(length=64), nullable=False),
            sa.Column('detail', sa.Text(), nullable=True),
            sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('duration_seconds', sa.Float(), nullable=True),
            sa.Column('notified', sa.Boolean(), nullable=False),
    )

    op.create_index('ix_health_camera_observed', 'camera_health_events', ['camera_id', 'observed_at'], unique=False)


    op.create_table(
        "camera_stream_sessions",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='CASCADE'), nullable=False),
            sa.Column('pid', sa.Integer(), nullable=True),
            sa.Column('state', sa.String(length=32), nullable=False),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_frame_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('frames_received', sa.Integer(), nullable=False),
            sa.Column('frames_dropped', sa.Integer(), nullable=False),
            sa.Column('decode_failures', sa.Integer(), nullable=False),
            sa.Column('retry_count', sa.Integer(), nullable=False),
            sa.Column('viewer_count', sa.Integer(), nullable=False),
            sa.Column('measured_fps', sa.Float(), nullable=False),
            sa.Column('terminal', sa.Boolean(), nullable=False),
            sa.Column('termination_reason', sa.String(length=64), nullable=True),
    )

    op.create_index('ix_sessions_camera_started', 'camera_stream_sessions', ['camera_id', 'started_at'], unique=False)


    op.create_table(
        "detection_events",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='CASCADE'), nullable=False),
            sa.Column('policy_id', sa.Integer(), sa.ForeignKey('monitoring_policies.id', ondelete='SET NULL'), nullable=True),
            sa.Column('category', sa.String(length=64), nullable=False),
            sa.Column('confidence', sa.Float(), nullable=False),
            sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
            sa.Column('status', sa.String(length=64), nullable=False),
            sa.Column('dedupe_key', sa.String(length=160), nullable=True),
            sa.Column('suppressed', sa.Boolean(), nullable=False),
            sa.Column('reviewed_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('review_note', sa.Text(), nullable=True),
    )

    op.create_unique_constraint('uq_event_dedupe', 'detection_events', ['camera_id', 'dedupe_key'])
    op.create_index('ix_events_status_occurred', 'detection_events', ['status', 'occurred_at'], unique=False)


    op.create_table(
        "incidents",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('reference', sa.String(length=32), nullable=False, unique=True),
            sa.Column('title', sa.String(length=256), nullable=False),
            sa.Column('summary', sa.Text(), nullable=True),
            sa.Column('category', sa.String(length=64), nullable=False),
            sa.Column('severity', sa.String(length=64), nullable=False),
            sa.Column('status', sa.String(length=64), nullable=False),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='SET NULL'), nullable=True),
            sa.Column('origin_event_id', sa.Integer(), sa.ForeignKey('detection_events.id', ondelete='SET NULL'), nullable=True),
            sa.Column('campus_location', sa.String(length=256), nullable=True),
            sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('assigned_to', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('escalated_to', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('resolution', sa.Text(), nullable=True),
            sa.Column('outcome', sa.String(length=64), nullable=True),
            sa.Column('created_by', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index('ix_incidents_camera', 'incidents', ['camera_id'], unique=False)
    op.create_index('ix_incidents_status_occurred', 'incidents', ['status', 'occurred_at'], unique=False)


    op.create_table(
        "evidence_assets",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=True),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='SET NULL'), nullable=True),
            sa.Column('detection_event_id', sa.Integer(), sa.ForeignKey('detection_events.id', ondelete='SET NULL'), nullable=True),
            sa.Column('kind', sa.String(length=24), nullable=False),
            sa.Column('filename', sa.String(length=512), nullable=False),
            sa.Column('storage_key', sa.String(length=512), nullable=False, unique=True),
            sa.Column('content_type', sa.String(length=64), nullable=False),
            sa.Column('byte_size', sa.Integer(), nullable=False),
            sa.Column('sha256', sa.String(length=64), nullable=False),
            sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )

    op.create_index('ix_evidence_incident', 'evidence_assets', ['incident_id'], unique=False)


    op.create_table(
        "incident_actions",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
            sa.Column('action', sa.String(length=48), nullable=False),
            sa.Column('note', sa.Text(), nullable=True),
            sa.Column('actor_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index('ix_actions_incident', 'incident_actions', ['incident_id'], unique=False)


    op.create_table(
        "notifications",
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('kind', sa.String(length=48), nullable=False),
            sa.Column('title', sa.String(length=200), nullable=False),
            sa.Column('body', sa.Text(), nullable=False),
            sa.Column('severity', sa.String(length=64), nullable=False),
            sa.Column('channel', sa.String(length=64), nullable=False),
            sa.Column('state', sa.String(length=64), nullable=False),
            sa.Column('dedupe_key', sa.String(length=160), nullable=True),
            sa.Column('camera_id', sa.Uuid(as_uuid=True), sa.ForeignKey('cameras.id', ondelete='CASCADE'), nullable=True),
            sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=True),
            sa.Column('event_id', sa.Integer(), sa.ForeignKey('detection_events.id', ondelete='CASCADE'), nullable=True),
            sa.Column('recipient_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('failure_reason', sa.String(length=256), nullable=True),
    )

    op.create_unique_constraint('uq_notification_dedupe', 'notifications', ['dedupe_key', 'recipient_id', 'channel'])
    op.create_index('ix_notifications_recipient_state', 'notifications', ['recipient_id', 'state'], unique=False)


def downgrade() -> None:
    op.drop_table("notifications")
    op.drop_table("incident_actions")
    op.drop_table("evidence_assets")
    op.drop_table("incidents")
    op.drop_table("detection_events")
    op.drop_table("camera_stream_sessions")
    op.drop_table("camera_health_events")
    op.drop_table("cameras")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("camera_connection_profiles")
    op.drop_table("audit_logs")
    op.drop_table("users")
    op.drop_table("system_jobs")
    op.drop_table("roles")
    op.drop_table("permissions")
    op.drop_table("monitoring_policies")
    op.drop_table("camera_secrets")
    op.drop_table("camera_groups")
