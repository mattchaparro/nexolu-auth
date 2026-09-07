"""Esquema inicial: identidades, credenciales, cuentas vinculadas, sesiones e intentos

Revision ID: a1c4e7b90f22
Revises:
Create Date: 2026-09-07 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1c4e7b90f22'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'identities',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('email', sa.String(length=191), nullable=False),
        sa.Column('full_name', sa.String(length=128), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )

    op.create_table(
        'credentials',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('identity_id', sa.String(length=32), nullable=False),
        sa.Column('type', sa.String(length=32), nullable=False),
        sa.Column('secret', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('password_changed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['identity_id'], ['identities.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('identity_id', 'type', name='uq_credential_identity_type'),
    )
    op.create_index(op.f('ix_credentials_identity_id'), 'credentials', ['identity_id'])

    op.create_table(
        'linked_accounts',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('identity_id', sa.String(length=32), nullable=False),
        sa.Column('product', sa.String(length=64), nullable=False),
        sa.Column('external_user_id', sa.String(length=64), nullable=True),
        sa.Column('external_email', sa.String(length=191), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['identity_id'], ['identities.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('identity_id', 'product', name='uq_linked_account_identity_product'),
        sa.UniqueConstraint('product', 'external_user_id', name='uq_linked_account_product_user'),
    )
    op.create_index(op.f('ix_linked_accounts_identity_id'), 'linked_accounts', ['identity_id'])

    op.create_table(
        'auth_sessions',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('identity_id', sa.String(length=32), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['identity_id'], ['identities.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index(op.f('ix_auth_sessions_identity_id'), 'auth_sessions', ['identity_id'])
    op.create_index('ix_auth_sessions_identity', 'auth_sessions', ['identity_id'])

    op.create_table(
        'login_attempts',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('email', sa.String(length=191), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('succeeded', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_login_attempts_ip', 'login_attempts', ['ip', 'created_at'])
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_login_attempts_email', table_name='login_attempts')
    op.drop_index('ix_login_attempts_ip', table_name='login_attempts')
    op.drop_table('login_attempts')

    op.drop_index('ix_auth_sessions_identity', table_name='auth_sessions')
    op.drop_index(op.f('ix_auth_sessions_identity_id'), table_name='auth_sessions')
    op.drop_table('auth_sessions')

    op.drop_index(op.f('ix_linked_accounts_identity_id'), table_name='linked_accounts')
    op.drop_table('linked_accounts')

    op.drop_index(op.f('ix_credentials_identity_id'), table_name='credentials')
    op.drop_table('credentials')

    op.drop_table('identities')
