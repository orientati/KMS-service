"""create key_pairs table

Revision ID: a662591b3abc
Revises: 
Create Date: 2026-01-10 23:51:39.123456

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a662591b3abc'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'key_pairs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('kid', sa.String(length=255), nullable=False),
        sa.Column('private_key', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_key_pairs_id'), 'key_pairs', ['id'], unique=False)
    op.create_index(op.f('ix_key_pairs_kid'), 'key_pairs', ['kid'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_key_pairs_kid'), table_name='key_pairs')
    op.drop_index(op.f('ix_key_pairs_id'), table_name='key_pairs')
    op.drop_table('key_pairs')
