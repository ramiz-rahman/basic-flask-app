"""empty message

Revision ID: bd2afdaafbd2
Revises: 48589646af9b
Create Date: 2017-12-10 20:12:42.027087

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'bd2afdaafbd2'
down_revision = '48589646af9b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('external_authentication_provider',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_external_login',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_account_id', sa.Integer(), nullable=False),
    sa.Column('external_auth_provider_id', sa.Integer(), nullable=False),
    sa.Column('external_user_id', sa.String(length=255), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('first_name', sa.String(length=30), nullable=True),
    sa.Column('last_name', sa.String(length=30), nullable=True),
    sa.Column('email', sa.String(length=64), nullable=True),
    sa.Column('login_name', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['external_auth_provider_id'], ['external_authentication_provider.id'], ),
    sa.ForeignKeyConstraint(['user_account_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('facebook_accounts')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('facebook_accounts',
    sa.Column('user_id', mysql.INTEGER(display_width=11), autoincrement=False, nullable=False),
    sa.Column('facebook_id', mysql.VARCHAR(length=30), nullable=True),
    sa.Column('first_name', mysql.VARCHAR(length=64), nullable=True),
    sa.Column('last_name', mysql.VARCHAR(length=64), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='facebook_accounts_ibfk_1'),
    sa.PrimaryKeyConstraint('user_id'),
    mysql_default_charset='utf8',
    mysql_engine='InnoDB'
    )
    op.drop_table('user_external_login')
    op.drop_table('external_authentication_provider')
    # ### end Alembic commands ###
