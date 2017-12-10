import hashlib
from datetime import datetime

from ..exceptions import ValidationError
from flask import current_app, request, url_for
from flask_login import AnonymousUserMixin, UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from werkzeug.security import check_password_hash, generate_password_hash

from .. import db, login_manager
from .role import Role, Permission 
from .post import Post


class ExternalAuthProvider(db.Model):
    __tablename__ = 'external_authentication_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    user_logins = db.relationship('UserExternalLogin',
                                backref='external_auth_provider',
                                lazy='dynamic')

    @staticmethod
    def insert_auth_providers():
        providers = ['facebook', 'google', 'linkedin', 'github']
        for p in providers:
            provider = ExternalAuthProvider.query.filter_by(name=p).first()
            if provider is None:
                provider = ExternalAuthProvider(name=p)
                db.session.add(provider)
        db.session.commit()

    def __repr__(self):
        return '<External Authentication Provider: {}>'.format(self.name)


class UserExternalLogin(db.Model):
    __tablename__ = 'user_external_login'
    id = db.Column(db.Integer, primary_key=True)
    user_account_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                                nullable=False)
    external_auth_provider_id = db.Column(db.Integer,
                        db.ForeignKey('external_authentication_provider.id'),
                        nullable=False)

    # information acquired from external authentication service
    external_user_id = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(64), nullable=True)
    first_name = db.Column(db.String(30), nullable=True)
    last_name = db.Column(db.String(30), nullable=True)
    email = db.Column(db.String(64), nullable=True)
    login_name = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return '''<User External Login: [
            id: {},
            user_account_id: {},
            external_auth_provider: {},
            external_user_id: {},
            name: {},
            first_name: {},
            last_name: {},
            email: {},
            login_name: {}
            ]>
            '''.format(self.id, self.user_account_id,
                    self.external_auth_provider, self.external_user_id,
                    self.name, self.first_name, self.last_name,
                    self.email, self.login_name)