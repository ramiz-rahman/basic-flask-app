import unittest
import time
from datetime import datetime
from app import create_app, db
from app.models import User, AnonymousUser, Role, Permission

class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password='cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password='cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password='cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_salts_are_random(self):
        u = User(password='cat')
        u2 = User(password='cat')
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_valid_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmatin_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))

    def test_valid_reset_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertTrue(u.reset_password(token, 'dog'))
        self.assertTrue(u.verify_password('dog'))

    def test_invalid_reset_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_reset_token()
        self.assertFalse(u2.reset_password(token, 'horse'))
        self.assertTrue(u2.verify_password('dog'))

    def test_valid_email_change_token(self):
        u = User(email='john@example.com', password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_email_change_token('mark@anthony.com')
        self.assertTrue(u.change_email(token))
        self.assertEqual(u.email, 'mark@anthony.com')

    def test_invalid_email_change_token(self):
        u1 = User(email='julius@caesar.com')
        u2 = User(email='henry@king.net')
        db.session.add_all([u1, u2])
        db.session.commit()
        token = u1.generate_email_change_token('mark@anthony.com')
        self.assertFalse(u2.change_email(token))
        self.assertEqual(u2.email, 'henry@king.net')

    def test_duplicate_email_change_token(self):
        u1 = User(email='julius@caesar.com')
        u2 = User(email='henry@king.net')
        db.session.add_all([u1, u2])
        db.session.commit()
        token = u2.generate_email_change_token('julius@caesar.com')
        self.assertFalse(u2.change_email(token))
        self.assertEqual(u2.email, 'henry@king.net')

    def test_roles_and_permissions(self):
        u = User(email='julius@caesar.com')
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))
    
    def test_timestamps(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        self.assertLess(
            (datetime.utcnow() - u.member_since).total_seconds(), 3)
        self.assertLess(
            (datetime.utcnow() - u.last_seen).total_seconds(), 3)

    def test_ping(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        time.sleep(2)
        last_seen_before = u.last_seen
        u.ping()
        self.assertGreater(u.last_seen,last_seen_before)