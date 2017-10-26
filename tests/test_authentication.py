import unittest
from app.models import User

class UserModelTestCase(unittest.TestCase):
    def test_password_setter(self):
        u = User(password = 'cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password = 'cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password = 'cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_salts_are_random(self):
        u = User(password = 'cat')
        u2 = User(password = 'cat')
        self.assertNotEqual(u.password_hash, u2.password_hash)

    # populate users with passwords
    passwords = ['cat', 'dog', 'meow', 'agent42', 'ruby732js.Ang', 'secretPassword', '123abc#$%@', 'AHGHja789@$%!58902689']
    users = []
    for password in passwords:
        users.append(User(password=password))

    def test_correct_password(self):
        for i in range(len(self.users)):
            self.assertTrue(self.users[i].verify_password(self.passwords[i]))

    def test_false_password(self):
        self.passwords.reverse()

        for i in range(len(self.users)):
            self.assertFalse(self.users[i].verify_password(self.passwords[i]))


