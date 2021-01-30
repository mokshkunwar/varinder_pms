import unittest
from main import check_pawned, check_password_complexity
import bcrypt

class MyTestCase(unittest.TestCase):

    def setUp(self):
        self.password1 = 'Password@123'

        self.password2 = 'Aijkm5555@@h'

        self.password3 = 'Hello1234'

        self.password4 = "withlowerchars@123"

    def test_hibp(self):
        # Check if the created password is leaked or not
        # Returns true if password is leaked
        self.assertTrue(check_pawned(self.password1))

        # return false since the password isnt leaked
        self.assertFalse(check_pawned(self.password2))

    def test_hash_password(self):
        raw_password = bytes(self.password1, 'utf-8')
        salt = bcrypt.gensalt(12)
        hashed_password = bcrypt.hashpw(raw_password, salt)
        # decrypt password and check if its the same or not
        response = bcrypt.checkpw(self.password1.encode('utf-8'), hashed_password)
        self.assertTrue(response)

    def test_check_complexity_fail(self):
        # failing because it does not contain any special chars
        self.assertFalse(check_password_complexity(self.password3))

        # failing because it does not contain uppercase chars
        self.assertFalse(check_password_complexity(self.password4))

    def test_check_complexity_pass(self):
        # passing the criteria
        self.assertTrue(check_password_complexity(self.password1))


    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
