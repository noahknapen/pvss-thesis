import unittest
from dealer import Dealer

class TestDealer(unittest.TestCase):
    def test_initialization(self):
        dealer = Dealer(3, 3, 5, 2, [])
        self.assertIsInstance(dealer, Dealer)
        
    def test_create_polynomial(self):
        dealer = Dealer(3, 3, 5, 2, [])
        (coeffs, pol) = dealer.create_polynomial("Hello world") #! Adapted polyutils.py line 134 by appending dtype=object or else it threw an error

        self.assertEqual(len(coeffs), 3)
        for i in range(1, len(coeffs)):
            self.assertIn(coeffs[i]._value, range(5))

        self.assertEqual(pol.degree(), 2)
        self.assertEqual(len(pol.coef), 3)
        for i in range(3):
            self.assertEqual(pol.coef[i], coeffs[i])

    def test_generate_encrypted_shares(self):
        dealer = Dealer(3, 3, 5, 2, []) # TODO: Need parties for this
        coeffs = [1, 2, 3, 4, 5]
        encrypted_shares = dealer.generate_encrypted_shares(coeffs)

        self.assertEqual(len(encrypted_shares), 3)
        for encrypted_share in encrypted_shares:
            self.assertIsInstance(encrypted_share[0], int)
            self.assertIsInstance(encrypted_share[1], int)
        

if __name__ == '__main__':
    unittest.main()