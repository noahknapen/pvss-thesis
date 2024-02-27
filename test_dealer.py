import unittest
from dealer import Dealer

class TestDealer(unittest.TestCase):
    def test_initialization(self):
        dealer = Dealer(3, 3, 5, 2, [])
        self.assertIsInstance(dealer, Dealer)
        
    def test_create_polynomial(self):
        dealer = Dealer(3, 3, 5, 2, [])
        (coeffs, pol) = dealer.create_polynomial("Hello world")

        self.assertEqual(len(coeffs), 3)
        for coeff in coeffs:
            self.assertIn(coeff, range(0, 5))

        self.assertEqual(pol.coef, coeffs)
        self.assertEqual(pol.degree, 3)

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