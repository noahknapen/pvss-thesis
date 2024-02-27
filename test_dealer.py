import unittest
from unittest.mock import Mock
from dealer import Dealer
from Cryptodome.Protocol.SecretSharing import _Element
from numpy.polynomial.polynomial import Polynomial 

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
        mock = Mock()
        mock.public_key = 3
        mock2 = Mock()
        mock2.public_key = 5
        mock3 = Mock()
        mock3.public_key = 7
        dealer = Dealer(3, 3, 5, 2, [mock, mock2, mock3])
        coeffs = [_Element(1), _Element(2), _Element(3)]
        encrypted_shares = dealer.generate_encrypted_shares(coeffs)

        self.assertEqual(len(encrypted_shares), 3)
        for encrypted_share in encrypted_shares:
            self.assertIsInstance(encrypted_share[0], int)
            self.assertIsInstance(encrypted_share[1], _Element)
    
    def test_pi_pdl(self):
        mock = Mock()
        mock.public_key = 3
        mock2 = Mock()
        mock2.public_key = 5
        mock3 = Mock()
        mock3.public_key = 7
        dealer = Dealer(3, 3, 5, 2, [mock, mock2, mock3])
        (encrypted_r_x, z_x) = dealer.pi_pdl(Polynomial([1,2,3]), [(1, _Element(1)), (2, _Element(2)), (3, _Element(3))])

        self.assertEqual(len(encrypted_r_x), 3)
        self.assertEqual(z_x.degree(), 2)
        

if __name__ == '__main__':
    unittest.main()