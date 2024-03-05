from Cryptodome.Random.random import randint
from Cryptodome.Hash import SHA3_256
from numpy.polynomial.polynomial import Polynomial 
from numpy.polynomial.polynomial import polyval

class Dealer:
    def __init__(self, n, t, q, g, parties):
        """Initialize the dealer with the necessary parameters

        Args:
            n (integer):
                The number of parties
            t (integer):
                The number of parties needed to reconstruct the secret
            q (integer):
                The prime number denoting the order of the group Z_p
            g (integer):
                The generator of the cyclic group G of prime order q
            parties (list (Party)):
                The parties, assumed to be sorted on `Party().number`
        """

        self.n = n
        self.t = t
        self.q = q
        self.generator = g
        self.parties = parties
        self.secret = None

    def share_secret(self, secret):
        """Given the secret to share, broadcast the encrypted shares and corresponding proof to verify these shares

        Args:
            secret (integer):
                A secret in Z_p with a sufficient amount of entropy compared to previous secrets
        """
        self.secret = secret
        (coefficients, f_x) = self.create_polynomial(secret)
        encrypted_share_pairs = self.generate_encrypted_shares(coefficients)
        pi_share = self.pi_pdl(f_x, encrypted_share_pairs)
        self.broadcast(encrypted_share_pairs, pi_share)
           
    def create_polynomial(self, secret):
        """Conform with the Shamir secret sharing scheme, create a polynomial with random coefficients in GF(2^128): p(x) = \sum_{i=0}^{k-1} c_i * x^i where c_0 is the encoded secret
        
        Args:
            secret (integer):
                The secret to be encoded in the first coefficient of the polynomial

        Returns:
            result (tuple (list (integer), Polynomial))
                A tuple consisting of the coefficients and the polynomial, respectively, with the first coefficent being the secret
        """

        coeffs = [secret]
        coeffs += [randint(0, self.q-1) for _ in range(self.t)]
        polynomial = Polynomial(coeffs)

        return (coeffs, polynomial) 
 
    def generate_encrypted_shares(self, coefficients):
        """Given a list of coefficients of a polynomial, generate the encrypted shares for each party where each share is encrypted in an ElGamal-like manner

        Args:
            coefficients (list (integer)):
                A list of coefficients belonging to a polynomial

        Returns:
            result (list (tuple(integer, integer)))
                A list of tuples with each first element being the index `i` of the party, starting from 1 
                and the second element the encrypted share computed as `party_i_pub_key^f_i mod q` with `f_i` being the evaluation in `i` of the polynomial `f` to which the coefficients belong
        """
        encrypted_share_pairs = []
        
        for i in range(1, self.n+1):
            share = int(polyval(i, coefficients)) # share[i] = f(i)
            encrypted_share_pairs.append((i, pow(self.parties[i-1].public_key, share, self.q))) #? The power should here be in base q, right?

        return encrypted_share_pairs
  
    def pi_pdl(self, polynomial, encrypted_share_pairs):
        """Given a polynomial and encrypted shares along with their index, generate a NIZK proof of knowledge so that the validity of the encrypted shares may be verified
        For this purpose, it generates a polynomial `z(x) = r(x) + d*f(x)` 
        with `r(x)` a random polynomial in Z_q, `f(x)` the provided polynomial and `d` a random oracle value based on the encrypted shares and encrypted `r(i)` evaluations

        Arguments:
            polynomial (Polynomial):
                The witness polynomial `f` of which the knowledge has to be proven without exposing the polynomial itself to other parties
            encrypted_share_pairs (list (integer, integer)):
            A list of tuples with each first element being the index `i` of the party, starting from 1 
            and the second element the encrypted share computed as `party_i_pub_key^f_i mod q` with `f_i` being the evaluation in `i` of the polynomial `f` to which the coefficients belong
        
        Returns:
            result (tuple (list (integer), Polynomial)):
                A tuple with the first element being a list of the encrypted `r(i)` evaluations and the second element the polynomial `z(x)` as described above
        """
        (r_x_coeffs, r_x) = self.create_polynomial(randint(0, self.q-1))
        encrypted_r_x = []

        for i in range(len(encrypted_share_pairs)):
            r_i = int(polyval(encrypted_share_pairs[i][0], r_x_coeffs)) # Evaluate r(x) in the index of each party (1 through n)
            encrypted_r_x.append(pow(self.parties[i].public_key, r_i, self.q))

        args = [encrypted_share_pair[1] for encrypted_share_pair in encrypted_share_pairs] + encrypted_r_x
        d = self.get_random_oracle_value(args)

        d_polynomial = self.multiply_polynomial(d, polynomial)
        z_x = self.add_polynomial(r_x, d_polynomial)

        return (d, z_x)

    def multiply_polynomial(self, d, polynomial):
        """Given an integer and a polynomial, return the multiplication

        Arguments:
            d (integer):
                The integer to be multiplied with the polynomial
            polynomial (Polynomial):
                The polynomial to be multiplied with the integer

        Returns:
            result (Polynomial):
                The polynomial of which the coefficients are calculated as `result_coeff[i] = d*polynomial_coeff[i] mod q`
        """
        multiplied_coeffs = []

        for coeff in polynomial.coef:
            multiplied_coeffs.append((d*coeff) % self.q)

        return Polynomial(multiplied_coeffs)        

    def add_polynomial(self, pol1, pol2):
        """Given two polynomials, return the addition

        Arguments:
            pol1 (Polynomial):
                The polynomial to be added with the other polynomial
            pol2 (Polynomial):
                The polynomial to be added with the other polynomial

        Returns:
            result (Polynomial):
                The polynomial of which the coefficients are calculated as `result_coeff[i] = pol1_coeff[i]+pol2_coeff[i] mod q`
        """
        added_coeffs = []
        
        for i in range(pol1.degree()+1):
            added_coeffs.append((pol1.coef[i] + pol2.coef[i]) % self.q)

        return Polynomial(added_coeffs)
    
    def get_random_oracle_value(self, lst):
        """Given a list of arguments, return a random oracle value based on this list

        Arguments:
            lst (list (any)):
                The list holding all arguments that should be given to the random oracle

        Returns:
            result (integer):
                The random oracle value calculated based on the provided arguments
        """
        data = ""

        for value in lst:
            data += str(value)

        binary_data = data.encode('utf-8')
        hash_class = SHA3_256.new()
        hash_class.update(binary_data)
        binary_hash = hash_class.digest()
        return int.from_bytes(binary_hash, "little")

    def broadcast(self, encrypted_shares, pi_share):
        """Given the encrypted shares for each party and the NIZK proof of knowledge, broadcast this to all parties on the network

        Arguments:
            encrypted_shares (list (tuple(integer, integer)))
                A list of tuples with each first element being the index `i` of the party, starting from 1 
                and the second element the encrypted share computed as `party_i_pub_key^f_i mod q` with `f_i` being the evaluation in `i` of the polynomial `f` to which the coefficients belong
            pi_share (tuple (list (integer), Polynomial)):
                A tuple with the first element being a list of the encrypted `r(i)` evaluations and the second element the polynomial `z(x)` as described above
        """
        for party in self.parties:
            party.receive_shares_and_dealer_proof(encrypted_shares, pi_share)