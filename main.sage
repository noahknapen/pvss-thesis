from hashlib import sha256

p = 2^255 - 19
q = 2^252 + 27742317777372353535851937790883648493
Zq = Integers(q)
Am = 486662          # Montgomery A-coefficient
Ar = int((Am+2)/4)   # reduced Montgomery coefficent
E = EllipticCurve(GF(p),[0,Am,0,1,0])
RP.<x> = PolynomialRing(Zq)

G = E.random_point() # generator 
while G.order() != q:
    G = E.random_point()

def xADD(P,Q,R): # points are of the form [X,Z]
        [XP,ZP] = [P[0],P[1]];
        [XQ,ZQ] = [Q[0],Q[1]];
        [XR,ZR] = [R[0],R[1]];

        V0 = XP + ZP
        V1 = XQ - ZQ
        V1 = V1 * V0
        V0 = XP - ZP
        V2 = XQ + ZQ
        V2 = V2 * V0
        V3 = V1 + V2
        V3 = V3^2
        V4 = V1 - V2
        V4 = V4^2
        Xp = ZR * V3
        Zp = XR * V4
        
        return [Xp,Zp]

def xDBL(P): # points are of the form [X,Z]
    [XP,ZP] = [P[0],P[1]]
    
    V1 = XP + ZP
    V1 = V1^2
    V2 = XP - ZP
    V2 = V2^2
    X2 = V1 * V2
    V1 = V1 - V2
    V3 = Ar * V1
    V3 = V3 + V2
    Z2 = V1 * V3
    
    return [X2,Z2]

def Montgomery_ladder(k,P): # points are of the form [X,Z]
    x0,x1 = P,xDBL(P)
    k = k.binary()
    l = len(k)
    for i in range(1,l):
        if k[i]=='0':
            x0,x1 = xDBL(x0),xADD(x0,x1,P)
        if k[i]=='1':
            x0,x1 = xADD(x0,x1,P),xDBL(x1)
    return x0,x1

def recover_y(P,Q,R):
    [XP,YP] = [P[0],P[1]] # P is an actual elliptic curve point in the form (X:Y:Z)
    [XQ,ZQ] = [Q[0],Q[1]]
    [XR,ZR] = [R[0],R[1]]
        
    V1 = XP * ZQ
    V2 = XQ + V1
    V3 = XQ - V1
    V3 = V3^2
    V3 = V3 * XR
    V1 = 2*Am*ZQ
    
    V2 = V2 + V1
    V4 = XP * XQ
    V4 = V4 + ZQ
    V2 = V2 * V4
    V1 = V1 * ZQ
    V2 = V2 - V1
    V2 = V2 * ZR
    
    Y  = V2 - V3
    V1 =  2 * YP
    V1 = V1 * ZQ
    V1 = V1 * ZR
    X  = V1 * XQ
    Z  = V1 * ZQ
    
    return E(X,Y,Z)

def fast_multiply(k,P): # use montgomery ladder and y-recovery
    PM = [P[0],P[2]] # X-Z coordinates
    x0,x1 = Montgomery_ladder(Integer(k),PM)
    return E(recover_y(P,x0,x1))


class Party:
    def __init__(self, index, n):
        self.n = n
        self.index = index
        self.secret_key = Zq.random_element()
        self.public_key = Integer(self.secret_key) * G
        self.public_keys = [0 for _ in range(self.n)]
        self.encrypted_shares = [0 for _ in range(self.n)]
        self.dealer_proof = [0,0]
        self.decrypted_shares = [0 for _ in range(self.n)]
    
    def publish_public_key(self):
        return self.public_key

    def receive_public_keys(self, public_keys):
        self.public_keys = public_keys
    
    def receive_encrypted_shares_and_proof(self, encrypted_shares, dealer_proof):
        self.encrypted_shares = encrypted_shares
        self.dealer_proof = dealer_proof
    
    def receive_decrypted_share_and_proof(self, index, dec_share, share_proof):
        if self.verify_decrypted_share(index, dec_share, share_proof):
            self.decrypted_shares.append(dec_share)

    def verify_encrypted_shares(self):    
        d = self.dealer_proof[0]
        z = self.dealer_proof[1]
        temp_d1, temp_d2 = "", ""

        for i in range(self.n):
            temp_d1 = sha256(str(self.encrypted_shares[i]).encode()).hexdigest()+str(",")
            numerator = fast_multiply(z(x=i+1), self.public_keys[i])
            denominator = fast_multiply(d, self.encrypted_shares[i])
            temp_d2 = sha256(str(numerator - denominator).encode()).hexdigest()+str(",")
        
        temp_d1 = temp_d1[:-1]
        temp_d2 = temp_d2[:-1]
        reconstructed_d = Integer(Zq(int(sha256(str(temp_d1)+str(temp_d2)).hexdigest(),16)))

        return d == reconstructed_d
    
    def broadcast_decrypted_share_and_proof(self):
        dec_share = self.generate_decrypted_share()
        share_proof = self.nizk_proof_for_dleq(dec_share)
        return dec_share, share_proof
    
    def generate_decrypted_share(self):
        inv_priv_key = Integer(self.secret_key).inverse_mod(q)
        dec_share = fast_multiply(inv_priv_key, self.encrypted_shares[self.index-1])
        return dec_share
    
    def nizk_proof_for_dleq(self, dec_share):
        r = Zq.random_element()
        c1 = fast_multiply(r, G)
        c2 = fast_multiply(r, dec_share[self.index-1])

        d = sha256(str(self.public_key).encode()).hexdigest() + str(",")
        d += sha256(str(self.encrypted_shares[self.index-1]).encode()).hexdigest() + str(",")
        d += sha256(str(c1).encode()).hexdigest() + str(",")
        d += sha256(str(c2).encode()).hexdigest()

        d = Integer(Zq(int(d,16)))
        z = Integer(Zq(int(r + d*self.secret_key,16)))

        return d,z

    def verify_decrypted_share(self, index, dec_share, share_proof):
        d = share_proof[0]
        z = share_proof[1]

        nominator1 = fast_multiply(z, G)
        nominator2 = fast_multiply(z, dec_share)

        denominator1 = fast_multiply(d, self.public_keys[index-1])
        denominator2 = fast_multiply(d, self.encrypted_shares[index-1])

        temp_d = sha256(str(self.public_keys[index-1]).encode()).hexdigest() + str(",")
        temp_d += sha256(str(self.encrypted_shares[index-1]).encode()).hexdigest() + str(",")
        temp_d += sha256(str(nominator1-denominator1).encode()).hexdigest() + str(",")
        temp_d += sha256(str(nominator2-denominator2).encode()).hexdigest()

        reconstructed_d = Integer(Zq(int(temp_d,16)))

        return d == reconstructed_d

    def reconstruct_secret(self):
        f = RP.lagrange_polynomial([self.decrypted_shares[i] for i in range(len(self.decrypted_shares))])
        return f(x=0)


class Dealer:
    def __init__(self, public_keys, n):
        self.pub_keys = public_keys
        self.n = n
        self.t = n//2-1 # assumes n is even!

    def broadcast_secret_and_proof(self):
        f = RP.random_element(degree=self.t)
        enc_shares = self.generate_encrypted_evals(f)
        pi_share = self.pi_pdl(enc_shares)

        return enc_shares, pi_share

    def generate_encrypted_evals(self, pol):
        evals = [pol(x=i) for i in range(1, self.n+1)]
        enc_evals = [0 for _ in range(self.n)]
        
        for i in range(self.n):
            enc_evals[i] = fast_multiply(Integer(evals[i]), self.public_keys[i])

        return enc_evals
    
    def pi_pdl(self, enc_shares, f):
        r = RP.random_element(degree=self.t)
        enc_r_evals = self.generate_encrypted_evals(r)

        temp_d1, temp_d2 = "", ""

        for i in range(self.n):
            temp_d1 = sha256(str(enc_shares[i]).encode()).hexdigest()+str(",")
            temp_d2 = sha256(str(enc_r_evals[i]).encode()).hexdigest()+str(",")
        
        temp_d1 = temp_d1[:-1]
        temp_d2 = temp_d2[:-1]
        d = Integer(Zq(int(sha256(str(temp_d1)+str(temp_d2)).hexdigest(),16)))
        z = r + d*f

        return d,z

    