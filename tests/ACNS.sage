import os

os.system('sage --preparse ../src/ACNS.sage')
os.system('mv ../src/ACNS.sage.py ./src_ACNS.py')

from src_ACNS import *

#############
# Variables #
#############

n = 7 # Number of parties

#################
# ACNS PVSS #
#################

public_keys = [0 for _ in range(n)]
parties = [0 for _ in range(n)]
decrypted_shares_and_proofs = [0 for _ in range(n)]

print("------------------------")
print("Starting ACNS PVSS tests")
print("------------------------")

for i in range(1,n+1):
    p = Party(i, n)
    public_keys[i-1] = p.broadcast_public_key()
    parties[i-1] = p

print("------------------------------------------------------")
print("Party generation and public key publication successful")
print("------------------------------------------------------")

dealer = Dealer(public_keys, n)
dealer.generate_polynomial()
dealer.generate_commitments()
commitments = dealer.broadcast_commitments()
dealer.generate_encrypted_evals()
dealer.dleq_pol()
(enc_shares, pi_share) = dealer.broadcast_share_and_proof()

print("---------------------------------------------------------------------")
print("Dealer generation and encrypted shares + proof publication successful")
print("---------------------------------------------------------------------")

for i in range(n):
    p = parties[i]
    p.store_public_keys(public_keys)
    p.store_commitments(commitments)
    p.store_encrypted_shares_and_proof(enc_shares, pi_share)

    assert p.verify_encrypted_shares()

print("---------------------------------------------")
print("Party encrypted share verification successful")
print("---------------------------------------------")

for i in range(n):
    p = parties[i]
    p.generate_decrypted_share()
    assert p.encrypted_shares[p.index-1] == fast_multiply(p.secret_key, p.decrypted_share)
    p.dleq_share()
    decrypted_shares_and_proofs[i] = p.broadcast_decrypted_share_and_proof()
    assert len(decrypted_shares_and_proofs[i]) == 2 and decrypted_shares_and_proofs[i][0] != 0 and decrypted_shares_and_proofs[i][1] != 0


for i in range(n):
    p = parties[i]
    p.store_decrypted_shares_and_proofs(decrypted_shares_and_proofs)
    assert len(p.decrypted_shares_and_proof) == n
    for j in range(n):
        assert len(p.decrypted_shares_and_proof[j]) == 2 and p.decrypted_shares_and_proof[j][0] != 0 and p.decrypted_shares_and_proof[j][1] != 0

print("---------------------------------------------")
print("Party decrypted share distribution successful")
print("---------------------------------------------")

for i in range(n):
    p = parties[i]
    p.verify_decrypted_shares()
    assert len(p.valid_decrypted_shares) == p.t+1
    for j in range(p.t+1):
        assert p.valid_decrypted_shares[j] != 0

print("---------------------------------------------")
print("Party decrypted share verification successful")
print("---------------------------------------------")

for i in range(n):
    p = parties[i]
    reconstructed_secret = p.reconstruct_secret()
    generator_secret = fast_multiply(dealer.f(x=0), H)
    assert generator_secret == reconstructed_secret

print("--------------------------------------")
print("Party secret reconstruction successful")
print("--------------------------------------")

print("All tests successful")
