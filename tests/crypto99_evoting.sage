import os

os.system('sage --preparse ../src/crypto99_evoting.sage')
os.system('mv ../src/crypto99_evoting.sage.py ./src_crypto99_evoting.py')

from src_crypto99_evoting import *

m = 1 # Number of voters (dealers)
n = 9 # Number of talliers (parties)
public_keys = [0 for _ in range(n)]
parties = [0 for _ in range(n)]
dealers = [0 for _ in range(m)]
secret_vote = 0
enc_shares = [0 for _ in range(m)]
dealer_proofs = [[0,0] for _ in range(m)]
commitments = [0 for _ in range(m)]
enc_votes = [0 for _ in range(m)]
vote_proofs = [0 for _ in range(m)]
dec_shares_and_proofs = [0 for _ in range(n)]
b = BulletinBoard()

for i in range(1,n+1):
    p = Tallier(i, m, n)
    parties[i-1] = p
    public_keys[i-1] = p.broadcast_public_key()

for i in range(m):
    d = Voter(public_keys, n)
    dealers[i] = d
    [temp_commitments, encrypted_shares, dealer_proof, encrypted_vote, vote_proof] = d.share_stage()
    secret_vote += d.vote
    enc_shares[i] = encrypted_shares
    dealer_proofs[i] = dealer_proof
    commitments[i] = temp_commitments
    enc_votes[i] = encrypted_vote
    vote_proofs[i] = vote_proof

    assert b.verify_adapted_dleqs(temp_commitments[0], enc_votes, vote_proofs)

for i in range(n):
    p = parties[i]
    p.store_public_keys(public_keys)
    p.store_commitments(commitments)
    p.store_encrypted_shares_and_proofs(enc_shares, dealer_proofs)
    p.store_encrypted_votes(enc_votes)

    assert p.verify_encrypted_shares()

for i in range(n):
    p = parties[i]
    p.generate_accumulated_encrypted_shares()
    p.generate_decrypted_share()
    p.dleq_share()
    dec_shares_and_proofs[i] = [p.decrypted_share, p.share_proof]
    assert p.encrypted_shares[p.index-1] == fast_multiply(p.secret_key, p.decrypted_share) #TODO: This assertion will fail if there is more than 1 voter. Adapt this.

for i in range(n):
    p = parties[i]
    p.store_decrypted_shares_and_proofs(dec_shares_and_proofs)
    p.verify_decrypted_shares()

    assert len(p.valid_decrypted_shares) == p.t+1
    for j in range(p.t+1):
        assert p.valid_decrypted_shares[j] != 0
    
    secret = p.reconstruct_secret()
    p.generate_accumulated_encrypted_vote()
    assert secret == fast_multiply(d.f(x=0), H) #TODO: This assertion will fail if there is more than 1 voter. Adapt this.
    assert p.acc_vote == fast_multiply(secret_vote+d.f(x=0), H) #TODO: This assertion will fail if there is more than 1 voter. Adapt this.
    assert p.acc_vote - secret == fast_multiply(secret_vote, H)
    assert fast_multiply(0, H) == fast_multiply(1, H) #! This gives a serious problem
    reconstructed_vote = p.reconstruct_accumulated_decrypted_vote(secret)
    assert reconstructed_vote == secret_vote
