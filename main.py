from Cryptodome.Math.Primality import generate_probable_safe_prime
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Random import get_random_bytes
from party import Party
from dealer import Dealer

def create_generator_and_prime_pair():
    p = generate_probable_safe_prime(exact_bits=2048, randfunc=get_random_bytes)
    q = (p - 1) >> 1

    while True:
        g = pow(Integer.random_range(min_inclusive=2, 
                                     max_inclusive=p, 
                                     randfunc=get_random_bytes), 2, p)

        if g in (1, 2):
            continue

        if (p-1) % g == 0:
            continue

        g_inv = g.inverse(p)
        if (p-1) % g_inv == 0:
            continue

        return (g, (p, q))

def main():

    # Initialization stage
    (generator, prime_pair) = create_generator_and_prime_pair()
    n = 3
    t = 3
    party_list = []

    for i in range(n):
        party_list.append(Party(i, generator, t, prime_pair[1]))
    
    # Share stage
    dealer = Dealer(n, t, prime_pair[1], generator, party_list)
    dealer.share_secret("Hello world")

    # Verification stage TODO: implement t < n
    for party in party_list:
        party.receive_party_objects(party_list)
        if party.verify_shares() == False:
            print("Verification failed at party " + str(party.number))
            return
    
    # Reconstruction stage
    for party in party_list:
        party.publish_decrypted_share_and_proof()

    secret = party_list[0].reconstruct_secret()





if __name__ == '__main__':
    main()