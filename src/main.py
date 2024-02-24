from Cryptodome.Math.Primality import generate_probable_safe_prime
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Random import get_random_bytes
from party.party import Party

def create_generator():
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

        return g

def main():
    generator = create_generator()
    party_list = []

    for i in range(5):
        party_list.append(Party(i, generator, 2048))


if __name__ == '__main__':
    main()