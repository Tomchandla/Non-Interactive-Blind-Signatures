import itertools

F2 = GF(2)
F.<x> = GF(2)[]
F128.<a> = GF(2**128, name='a', modulus=x^128 + x^7 + x^2 + x + 1 )
FX.<X> = F128[]


print(F128)
print(a**128)

found = False
for sparsity in range(3, 10):
    # generate all polynomials with given 'sparsity'
    for x in itertools.combinations(range(512), sparsity):

        if sparsity == 3 and x[-2] < 128:
            continue 

        f = X^4
        for i in x:
            f += a**(i%128) * X^(i//128)

        irred = f.is_irreducible()
        if irred:
            print("found:", f)
            found = True
            break

    if found:
        print("Found irreducible polynomial of sparsity", sparsity)
        break

