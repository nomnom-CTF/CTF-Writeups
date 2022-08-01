# UIUCTF 2022 - asr Challenge Writeup

## Description

Oh no I dropped my d. Good thing I'm not telling you my n.

## Challenge Source Code

```python
from secret import flag
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from math import prod

small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
def gen_prime(bits, lim = 7, sz = 64):
    while True:
        p = prod([getPrime(sz) for _ in range(bits//sz)])
        for i in range(lim):
            if isPrime(p+1):
                return p+1
            p *= small_primes[i]

p = gen_prime(512)
q = gen_prime(512)
n = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = pow(e, -1, phi)

msg = bytes_to_long(flag)
ct = pow(msg, e, n)

print("e = ", e)
print("d = ", d)
print("ct = ", ct)
'''
e = 65537
d = 195285722677343056731308789302965842898515630705905989253864700147610471486140197351850817673117692460241696816114531352324651403853171392804745693538688912545296861525940847905313261324431856121426611991563634798757309882637947424059539232910352573618475579466190912888605860293465441434324139634261315613929473
ct = 212118183964533878687650903337696329626088379125296944148034924018434446792800531043981892206180946802424273758169180391641372690881250694674772100520951338387690486150086059888545223362117314871848416041394861399201900469160864641377209190150270559789319354306267000948644929585048244599181272990506465820030285
'''
```

## Understanding The gen_prime Function

As we can see, the function generates 512//64 = 8 64-bit primes, takes the product of all of these primes and stores the result in p. Then there's a loop that runs 7 times and each iteration of that loop there's a check for whether p+1 is a prime, if it is then the function returns p+1, and if it isn't then p keeps on getting multiplied by small_primes[i] where i is the iteration number of the loop.

What we can conclude from this is the following:

- p+1 is prime (the value that gets returned)

- p consists of 8 64-bit prime numbers.

- there are probably going to be some numbers from the small_primes list multiplied into p

## Writing The Solution

The rest of the source code is really easy to understand. We see that we are given d, e, ct. We can use this information to find p and q. We know that `d*e = 1 (mod ϕ(n))` so in other words,
`d*e = 1 + k*ϕ(n)` which means `d*e - 1 = k*ϕ(n)`. By defintion, `ϕ(n) | (d*e - 1)`. Since we can calculate `d*e - 1` and it is fairly smooth, we can factor `d*e - 1`. The product of some combination of the factors will give us p-1, and from our conclusions about the gen_prime function we know that p-1 consists of 8 64-bit prime numbers. After factoring `d*e - 1`, we find that there are 16 64-bit prime numbers which means that the product of some combination of 8 of them is equal to p-1 and the product of the other 8 is equal to q-1. Realizing that, the solution becomes trivial. We just have to brute force some combination of 8 primes, maybe multiply in some small primes as well until p+1 is prime. Then we take the other 8 64 bit prime numbers and do the same thing we did to find p-1; that will give us q-1. after getting p-1 and q-1 the challenge basically becomes a simple textbook rsa problem.

Solver Script:

```python
from math import gcd, prod
import itertools

def isPrime(n, k=5):
    from random import randint
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        x = pow(randint(2, n-1), d, n)
        if x == 1 or x == n-1: continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1: return False
            if x == n-1: break
        else: return False
    return True

e = 65537
d = 195285722677343056731308789302965842898515630705905989253864700147610471486140197351850817673117692460241696816114531352324651403853171392804745693538688912545296861525940847905313261324431856121426611991563634798757309882637947424059539232910352573618475579466190912888605860293465441434324139634261315613929473
c = 212118183964533878687650903337696329626088379125296944148034924018434446792800531043981892206180946802424273758169180391641372690881250694674772100520951338387690486150086059888545223362117314871848416041394861399201900469160864641377209190150270559789319354306267000948644929585048244599181272990506465820030285

kphi = d*e - 1
kphi_factors = []

#16 64-bit prime factors
kphi_factors.append(10357495682248249393)
kphi_factors.append(10441209995968076929)
kphi_factors.append(10476183267045952117)
kphi_factors.append(11157595634841645959)
kphi_factors.append(11865228112172030291)
kphi_factors.append(12775011866496218557)
kphi_factors.append(13403263815706423849)
kphi_factors.append(13923226921736843531)
kphi_factors.append(14497899396819662177)
kphi_factors.append(14695627525823270231)
kphi_factors.append(15789155524315171763)
kphi_factors.append(16070004423296465647)
kphi_factors.append(16303174734043925501)
kphi_factors.append(16755840154173074063)
kphi_factors.append(17757525673663327889)
kphi_factors.append(18318015934220252801)


all_combinations = []
for i in itertools.combinations(kphi_factors,8):
    all_combinations.append(i)
small_primes = [2, 3, 5, 7, 11, 13, 17]

product = prod(kphi_factors) # product of the 16 64-bit prime factors

for sets in all_combinations:
    p=1
    saved = 1
    for j in sets:
        p *= j
    saved = p # saving p before multiplying in the small primes (used to find q)
    if not isPrime(p+1):
        for j in small_primes:
            p*=j
            if isPrime(p+1):
                break
    if not isPrime(p+1):
        continue
    q = (product//saved)
    if not isPrime(q+1):
        for j in small_primes:
            q*=j
            if isPrime(q+1):
                break
    if not isPrime(q+1):
        continue
    p=p+1
    q=q+1
    phi_n = (p-1)*(q-1)
    if gcd(e, phi_n) == 1 and p*q != 0:
        n = p*q
        flag = hex(pow(c,d,n))[2:]
        flag = ''.join(chr(int(flag[i:i+2],16)) for i in range(0,len(flag),2))
        if 'ctf' in flag:
            print(flag)
```

flag: `uiuctf{bru4e_f0rc3_1s_FUn_fuN_Fun_f0r_The_whOLe_F4miLY!}`
