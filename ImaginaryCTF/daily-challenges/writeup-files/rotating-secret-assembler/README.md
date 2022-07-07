# Description

- Encrypt the flag as many times as you want! I'm making sure to never use the same public key twice, just to be safe.

# Challenge Source Code

```python
#!/usr/bin/env python3

from Crypto.Util.number import *

class Rotator:
    QUEUE_LENGTH = 10

    def __init__(self):
        self.e = 65537
        self.m = bytes_to_long(open('flag.txt', 'rb').read())
        self.queue = [getPrime(512) for i in range(self.QUEUE_LENGTH)]

    def get_new_primes(self):
        ret = self.queue[-2:]
        self.queue.pop()
        while(len(self.queue) < self.QUEUE_LENGTH):
            self.queue = [getPrime(512)] + self.queue
        return tuple(ret)

    def enc_flag(self):
        p, q = self.get_new_primes()
        n = p*q
        print(f"Public key: {(n, self.e)}")
        print(f"Your encrypted flag: {pow(self.m, self.e, n)}")

rot = Rotator()

print('='*80)
print(open(__file__).read())
print('='*80)

while True:
    inp = input("Would you like an encrypted flag (y/n)? ")
    if 'y' in inp.lower():
        rot.enc_flag()
        print()
    else:
        break
```

# Solution

The `get_new_primes()` method returns 2 prime numbers that were at the end of the queue but only one of the numbers get popped. That means that each two consecutive encryptions will have the same factor of some x. So,

```
n1 = P*Q_1
n2 = P*Q_2
```

from this we can deduct that P divides n1 and P divides n2. Now it's becomes fairly obvious that taking the gcd of n1 and n2 should result in some multiple of P. After calculating gcd(n1,n2) and plugging the result into factorDB we'll be able to figure out what P is and hence get Q_1 by dividing n1 by p (q=n1//p). After getting P and Q_1, all that's left is to perform textbook RSA and we'll get the flag. 

Solver script:
```python
import math

c=36863369361668262755102371947721531166725738216532122361100110605821849216450500173096210850005994917246163629449149015831331456572665685072103678840167665071995244530509541711141717726254193292686990321278347785437639052923228689444564645709583471587778439214996741410135160689192089122691656894148149841562
n1=118157563752563196208337914272917420227208138355404162291816209206573329118152225878587992381956292051105278737199541339812338529656755382317613684312087741778869841853567971311420439878078415097856563979317277443036087779113485344975857256230645831662499120789612557834380784389129211810305608108270034467773
n2=139386295741402261250294742227817468312056970216100789902635417403631823194540550439803007839361393538708013437024457766971080700096177331882855724841201788056513855199402841530222481106246990189487009297387839250508232661021207725293755235006822062469702770435939910437350057981628685874872606834381345522857
e=65537
p=math.gcd(n1,n2)
q=n1//p
phi_n = (p-1)*(q-1)
d = pow(e,-1,phi_n)
flag = hex(pow(c,d,n1))[2:]
print(''.join([chr(int(flag[i:i+2],16)) for i in range(len(flag)-1)][::2]))
```
