#!/usr/bin/env python3
"""P6-ANON estimate (docs/research/pqz-anonymity.md §7.2, §8.2): primal uSVP block size beta, ADPS16 2016 model as
pq-zero-knowledge.md §4.1 (scratch script of 2026-10-06 re-done; reproduces Kyber-512 406, PQZ 476, 32 hints 466).
Hints approximated as dimensions removed (pq-zero-knowledge.md §4.5). Not the pinned lattice-estimator. python3 -I usvp.py"""
from math import log, pi, e, sqrt
def delta(b): return ((pi*b)**(1/b) * b/(2*pi*e))**(1/(2*(b-1)))
def beta(n, q, ss, se, mmax):
    best=None
    for m in range(max(1,n//4), mmax+1, 16):
        d=m+n+1; lv=(m*log(q)+n*log(se/ss))/d
        for b in range(50, 2000):
            if log(se*sqrt(b)) <= (2*b-d-1)*log(delta(b)) + lv:
                if best is None or b<best: best=b
                break
    return best
K=beta(512,3329,sqrt(1.5),sqrt(1.5),1024); print('kyber512',K)
q=2**42-215
print('pqz n=2048', beta(2048,q,sqrt(.5),sqrt(10),2048))
for h in (32,48,80,144,272):
    print('hints',h,'n',2048-h, beta(2048-h,q,sqrt(.5),sqrt(10),2048))
# B2: base key / delta with sparse ternary secret (var h/2048) and CBD(eta) error
for hw,eta in ((256,5),(256,10),(324,5),(512,5),(512,10),(256,20)):
    print('B2 secret weight',hw,'CBD',eta, beta(2048,q,sqrt(hw/2048),sqrt(eta/2),2048))
