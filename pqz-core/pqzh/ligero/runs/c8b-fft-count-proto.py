# WIP 5h Task 8c part 1b: prototype of the prover-cost fix for ligero_params.py --set: FFT products as fft.rs Domain::rec
# counts them (the zero-padding skip of the deepest stage); to be folded into ligero_params.py on resume.
import math, functools
def fft_products(n, radices, length):
    """products of fft.rs Domain::rec for a size-n transform of `length` nonzero leading inputs (the crate's counter)"""
    rs = []
    m = n
    for r in radices:
        while m % r == 0:
            rs.append(r); m //= r
    assert m == 1
    @functools.lru_cache(None)
    def rec(size, level, length, stride):
        if size == 1:
            return 0
        r = rs[level]; mm = size // r
        c = sum(rec(mm, level + 1, max(0, length - s * stride), stride * r) for s in range(r))
        if r == 2:
            return c + mm
        ns = min(r, -(-length // stride))
        return c + mm * ((r - 1) + (r * ns if ns * 4 < r else r * r))
    return rec(n, 0, min(length, n), 1)
R4=[2,19,43,431]; R6=[2,7,17,19,43,431]
for name,n,k,n2,R in [('THE',32756,817,1634,R4),('B',45752,952,2261,R6)]:
    a=fft_products(k,R,k); b=fft_products(n,R,k); bb=fft_products(n,R,2*k-1); c=fft_products(n2,R,k); c2=fft_products(n2,R,n2)
    print(name, 'ifft_k',a,'coset_n(len k)',b,'coset_n(len 2k-1)',bb,'fft_n2(len k)',c,'n2 dense',c2, 'n dense', fft_products(n,R,n))
