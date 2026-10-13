unit costs (ns):
  fork prims: P=1795.00, F=191.30, I=351.30, G=58.18, H=1.69, J=0.57, R=15531.40, S=6.15, C=10.00
  portable CRT: P=128.10, F=594.30, I=2484.00, G=58.18, H=1.69, J=0.57, R=15531.40, S=6.15, C=10.00
  portable CRT, SHAKE PRG: P=128.10, F=594.30, I=2484.00, G=1.75, H=1.69, J=0.57, R=567.24, S=6.15, C=10.00
  wasm fork prims: P=6783.70, F=671.00, I=1182.40, G=66.18, H=1.97, J=0.74, R=17101.10, S=10.73, C=17.45
  wasm CRT, SHAKE PRG: P=223.50, F=1201.20, I=4805.18, G=2.00, H=1.97, J=0.74, R=663.08, S=10.73, C=17.45
  AVX2: P=24.75, F=172.73, I=814.23, G=0.11, H=1.55, J=0.14, R=200.00, S=6.22, C=3.00

### R_TX

| Term | Kind | Counts | fork prims (ms) | portable CRT (ms) | portable CRT, SHAKE PRG (ms) | wasm fork prims (ms) | wasm CRT, SHAKE PRG (ms) | AVX2 (ms) |
|---|---|---|---|---|---|---|---|---|
| ABDLOP: w = A1 z1 + A2' z21 - c 2^D tA1 (+ INTT w, dcompress) | proof | P 4,577, F 222, I 23 | 8.279 | 0.587 | 0.587 | 31.225 | 1.400 | 0.417 |
| B rows: c tB - B' z21 (garbage / y3 / y4 / beta / g commitments) | proof | P 552, F 12 | 0.993 | 0.078 | 0.078 | 3.753 | 0.138 | 0.016 |
| Statement R_q-linear rows: A s + e = pk (R_TX also A^T r + e1 = u) | proof | P 2,048 | 3.676 | 0.262 | 0.262 | 13.893 | 0.458 | 0.051 |
| Statement Z_q rows (R_TX: 80 evaluation eqs: pk^T r, u_T^T s, digits) | proof | P 216, S 20,480 | 0.514 | 0.154 | 0.154 | 1.685 | 0.268 | 0.133 |
| Norm-proof quadratic terms: o(z_i) z_i (l2, binary), upsilon, beta | proof | P 156, S 1,080 | 0.287 | 0.027 | 0.027 | 1.070 | 0.046 | 0.011 |
| JL (l2 approx, 256 rows): expand R, fold V^T R, <vR, o(z)> beta | proof | P 624, F 616, G 630,784, J 10,092,544, S 2,048 | 43.734 | 42.942 | 7.345 | 53.858 | 9.608 | 1.621 |
| Quad-many fold: sum_k mu_k F_k(z), c r1 z, c^2 r0; mu expansion | proof | P 136, F 70, I 1, G 26,112 | 1.777 | 1.581 | 0.107 | 2.699 | 0.172 | 0.019 |
| Fiat-Shamir: statement + transcript hashing, Z_q challenge expansion | proof | H 100,840, G 98,196, R 4 | 5.946 | 5.946 | 0.344 | 6.766 | 0.398 | 0.167 |
| Decode proof, norm checks (z1, z21, z3, z4, w1 - gamma hint, h) | proof | C 17,088 | 0.171 | 0.171 | 0.171 | 0.298 | 0.298 | 0.051 |
| Statement polys to NTT (pk, u, u_T): per account / per tx, cacheable per account | cache | F 192 | 0.037 | 0.114 | 0.114 | 0.129 | 0.231 | 0.033 |
| A, A^T, A1, A2', B' in NTT form | param |  | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| **Total per proof** | | | **65.38** | **51.75** | **9.07** | **115.25** | **12.79** | **2.49** |
| Total incl. statement NTTs (no per-account cache) | | | 65.41 | 51.86 | 9.19 | 115.38 | 13.02 | 2.52 |

count totals: P 8,309, F 1,112, I 24, G 755,092, H 100,840, J 10,092,544, R 4, S 23,608, C 17,088

### R_REG

| Term | Kind | Counts | fork prims (ms) | portable CRT (ms) | portable CRT, SHAKE PRG (ms) | wasm fork prims (ms) | wasm CRT, SHAKE PRG (ms) | AVX2 (ms) |
|---|---|---|---|---|---|---|---|---|
| ABDLOP: w = A1 z1 + A2' z21 - c 2^D tA1 (+ INTT w, dcompress) | proof | P 2,464, F 134, I 22 | 4.484 | 0.347 | 0.347 | 16.831 | 0.817 | 0.166 |
| B rows: c tB - B' z21 (garbage / y3 / y4 / beta / g commitments) | proof | P 552, F 12 | 0.993 | 0.078 | 0.078 | 3.753 | 0.138 | 0.016 |
| Statement R_q-linear rows: A s + e = pk (R_TX also A^T r + e1 = u) | proof | P 1,024 | 1.838 | 0.131 | 0.131 | 6.947 | 0.229 | 0.025 |
| Statement Z_q rows (R_TX: 80 evaluation eqs: pk^T r, u_T^T s, digits) | proof | P 0, S 0 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| Norm-proof quadratic terms: o(z_i) z_i (l2, binary), upsilon, beta | proof | P 69, S 1,040 | 0.130 | 0.015 | 0.015 | 0.479 | 0.027 | 0.008 |
| JL (l2 approx, 256 rows): expand R, fold V^T R, <vR, o(z)> beta | proof | P 276, F 268, G 274,432, J 4,390,912, S 2,048 | 19.042 | 18.690 | 3.203 | 23.475 | 4.194 | 0.713 |
| Quad-many fold: sum_k mu_k F_k(z), c r1 z, c^2 r0; mu expansion | proof | P 72, F 38, I 1, G 13,824 | 0.941 | 0.839 | 0.058 | 1.430 | 0.094 | 0.011 |
| Fiat-Shamir: statement + transcript hashing, Z_q challenge expansion | proof | H 35,088, G 96,396, R 4 | 5.730 | 5.730 | 0.230 | 6.517 | 0.265 | 0.065 |
| Decode proof, norm checks (z1, z21, z3, z4, w1 - gamma hint, h) | proof | C 11,392 | 0.114 | 0.114 | 0.114 | 0.199 | 0.199 | 0.034 |
| Statement polys to NTT (pk, u, u_T): per account / per tx, cacheable per account | cache | F 32 | 0.006 | 0.019 | 0.019 | 0.021 | 0.038 | 0.006 |
| A, A^T, A1, A2', B' in NTT form | param |  | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| **Total per proof** | | | **33.27** | **25.94** | **4.18** | **59.63** | **5.96** | **1.04** |
| Total incl. statement NTTs (no per-account cache) | | | 33.28 | 25.96 | 4.20 | 59.65 | 6.00 | 1.04 |

count totals: P 4,457, F 484, I 23, G 384,652, H 35,088, J 4,390,912, R 4, S 3,088, C 11,392
