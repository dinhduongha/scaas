t66a backup (2026-11-08, plan T66a): `ua8-roundtrip.json` as it stood at 3d150ad6, when a PQ-eligible `msig` held a KEM key
(`msig-pq/<set>` with KEM records 3, 1, 2). CTR-UA-32 now refuses an `msig` KEM key, so `ua8_record_bytes_round_trip` regenerated it
(`UA8_WRITE=1`). Reference only, not read by any test.
