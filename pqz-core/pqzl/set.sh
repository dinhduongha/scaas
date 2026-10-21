# Sourced by build.sh and the harness builds (owner 2026-10-21: one parameter set per library build): PQZ_SET (default
# n2304-kmax4096; the frozen v3 set is n2048-kmax1024) names pqz-core/params/sets/<set>/, whose pqz_set.h and relation headers
# pqz_*_params.h are copied into $B/include (every build compiles with -I$B/include). Needs $B, cwd = pqzl/.
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
[ -f "../params/sets/$PQZ_SET/pqz_set.h" ] || { echo "PQZ_SET=$PQZ_SET: no pqz-core/params/sets/$PQZ_SET/pqz_set.h" >&2; exit 2; }
mkdir -p "$B/include"
rm -f "$B/include"/pqz_set.h "$B/include"/pqz_*_params.h
cp "../params/sets/$PQZ_SET"/pqz_set.h "../params/sets/$PQZ_SET"/pqz_*_params.h "$B/include/"
