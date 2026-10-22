# Per-part resume for long gate runs (owner 2026-10-23: an interrupted gate restarts near where it stopped, not from
# its first step). Sourced by gate.sh and the step scripts it calls (pqzl/sv/diff.sh, ffi/run.sh, ffi/vectors/run.sh).
# gate.sh exports GATE_STATE (runs/gate/<label>-state) and GATE_TREE (HEAD + a hash of the uncommitted changes, logs
# excluded); `part <name> <cmd…>` runs <cmd…> unless "<name> <GATE_TREE>" is in GATE_STATE, and records it when <cmd…>
# exits 0. A part's outputs are files named by the gate label, so a skipped part's results are still on disk. Without
# GATE_STATE (a script run alone) every part runs.
part() {
  _p=$1
  shift
  if [ -n "${GATE_STATE:-}" ] && grep -qxF "$_p $GATE_TREE" "$GATE_STATE" 2>/dev/null; then
    echo "resumed: $_p (passed earlier at this tree)"
    return 0
  fi
  "$@" || return $?
  [ -z "${GATE_STATE:-}" ] || echo "$_p $GATE_TREE" >> "$GATE_STATE"
}
