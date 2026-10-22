# Per-part resume for long gate runs (owner 2026-10-23: an interrupted gate restarts near where it stopped, not from
# its first step). Sourced by gate.sh and the step scripts it calls (pqzl/sv/diff.sh, ffi/run.sh, ffi/vectors/run.sh).
# gate.sh exports GATE_STATE (runs/gate/<label>-state) and GATE_TREE (the set + HEAD + a hash of the uncommitted
# changes, logs excluded); `part <name> <cmd…>` runs <cmd…> unless "<name> <GATE_TREE>" is in GATE_STATE, and records it
# when <cmd…> exits 0. A part's outputs are files named by the gate label, so a skipped part's results are still on
# disk. Without GATE_STATE (a script run alone) every part runs.
# Milestones (owner 2026-10-23): with GATE_LOG set (runs/gate/<label>-progress.txt) every step and part writes a
# timestamped line when it starts, passes (with its duration), fails (rc, duration) or is resumed.
glog() { [ -z "${GATE_LOG:-}" ] || echo "$(date +%FT%T) $*" >> "$GATE_LOG"; }
dur() { _s=$(($(date +%s) - $1)); echo "$((_s / 3600))h$((_s / 60 % 60))m$((_s % 60))s"; }
part() {
  _p=$1
  shift
  if [ -n "${GATE_STATE:-}" ] && grep -qxF "$_p $GATE_TREE" "$GATE_STATE" 2>/dev/null; then
    echo "resumed: $_p (passed earlier at this tree)"
    glog "resumed $_p"
    return 0
  fi
  glog "start   $_p"
  _t0=$(date +%s)
  "$@"
  _rc=$?
  if [ $_rc = 0 ]; then
    [ -z "${GATE_STATE:-}" ] || echo "$_p $GATE_TREE" >> "$GATE_STATE"
    glog "ok      $_p ($(dur "$_t0"))"
  else
    glog "FAILED  $_p rc=$_rc ($(dur "$_t0"))"
  fi
  return $_rc
}
