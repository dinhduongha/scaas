# Per-part resume for long gate runs (owner 2026-10-23: an interrupted gate restarts near where it stopped, not from
# its first step). Sourced by gate.sh and the step scripts it calls (pqzl/sv/diff.sh, ffi/run.sh, ffi/vectors/run.sh).
# gate.sh exports GATE_STATE (runs/gate/<label>-state) and GATE_TREE (the set + a hash of the file contents, the fuzz
# seconds and the step environment; gate.sh tree()); `part <name> <cmd…>` runs <cmd…> unless "<name> <GATE_TREE>" is in
# GATE_STATE, and records it when <cmd…> exits 0. A part's outputs are files named by the gate label, so a skipped
# part's results are still on disk; gate.sh drops a state of any other tree, so they are this tree's. Without
# GATE_STATE (a script run alone) every part runs.
# Milestones (owner 2026-10-23): with GATE_LOG set (runs/gate/<label>-progress.txt) every step and part writes a
# timestamped line when it starts, passes (with its duration), fails (rc, duration) or is resumed.
# the resume key: the set + a hash of the file contents (the index's blob ids, the unstaged changes --binary, the untracked
# files' sha256; logs, .gitignore and *.md excluded — 8b review I3), the fuzz seconds and GATE_ENV; gate.sh exports
# GATE_TOP / GATE_FZ / GATE_ENV. Recomputed before a step or part is recorded (re-review N1): a file edited during the
# run means the result belongs to no single tree, so it is not recorded and re-runs on resume.
gate_tree() {
  (cd "$GATE_TOP" && set -- . ':(exclude,glob)**/runs/**' ':(exclude,glob)**/.gitignore' ':(exclude,glob)**/*.md' &&
    git ls-files -s -- "$@" && git diff --binary --no-ext-diff --no-textconv -- "$@" &&
    git ls-files -o --exclude-standard -z -- "$@" | xargs -0r sha256sum &&
    echo "fz=$GATE_FZ" && for v in $GATE_ENV; do echo "$v=$(printenv "$v" || echo '<unset>')"; done) |
    sha256sum | cut -c1-16 | sed "s/^/$PQZ_SET-/"
}
gate_record() {
  [ -n "${GATE_STATE:-}" ] || return 0
  if [ "$(gate_tree)" = "$GATE_TREE" ]; then echo "$1 $GATE_TREE" >> "$GATE_STATE"
  else glog "not recorded $1: files changed during the run"; fi
}
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
    gate_record "$_p"
    glog "ok      $_p ($(dur "$_t0"))"
  else
    glog "FAILED  $_p rc=$_rc ($(dur "$_t0"))"
  fi
  return $_rc
}
