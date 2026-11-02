#!/usr/bin/env python3
"""The one-library form: UAViewLib's functions appended to UARegisterLib. usage: merge.py <register lib> <view lib> <out>"""
import re, sys
reg, view, out = sys.argv[1:4]
r, v = open(reg).read(), open(view).read()
body = v[v.index('library UAViewLib {') + len('library UAViewLib {'):v.rindex('}')]
body = re.sub(r'    function _pred\(\) private view returns \(address\) \{.*?\n    \}\n', '', body, count=1, flags=re.S)
i = r.rindex('}')
open(out, 'w').write(r[:i] + '\n    // ----- the views (lever R1′), in this library -----\n' + body + r[i:])
