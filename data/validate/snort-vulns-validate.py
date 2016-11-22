#!/bin/python

import re
import time
import argparse


snort_suite = [
# = [24] =
# INPUT: /^Location\x3a(\s*|\s*\r?\n\s+)*URL\s*\x3a/smiH
# PARSE: OK
# SIZE: 34
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: a(\s*|\s*\r?\n\s+)
# PREFIX: location:
# PUMPABLE: \x0d\x0a\x0b
# SUFFIX: 
  {
    "index"    : "24", 
    "exp"      : "^Location\x3a(\s*|\s*\r?\n\s+)*URL\s*\x3a",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"location:",
    "pumpable" : "\x0d\x0a\x0b",
    "suffix"   : r"",
    "n"        : 3
  },
# = [141] =
# INPUT: /<\s*style\s*>\s*\w+\s*\{\s*(\w+|\w+-\w+)\s*\:\s*\w+\s*\(.*?(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1}.*?\)\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}.*?\}|(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,}.*?\}\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}/Psmi
# PARSE: OK
# SIZE: 505
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: |(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,
# PREFIX: '
# PUMPABLE: '\x09'
# SUFFIX: 
  {
    "index"    : "141", 
    "exp"      : "<\s*style\s*>\s*\w+\s*\{\s*(\w+|\w+-\w+)\s*\:\s*\w+\s*\(.*?(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1}.*?\)\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}.*?\}|(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,}.*?\}\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"'",
    "pumpable" : "'\x09'",
    "suffix"   : r"",
    "n"        : 5
  },
# = [142] =
# INPUT: /<\s*style\s*>\s*\w+\s*\{\s*(\w+|\w+-\w+)\s*\:\s*\w+\s*\(.*?(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1}.*?\)\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}.*?\}|(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,}.*?\}\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}/smi
# PARSE: OK
# SIZE: 505
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: |(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,
# PREFIX: '
# PUMPABLE: '\x09'
# SUFFIX: 
  {
    "index"    : "142", 
    "exp"      : "<\s*style\s*>\s*\w+\s*\{\s*(\w+|\w+-\w+)\s*\:\s*\w+\s*\(.*?(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1}.*?\)\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}.*?\}|(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){1,}.*?\}\s*(\s*\x27\s*|\s*\&\#39\;\s*|\s*\&\#x27\;\s*|\s*\\u0027\;\s*){3,}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"'",
    "pumpable" : "'\x09'",
    "suffix"   : r"",
    "n"        : 5
  },
# = [2090] =
# INPUT: /^POST [^\r\n]*?\x3F([^\r\n]*?\x26)*?[^\x3D\r\n]{1025}/Osmi
# PARSE: OK
# SIZE: 1041
# PUMPABLE: YES
# VULNERABLE: YES {PRUNED}
# KLEENE: F([^\r\n]*?\x26)*
# PREFIX: post ?
# PUMPABLE: =&&
# SUFFIX: 
#
# Notice the final expression [^\x3D\r\n]{1025}. Python tries to optimize the matching process
# by observing that anything short of 1029 (+4 for POST, probably) characters is not going to
# match this expression. Therefore, we must ensure that the input string is >= 1029 characters
# in length if we are to exploit the vulnerability. However, exponential blowup at that level
# of pumping is massive, causing python to hang (that's why we skip this). To observe this, simply
# uncomment the "skip" line below; for n >= 341 python hangs, for anything short it will return
# immediately.
  {
    "index"    : "2090", 
    "exp"      : "^POST [^\r\n]*?\?([^\r\n]*?\x26)*?[^\x3D\r\n]{1025}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"post ?",
    "pumpable" : r"=&&",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 340
  },
# = [2092] =
# INPUT: /^GET [^\r\n]*?\x3F([^\r\n]*?\x26)*?[^\x3D\r\n]{1025}/Osmi
# PARSE: OK
# SIZE: 1040
# PUMPABLE: YES
# VULNERABLE: YES {PRUNED}
# KLEENE: F([^\r\n]*?\x26)*
# PREFIX: get ?
# PUMPABLE: =&&
# SUFFIX: 
#
# Note: see comments for [2090] above.
  {
    "index"    : "2092", 
    "exp"      : "^GET [^\r\n]*?\?([^\r\n]*?\x26)*?[^\x3D\r\n]{1025}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"get ?",
    "pumpable" : r"=&&",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 341
  },
# = [2318] =
# INPUT: /^SITE\s*(\w+\s*)+\x7c/smi
# PARSE: OK
# SIZE: 24
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: *(\w+\s*)
# PREFIX: site0
# PUMPABLE: 00
# SUFFIX: 
#
# Note: python successfully works around vulnerabilities of the form: ([a-z]*)*
  {
    "index"    : "2318", 
    "exp"      : "^SITE\s*(\w+\s*)+\x7c",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"site0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "notes"    : "see inline comments",
    "n"        : 5
  },
# = [2831] =
# INPUT: /[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}/Rmi
# PARSE: OK
# SIZE: 993
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: =([^\n\s>]|\(|\))
# PREFIX: ?o onmouseover=
# PUMPABLE: )
# SUFFIX: 
#
# What happens here is quite similar to that of [2090]. Uncomment the "skip" line below
# to observe Python hang.
  {
    "index"    : "2831", 
    "exp"      : "[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"?o onmouseover=",
    "pumpable" : r")",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 132
  },
# = [2853] =
# INPUT: /[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>)]|\(|\))*\s*){21}/Rmi
# PARSE: OK
# SIZE: 993
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: =([^\n\s>)]|\(|\))
# PREFIX: ?o onmouseover=
# PUMPABLE: (
# SUFFIX: 
# 
# What happens here is quite similar to that of [2090]. Uncomment the "skip" line below
# to observe Python hang.
  {
    "index"    : "2853", 
    "exp"      : "[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>)]|\(|\))*\s*){21}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"?o onmouseover=",
    "pumpable" : r"(",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 132
  },
# = [2878] =
# INPUT: /[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}/Rmi
# PARSE: OK
# SIZE: 993
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: =([^\n\s>]|\(|\))
# PREFIX: ?o onmouseover=
# PUMPABLE: )
# SUFFIX: 
#
# What happens here is quite similar to that of [2090]. Uncomment the "skip" line below
# to observe Python hang.
  {
    "index"    : "2878", 
    "exp"      : "[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"?o onmouseover=",
    "pumpable" : r")",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 132
  },
# = [2922] =
# INPUT: /[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}/Rmi
# PARSE: OK
# SIZE: 993
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: =([^\n\s>]|\(|\))
# PREFIX: ?o onmouseover=
# PUMPABLE: )
# SUFFIX: 
#
# What happens here is quite similar to that of [2090]. Uncomment the "skip" line below
# to observe Python hang.
  {
    "index"    : "2922", 
    "exp"      : "[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"?o onmouseover=",
    "pumpable" : r")",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 132
  },
# = [2958] =
# INPUT: /[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}/Rmi
# PARSE: OK
# SIZE: 993
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: =([^\n\s>]|\(|\))
# PREFIX: ?o onmouseover=
# PUMPABLE: )
# SUFFIX: 
#
# What happens here is quite similar to that of [2090]. Uncomment the "skip" line below
# to observe Python hang.
  {
    "index"    : "2878", 
    "exp"      : "[^>]\w*\s*(on(mouse(over|up|down)|load|click)=([^\n\s>]|\(|\))*\s*){21}",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"?o onmouseover=",
    "pumpable" : r")",
    "suffix"   : r"",
    "skip"     : True,
    "notes"    : "skipped - see inline comments",
    "n"        : 132
  },
# = [3072] =
# INPUT: /substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b/smi
# PARSE: OK
# SIZE: 73
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\s*\$\w+\s*,\s*){3,
# PREFIX: substr_replace($a ,$a ,$a,
# PUMPABLE: $a,\x09$0,
# SUFFIX: 
  {
    "index"    : "3072", 
    "exp"      : "substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"substr_replace($a ,$a ,$a,",
    "pumpable" : "$a,\x09$0,",
    "suffix"   : r"",
    "n"        : 6
  },
# = [3155] =
# INPUT: /substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b/Psmi
# PARSE: OK
# SIZE: 73
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\s*\$\w+\s*,\s*){3,
# PREFIX: substr_replace($a ,$a ,$a,
# PUMPABLE: $a,\x09$0,
# SUFFIX: 
  {
    "index"    : "3155", 
    "exp"      : "substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"substr_replace($a ,$a ,$a,",
    "pumpable" : "$a,\x09$0,",
    "suffix"   : r"",
    "n"        : 6
  },
# = [3156] =
# INPUT: /substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b/smi
# PARSE: OK
# SIZE: 73
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\s*\$\w+\s*,\s*){3,
# PREFIX: substr_replace($a ,$a ,$a,
# PUMPABLE: $a,\x09$0,
# SUFFIX: 
  {
    "index"    : "3155", 
    "exp"      : "substr_replace\((\s*\$\w+\s*,\s*){3,}.*?\)\x3b",
    "flags"    : re.IGNORECASE,
    "prefix"   : r"substr_replace($a ,$a ,$a,",
    "pumpable" : "$a,\x09$0,",
    "suffix"   : r"",
    "n"        : 6
  },
# = [10787] =
# INPUT: /^Accept\x2dCharset\x3a\s*?([^\x3b\x3d\x2c]{1,36}\s*?[\x2d\x3b\x3d\x2c]\s*?)*[^\x2d\x3b\x2c\x3d\n]{37}/smi
# PARSE: OK
# SIZE: 731
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ?([^\x3b\x3d\x2c]{1,36}\s*?[\x2d\x3b\x3d\x2c]\s*?)
# PREFIX: accept-charset:
# PUMPABLE: --\x09=
# SUFFIX: 
  {
    "index"    : "10787", 
    "exp"      : "^Accept\x2dCharset\x3a\s*?([^\x3b\x3d\x2c]{1,36}\s*?[\x2d\x3b\x3d\x2c]\s*?)*[^\x2d\x3b\x2c\x3d\n]{37}",
    "flags"    : re.MULTILINE,
    "prefix"   : r"Accept-Charset:",
    "pumpable" : "--\x09=",
    "suffix"   : r"",
    "n"        : 10
  },
]

# format strings (for the table)
output_format = "{0:>5}|{1:>10}|{2:>30}|{3:>10}|{4:<30}|"
header_format = "{0:^5}|{1:^10}|{2:^30}|{3:^10}|{4:^30}|"
hline = "-".rjust(90, "-")

# parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--base", help="base pump-count to use (default is 0)", type = int, default = 0)
parser.add_argument("--stress", help="stress-test the specified vulnerability", default = "")
args = parser.parse_args()
base_pumps = args.base
stress_id = args.stress

# profiling function
def profile(tpl):
  if "skip" in tpl:
    print output_format.format(tpl["index"], "N/A", "N/A", "N/A", tpl["notes"] if "notes" in tpl else "")
    return

  n = base_pumps + tpl["n"]
  pumping1 = ""
  pumping2 = ""
  for i in range(0, n):
    pumping1 = "{0:s}{1:s}".format(pumping1, tpl["pumpable"])
  pumping2 = "{0:s}{1:s}".format(pumping1, tpl["pumpable"])

  atk1 = "{0:s}{1:s}{2:s}".format(tpl["prefix"], pumping1, tpl["suffix"])
  atk2 = "{0:s}{1:s}{2:s}".format(tpl["prefix"], pumping2, tpl["suffix"])

  flags = tpl["flags"] if "flags" in tpl else 0
  p = re.compile(tpl["exp"], flags)

  ts1 = time.time()
  m1 = p.match(atk1)
  te1 = time.time()
  
  ts2 = time.time()
  m2 = p.match(atk2)
  te2 = time.time()

  t1 = (te1 - ts1)
  t2 = (te2 - ts2)
  gr = ((t2 - t1) / t1) * 100

  pumps = "({0:d},{1:d})".format(n, n + 1)
  times = "({0:.10f},{1:.10f})".format(t1, t2)
  growth = "{0:.1f}%".format(gr)
  print output_format.format(tpl["index"], pumps, times, growth, tpl["notes"] if "notes" in tpl else "")

# stress testing function
def stress(tpl):
  if "skip" in tpl:
    return

  pumping = tpl["pumpable"]
  atk = "{0:s}{1:s}{2:s}".format(tpl["prefix"], pumping, tpl["suffix"])

  flags = tpl["flags"] if "flags" in tpl else 0
  p = re.compile(tpl["exp"], flags)

  tprev = 0.0

  # 20 iterations should be enough
  for i in range(1, 21):
    ts = time.time()
    m = p.match(atk)
    te = time.time()
    gr = (((te - ts) - tprev) / tprev) * 100 if tprev != 0.0 else 0.0
    print output_format.format(tpl["index"], i, (te - ts), "{0:.1f}%".format(gr), tpl["notes"] if "notes" in tpl else "")
    tprev = te - ts
    pumping = "{0:s}{1:s}".format(pumping, tpl["pumpable"])
    atk = "{0:s}{1:s}{2:s}".format(tpl["prefix"], pumping, tpl["suffix"])

def validate_snort():
  print "{0:^90}".format("=[SNORT]=")
  print hline
  print header_format.format("ID", "PUMPS", "TIMES", "GROWTH", "NOTES")
  print hline
  for tpl in snort_suite:
    if (stress_id == ""):
      profile(tpl)
    elif (stress_id == tpl["index"]):
      stress(tpl)

# main
validate_snort()
