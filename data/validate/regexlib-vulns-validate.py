#!/bin/python

import re
import time
import argparse


regexlib_suite = [
# = [15] =
# INPUT: ^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.((html|HTML)|(htm|HTM))$
# PARSE: OK
# SIZE: 65
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\(\w[\w ]*.*))+
# PREFIX: a:\0
# PUMPABLE: \0\0
# SUFFIX: 
  {
    "index"    : "15", 
    "exp"      : r"^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.((html|HTML)|(htm|HTM))$",
    "prefix"   : r"a:\0",
    "pumpable" : r"\0\0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [59] =
# INPUT: ^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@(([0-9a-zA-Z])+([-\w]*[0-9a-zA-Z])*\.)+[a-zA-Z]{2,9})$
# PARSE: OK
# SIZE: 84
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([-.\w]*[0-9a-zA-Z])*
# PREFIX: 0
# PUMPABLE: 00
# SUFFIX: 
  {
    "index"    : "59", 
    "exp"      : r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@(([0-9a-zA-Z])+([-\w]*[0-9a-zA-Z])*\.)+[a-zA-Z]{2,9})$",
    "prefix"   : r"0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "n"        : 5
  },
# = [65] =
# INPUT: (?:[\w]*) *= *"(?:(?:(?:(?:(?:\\\W)*\\\W)*[^"]*)\\\W)*[^"]*")
# PARSE: OK
# SIZE: 23
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:\\\W)*\\\W)*
# PREFIX:  ="
# PUMPABLE: \\\]\]
# SUFFIX:
  {
    "index"    : "65", 
    "exp"      : r'(?:[\w]*) *= *"(?:(?:(?:(?:(?:\\\W)*\\\W)*[^"]*)\\\W)*[^"]*")',
    "prefix"   : r' ="',
    "pumpable" : r"\\\]\]",
    "suffix"   : r"",
    "n"        : 2
  },
# = [67] =
# INPUT: (<[^>]*?tag[^>]*?(?:identify_by)[^>]*>)((?:.*?(?:<[ \r\t]*tag[^>]*>?.*?(?:<.*?/.*?tag.*?>)?)*)*)(<[^>]*?/[^>]*?tag[^>]*?>)
# PARSE: OK
# SIZE: 74
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:<[ \r\t]*tag[^>]*>?.*?(?:<.*?/.*?tag.*?>)?)*
# PREFIX: <tagidentify_by>
# PUMPABLE: <<tag</<tag</tagtag>
# SUFFIX:
  {
    "index"    : "67", 
    "exp"      : r"((.*(<[ \r\t]*tag[^>]*>?.*(<.*/.*tag.*>)?)*)*)(<[^>]*?/[^>]*?tag[^>]*?>)",
    "prefix"   : r"",
    "pumpable" : r"<<tag</><tag<tag></</>/tagtag>",
    "suffix"   : r"",
    "n"        : 0,
    "skip"     : True,
    "notes"    : "skipped - python hangs"
  },
# = [70] =
# INPUT: ^([A-Za-z]|[A-Za-z][0-9]*|[0-9]*[A-Za-z])+$
# PARSE: OK
# SIZE: 26
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([A-Za-z]|[A-Za-z][0-9]*|[0-9]*[A-Za-z])+
# PREFIX: A
# PUMPABLE: A
# SUFFIX: !
  {
    "index"    : "70", 
    "exp"      : r"^([A-Za-z]|[A-Za-z][0-9]*|[0-9]*[A-Za-z])+$",
    "prefix"   : r"A",
    "pumpable" : r"A",
    "suffix"   : r"!",
    "n"        : 5
  },
# = [94] =
# INPUT: ((^[0-9]*).?((BIS)|(TER)|(QUATER))?)?((\W+)|(^))(([a-z]+.)*)([0-9]{5})?.(([a-z\'']+.)*)$
# PARSE: OK
# SIZE: 77
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-z]+.)*
# PREFIX:
# PUMPABLE: aaa{
# SUFFIX: aa00!
  {
    "index"    : "94", 
    "exp"      : r"((^[0-9]*).?((BIS)|(TER)|(QUATER))?)?((\W+)|(^))(([a-z]+.)*)([0-9]{5})?.(([a-z\'']+.)*)$",
    "prefix"   : r"",
    "pumpable" : r"aaa{",
    "suffix"   : r"aa00!",
    "n"        : 5
  },
# = [99] =
# INPUT: ^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*\s+<(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,3})>$|^(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,3})$
# PARSE: OK
# SIZE: 61
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*
# PREFIX: A
# PUMPABLE: A
# SUFFIX:
#
# NOTES: Python does not seem to exhibit an exponential execution time for n < 6, but the Kleene in question is
# clearly vulnerable for the pumpable string "A". This is probably due to python calculating a minimum input length
# that the expression is capable of matching, and using that for early rejection.
#
  {
    "index"    : "99", 
    "exp"      : r"^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*\s+<(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,3})>$|^(\w[-._\w]*\w@\w[-._\w]*\w\.\w{2,3})$",
    "prefix"   : r"A",
    "pumpable" : r"A",
    "suffix"   : r"",
    "n"        : 6
  },
# = [123] =
# INPUT: ^([a-zA-Z0-9][a-zA-Z0-9_]*(\.{0,1})?[a-zA-Z0-9\-_]+)*(\.{0,1})@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|([a-zA-Z0-9\-]+(\.([a-zA-Z]{2,10}))(\.([a-zA-Z]{2,10}))?(\.([a-zA-Z]{2,10}))?))[\s]*$
# PARSE: OK
# SIZE: 222
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z0-9][a-zA-Z0-9_]*(\.{0,1})?[a-zA-Z0-9\-_]+)*
# PREFIX:
# PUMPABLE: A0
# SUFFIX:
  {
    "index"    : "123", 
    "exp"      : r"^([a-zA-Z0-9][a-zA-Z0-9_]*(\.{0,1})?[a-zA-Z0-9\-_]+)*(\.{0,1})@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|([a-zA-Z0-9\-]+(\.([a-zA-Z]{2,10}))(\.([a-zA-Z]{2,10}))?(\.([a-zA-Z]{2,10}))?))[\s]*$",
    "prefix"   : r"",
    "pumpable" : r"A0",
    "suffix"   : r"",
    "n"        : 4
  },
# = [137] =
# INPUT: ^\\(\\[\w-]+){1,}(\\[\w-()]+(\s[\w-()]+)*)+(\\(([\w-()]+(\s[\w-()]+)*)+\.[\w]+)?)?$
# PARSE: OK
# SIZE: 82
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([\w-()]+(\s[\w-()]+)*)+
# PREFIX: \\a\a( a\(
# PUMPABLE: 0(
# SUFFIX: \x00
#
# Python cannot parse expressions like [\w-()]. This expression is quite questionable itself, as it
# seems to mix a pre-defined character class (\w) with a usual character range (x-y). Below I have
# modified the expression so that the predefined class is expanded out to its full form: [a-zA-Z0-9_]
# and interchanged () and - to make it a parsable expression. 
#
  {
    "index"    : "137", 
    "exp"      : r"^\\(\\[a-zA-Z0-9_-]+){1,}(\\[a-zA-Z0-9_()-]+(\s[a-zA-Z0-9_()-]+)*)+(\\(([a-zA-Z0-9_()-]+(\s[a-zA-Z0-9_()-]+)*)+\.[a-zA-Z0-9_]+)?)?$",
    "prefix"   : r"\\a\a( a\(",
    "pumpable" : r"0(",
    "suffix"   : "\x00",
    "notes"    : "modified - see inline comments",
    "n"        : 4,
  },
# = [295] =
# INPUT: ^(([a-zA-Z0-9]+([\-])?[a-zA-Z0-9]+)+(\.)?)+[a-zA-Z]{2,6}$
# PARSE: OK
# SIZE: 89
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([a-zA-Z0-9]+([\-])?[a-zA-Z0-9]+)+(\.)?)+
# PREFIX: a0
# PUMPABLE: 0AA0
# SUFFIX:
  {
    "index"    : "295", 
    "exp"      : r"^(([a-zA-Z0-9]+([\-])?[a-zA-Z0-9]+)+(\.)?)+[a-zA-Z]{2,6}$",
    "prefix"   : r"a0",
    "pumpable" : r"0AA0",
    "suffix"   : r"",
    "n"        : 1
  },
# = [299] =
# INPUT: ([A-Za-z0-9.]+\s*)+,
# PARSE: OK
# SIZE: 17
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([A-Za-z0-9.]+\s*)+
# PREFIX: .
# PUMPABLE: ..
# SUFFIX:
  {
    "index"    : "299", 
    "exp"      : r"([A-Za-z0-9.]+\s*)+,",
    "prefix"   : r".",
    "pumpable" : r"..",
    "suffix"   : r"",
    "n"        : 5
  },
# = [301] =
# INPUT: ^(ht|f)tp(s?)\:\/\/(([a-zA-Z0-9\-\._]+(\.[a-zA-Z0-9\-\._]+)+)|localhost)(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?([\d\w\.\/\%\+\-\=\&\?\:\\\"\'\,\|\~\;]*)$
# PARSE: OK
# SIZE: 64
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\.[a-zA-Z0-9\-\._]+)+
# PREFIX: https://localhosta.-
# PUMPABLE: .-.-
# SUFFIX: !
#
# Python cannot parse this, need to investigate. 
#
  {
    "index"    : "301", 
    "exp"      : r"",
    "prefix"   : r".",
    "pumpable" : r"..",
    "suffix"   : r"",
    "n"        : 5,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [329] =
# INPUT: ^([a-zA-Z0-9]+)([\._-]?[a-zA-Z0-9]+)*@([a-zA-Z0-9]+)([\._-]?[a-zA-Z0-9]+)*([\.]{1}[a-zA-Z0-9]{2,})+$
# PARSE: OK
# SIZE: 47
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([\._-]?[a-zA-Z0-9]+)*
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX:
  {
    "index"    : "329", 
    "exp"      : r"^([a-zA-Z0-9]+)([\._-]?[a-zA-Z0-9]+)*@([a-zA-Z0-9]+)([\._-]?[a-zA-Z0-9]+)*([\.]{1}[a-zA-Z0-9]{2,})+$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [332] =
# INPUT: ^([a-z0-9]+([\-a-z0-9]*[a-z0-9]+)?\.){0,}([a-z0-9]+([\-a-z0-9]*[a-z0-9]+)?){1,63}(\.[a-z0-9]{2,7})+$
# PARSE: OK
# SIZE: 27491
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-z0-9]+([\-a-z0-9]*[a-z0-9]+)?\.){0,}
# PREFIX:
# PUMPABLE: 0000000000000000000000000000000000000000000000000000000000000000.
# SUFFIX:
  {
    "index"    : "332", 
    "exp"      : r"^([a-z0-9]+([\-a-z0-9]*[a-z0-9]+)?\.){0,}([a-z0-9]+([\-a-z0-9]*[a-z0-9]+)?){1,63}(\.[a-z0-9]{2,7})+",
    "prefix"   : r"",
    "pumpable" : r"0000000000000000000000000000000000000000000000000000000000000000.",
    "suffix"   : r"",
    "n"        : 0,
    "skip"     : True,
    "notes"    : "skipped - python hangs"
  },
# = [357] =
# INPUT: ^(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&%\$\-]+)*@)?((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)?(/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-@]*)*$
# PARSE: OK
# SIZE: 153
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-@]*)*
# PREFIX: http://a.aA
# PUMPABLE: /!/0
# SUFFIX: !
  {
    "index"    : "357", 
    "exp"      : r"^(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&%\$\-]+)*@)?((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)?(/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-@]*)*$",
    "prefix"   : r"http://a.aA",
    "pumpable" : r"/!/0",
    "suffix"   : r"!",
    "n"        : 10
  },
# = [360] =
# INPUT: <select(.|\n)*?selected(.|\n)*?>(.*?)</option>(.|\n)*?</select>
# PARSE: OK
# SIZE: 57
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n)*?
# PREFIX: <select
# PUMPABLE: \x0a
# SUFFIX:
#
# Notes: Python seems to optimize away obvious mismatches. In the following case, n < 26 leads
# to an immediate rejection, uncomment the "skip" like to observe python hanging. Looks like
# python calculates a minimum input length based on the input expression and uses that for early
# rejection.
#
  {
    "index"    : "360", 
    "exp"      : r"<select(.|\n)*?selected(.|\n)*?>(.*?)</option>(.|\n)*?</select>",
    "flags"    : re.DOTALL,
    "prefix"   : r"<select",
    "pumpable" : "\x0a",
    "suffix"   : r"",
    "n"        : 26,
    "skip"     : True,
    "notes"    : "see inline comments (hangs)"
  },
# = [361] =
# INPUT: <textarea(.|\n)*?>((.|\n)*?)</textarea>
# PARSE: OK
# SIZE: 36
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n)*?
# PREFIX: <textarea
# PUMPABLE: \x0a
# SUFFIX:
#
# Same as above (n >= 12).
#
  {
    "index"    : "361", 
    "exp"      : r"<textarea(.|\n)*?>((.|\n)*?)</textarea>",
    "flags"    : re.DOTALL,
    "prefix"   : r"<textarea",
    "pumpable" : "\x0a",
    "suffix"   : r"",
    "n"        : 12
  },
# = [394] =
# INPUT: ^([\!#\$%&'\*\+/\=?\^`\{\|\}~a-zA-Z0-9_-]+[\.]?)+[\!#\$%&'\*\+/\=?\^`\{\|\}~a-zA-Z0-9_-]+@{1}((([0-9A-Za-z_-]+)([\.]{1}[0-9A-Za-z_-]+)*\.{1}([A-Za-z]){1,6})|(([0-9]{1,3}[\.]{1}){3}([0-9]{1,3}){1}))$
# PARSE: OK
# SIZE: 137
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([\!#\$%&'\*\+/\=?\^`\{\|\}~a-zA-Z0-9_-]+[\.]?)+
# PREFIX: !
# PUMPABLE: !!
# SUFFIX:
  {
    "index"    : "394", 
    "exp"      : r"^([\!#\$%&'\*\+/\=?\^`\{\|\}~a-zA-Z0-9_-]+[\.]?)+[\!#\$%&'\*\+/\=?\^`\{\|\}~a-zA-Z0-9_-]+@{1}((([0-9A-Za-z_-]+)([\.]{1}[0-9A-Za-z_-]+)*\.{1}([A-Za-z]){1,6})|(([0-9]{1,3}[\.]{1}){3}([0-9]{1,3}){1}))$",
    "prefix"   : r"!",
    "pumpable" : r"!!",
    "suffix"   : r"",
    "n"        : 5
  },
# = [404] =
# INPUT: ^(/w|/W|[^<>+?$%{}&])+$
# PARSE: OK
# SIZE: 22
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (/w|/W|[^<>+?$%{}&])+
# PREFIX: 0
# PUMPABLE: /W
# SUFFIX: $
  {
    "index"    : "404", 
    "exp"      : r"^(/w|/W|[^<>+?$%{}&])+$",
    "prefix"   : r"0",
    "pumpable" : r"/W",
    "suffix"   : r"$",
    "n"        : 10
  },
# = [409] =
# INPUT: ^((?:(?:(?:[a-zA-Z0-9][\.\-\+_]?)*)[a-zA-Z0-9])+)\@((?:(?:(?:[a-zA-Z0-9][\.\-_]?){0,62})[a-zA-Z0-9])+)\.([a-zA-Z0-9]{2,6})$
# PARSE: OK
# SIZE: 15794
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:(?:[a-zA-Z0-9][\.\-\+_]?)*)[a-zA-Z0-9])+
# PREFIX: 0
# PUMPABLE: 0a
# SUFFIX:
  {
    "index"    : "409", 
    "exp"      : r"^((?:(?:(?:[a-zA-Z0-9][\.\-\+_]?)*)[a-zA-Z0-9])+)\@((?:(?:(?:[a-zA-Z0-9][\.\-_]?){0,62})[a-zA-Z0-9])+)\.([a-zA-Z0-9]{2,6})$",
    "prefix"   : r"0",
    "pumpable" : r"0a",
    "suffix"   : r"",
    "n"        : 5
  },
# = [410] =
# INPUT: ^((?:(?:(?:\w[\.\-\+]?)*)\w)+)\@((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$
# PARSE: OK
# SIZE: 15794
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:(?:\w[\.\-\+]?)*)\w)+
# PREFIX: 0
# PUMPABLE: 00
# SUFFIX:
  {
    "index"    : "410", 
    "exp"      : r"^((?:(?:(?:\w[\.\-\+]?)*)\w)+)\@((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$",
    "prefix"   : r"0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "n"        : 5
  },
# = [436] =
# INPUT: ^(http(s?)\:\/\/)*[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?$
# PARSE: OK
# SIZE: 46
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([-.\w]*[0-9a-zA-Z])*
# PREFIX: i
# PUMPABLE: 00
# SUFFIX: !
#
# Python cannot parse this, need to investigate. 
#
  {
    "index"    : "436", 
    "exp"      : r"",
    "prefix"   : r"i",
    "pumpable" : r"00",
    "suffix"   : r"!",
    "n"        : 5,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [447] =
# INPUT: ^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*(\.[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*)*\.([a-z]{2}|xn\-{2}[a-z0-9]{4,18}|arpa|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx)$
# PARSE: OK
# SIZE: 276
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\.[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*)*
# PREFIX: a.a@0
# PUMPABLE: .ya0
# SUFFIX:
  {
    "index"    : "447", 
    "exp"      : r"^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*(\.[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*)*\.([a-z]{2}|xn\-{2}[a-z0-9]{4,18}|arpa|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx)$",
    "prefix"   : r"a.a@0",
    "pumpable" : r".ya0",
    "suffix"   : r"",
    "n"        : 4
  },
# = [522] =
# INPUT: /\*.*((\r\n).+)+\*/
# PARSE: OK
# SIZE: 24
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: *((\r\n).+)
# PREFIX: *\x0d\x0a!
# PUMPABLE: \x0d\x0a+\x0d\x0a+
# SUFFIX:
  {
    "index"    : "522", 
    "exp"      : r"\*.*((\r\n).+)+\*",
    "flags"    : re.DOTALL,
    "prefix"   : "*\x0d\x0a!",
    "pumpable" : "\x0d\x0a+\x0d\x0a+",
    "suffix"   : r"",
    "n"        : 4
  },
# = [532] =
# INPUT: (/\*[\d\D]*?\*/)|(\/\*(\s*|.*?)*\*\/)|(\/\/.*)|(/\\*[\\d\\D]*?\\*/)|([\r\n ]*//[^\r\n]*)+
# PARSE: OK
# SIZE: 62
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*|.*?)*
# PREFIX: /*
# PUMPABLE: +
# SUFFIX:
  {
    "index"    : "532", 
    "exp"      : r"",
    "prefix"   : r"/*",
    "pumpable" : r"+",
    "suffix"   : r"",
    "n"        : 4,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [539] =
# INPUT: ^((([a-z0-9])+([\w.-]{1})?)+([^\W_]{1}))+@((([a-z0-9])+([\w-]{1})?)+([^\W_]{1}))+\.[a-z]{2,3}(\.[a-z]{2,4})?$
# PARSE: OK
# SIZE: 161
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([a-z0-9])+([\w.-]{1})?)+
# PREFIX: 0
# PUMPABLE: a00
# SUFFIX:
  {
    "index"    : "539", 
    "exp"      : r"^((([a-z0-9])+([\w.-]{1})?)+([^\W_]{1}))+@((([a-z0-9])+([\w-]{1})?)+([^\W_]{1}))+\.[a-z]{2,3}(\.[a-z]{2,4})?$",
    "prefix"   : r"0",
    "pumpable" : r"a00",
    "suffix"   : r"",
    "n"        : 3
  },
# = [548] =
# INPUT: (\s)*(int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*(\s)*(\()(\s)*((int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*((\s)*[,](\s)*(int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*)*)?(\s)*(\))(\s)*;
# PARSE: OK
# SIZE: 236
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\s)*[,](\s)*(int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*)*
# PREFIX: int & a (int a
# PUMPABLE:  ,int\x09\x09a
# SUFFIX:
  {
    "index"    : "548", 
    "exp"      : r"(\s)*(int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*(\s)*(\()(\s)*((int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*((\s)*[,](\s)*(int|void|float|char|double|string)((\s)|(\*))*(\&?)(\s)+([a-z])([a-z0-9])*)*)?(\s)*(\))(\s)*;",
    "prefix"   : r"int & a (int a",
    "pumpable" : " ,int\x09\x09a",
    "suffix"   : r"",
    "n"        : 6
  },
# = [560] =
# INPUT: /class\s+([a-z0-9_]+)(?:\s+extends\s+[a-z0-9_]+)?(?:\s+implements\s+(?:[a-z0-9_]+\s*,*\s*)+)?\s*\{/Usi
# PARSE: OK
# SIZE: 72
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: +(?:[a-z0-9_]+\s*,*\s*)
# PREFIX: class a extends a implements 0
# PUMPABLE: 0\x09
# SUFFIX:
  {
    "index"    : "560", 
    "exp"      : r"class\s+([a-z0-9_]+)(?:\s+extends\s+[a-z0-9_]+)?(?:\s+implements\s+(?:[a-z0-9_]+\s*,*\s*)+)?\s*\{",
    "prefix"   : r"class a extends a implements 0",
    "pumpable" : "0\x09",
    "suffix"   : r"",
    "n"        : 6
  },
# = [569] =
# INPUT: ^(\w+([_.]{1}\w+)*@\w+([_.]{1}\w+)*\.[A-Za-z]{2,3}[;]?)*$
# PARSE: OK
# SIZE: 36
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\w+([_.]{1}\w+)*@\w+([_.]{1}\w+)*\.[A-Za-z]{2,3}[;]?)*
# PREFIX:
# PUMPABLE: 0__@0.Aa__.AA
# SUFFIX: !
  {
    "index"    : "569", 
    "exp"      : r"^(\w+([_.]{1}\w+)*@\w+([_.]{1}\w+)*\.[A-Za-z]{2,3}[;]?)*$",
    "prefix"   : r"",
    "pumpable" : r"0__@0.Aa__.AA",
    "suffix"   : r"!",
    "n"        : 4
  },
# = [580] =
# INPUT: <blockquote>(?:\s*([^<]+)<br>\s*)+</blockquote>
# PARSE: OK
# SIZE: 53
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:\s*([^<]+)<br>\s*)+
# PREFIX: <blockquote> \x00<br>
# PUMPABLE: \x09\x09<br>
# SUFFIX:
  {
    "index"    : "580", 
    "exp"      : r"<blockquote>(?:\s*([^<]+)<br>\s*)+</blockquote>",
    "prefix"   : "<blockquote> \x00<br>",
    "pumpable" : "\x09\x09<br>",
    "suffix"   : r"",
    "n"        : 5
  },
# = [603] =
# INPUT: ^\d*((\.\d+)?)*$
# PARSE: OK
# SIZE: 18
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\.\d+)?)*
# PREFIX:
# PUMPABLE: .0
# SUFFIX: !
#
# This is of kind ^(a?)*$, which is trivially vulnerable (the input string 'a' may
# be matched in more than one way). However, python seem to work around this type
# of vulnerabilities.
#
  {
    "index"    : "603", 
    "exp"      : r"^\d*((\.\d+)?)*$",
    "prefix"   : r"",
    "pumpable" : r".0",
    "suffix"   : r"!",
    "n"        : 5,
    "notes"    : "see inline comments"
  },
# = [605] =
# INPUT: [a-zA-Z0-9_\\-]+@([a-zA-Z0-9_\\-]+\\.)+(com)
# PARSE: OK
# SIZE: 25
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z0-9_\\-]+\\.)+
# PREFIX: a@a\{
# PUMPABLE: d\\\\d
# SUFFIX:
  {
    "index"    : "605", 
    "exp"      : r"[a-zA-Z0-9_\\-]+@([a-zA-Z0-9_\\-]+\\.)+(com)",
    "prefix"   : r"a@a\{",
    "pumpable" : r"d\\\\d",
    "suffix"   : r"",
    "n"        : 4
  },
# = [638] =
# INPUT: /^([a-z0-9])(([\-.]|[_]+)?([a-z0-9]+))*(@)([a-z0-9])((([-]+)?([a-z0-9]+))?)*((.[a-z]{2,3})?(.[a-z]{2,6}))$/i
# PARSE: OK
# SIZE: 82
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: )(([\-.]|[_]+)?([a-z0-9]+))
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX:
  {
    "index"    : "638", 
    "exp"      : r"^([a-z0-9])(([\-.]|[_]+)?([a-z0-9]+))*(@)([a-z0-9])((([-]+)?([a-z0-9]+))?)*((.[a-z]{2,3})?(.[a-z]{2,6}))$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 4
  },
# = [652] =
# INPUT: ^([a-zA-z]:((\\([-*\.*\w+\s+\d+]+)|(\w+)\\)+)(\w+.zip)|(\w+.ZIP))$
# PARSE: OK
# SIZE: 59
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\([-*\.*\w+\s+\d+]+)|(\w+)\\)+
# PREFIX: a:\\x09
# PUMPABLE: a\\\x0900zip\
# SUFFIX:
#
# Input has a combination of backslashes and hexadecimal characters (\x09) which makes it difficult to use raw Python
# strings (r""). The hexadecimal was replaced with a literal which is also matched by both the branches within the 
# vulnerable Kleene expression, and the final '\' was replaced with '\\' due to http://stackoverflow.com/q/647769/591181
  {
    "index"    : "652", 
    "exp"      : r"^([a-zA-z]:((\\([-*\.*\w+\s+\d+]+)|(\w+)\\)+)(\w+.zip)|(\w+.ZIP))$",
    "prefix"   : r"a:\p",
    "pumpable" : r"a\p00zip\\",
    "suffix"   : r"",
    "n"        : 4,
    "notes"    : "modified - see inline comments",
  },
# = [697] =
# INPUT: ^(([a-zA-Z]:|\\)\\)?(((\.)|(\.\.)|([^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?))\\)*[^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?$
# PARSE: OK
# SIZE: 59
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (((\.)|(\.\.)|([^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?))\\)*
# PREFIX:
# PUMPABLE: {\x00\
# SUFFIX:
  {
    "index"    : "697", 
    "exp"      : r'^(([a-zA-Z]:|\\)\\)?(((\.)|(\.\.)|([^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?))\\)*[^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?$',
    "prefix"   : r"",
    "pumpable" : "{\x00\\",
    "suffix"   : r"",
    "n"        : 5
  },
# = [721] =
# INPUT: ^\s*((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\,?\s+((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\,?\s+((?:[A-Za-z]+\x20*)+)\,\s+(A[LKSZRAP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+(\d+(?:-\d+)?)\s*$
# PARSE: OK
# SIZE: 692
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[A-Za-z]+\x20*)+
# PREFIX: 0 aS.  V
# PUMPABLE: VV
# SUFFIX:
  {
    "index"    : "721", 
    "exp"      : "^\s*((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\,?\s+((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\,?\s+((?:[A-Za-z]+\x20*)+)\,\s+(A[LKSZRAP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\s+(\d+(?:-\d+)?)\s*$",
    "prefix"   : r"0 aS.  V",
    "pumpable" : r"VV",
    "suffix"   : r"",
    "n"        : 5
  },
# = [726] =
# INPUT: ^(\d?)*(\.\d{1}|\.\d{2})?$
# PARSE: OK
# SIZE: 21
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\d?)*
# PREFIX:
# PUMPABLE: 0
# SUFFIX: !
#
# See notes for [603]
#
  {
    "index"    : "726", 
    "exp"      : r"^(\d?)*(\.\d{1}|\.\d{2})?$",
    "prefix"   : r"",
    "pumpable" : r"0",
    "suffix"   : r"!",
    "n"        : 5,
    "notes"    : "see inline comments"
  },
# = [751] =
# INPUT: <img\s((width|height|alt|align|style)="[^"]*"\s)*src="(\/?[a-z0-9_-]\/?)+\.(png|jpg|jpeg|gif)"(\s(width|height|alt|align|style)="[^"]*")*\s*\/>
# PARSE: OK
# SIZE: 132
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\/?[a-z0-9_-]\/?)+
# PREFIX: <img src="0
# PUMPABLE: 0/-
# SUFFIX:
  {
    "index"    : "751", 
    "exp"      : r'<img\s((width|height|alt|align|style)="[^"]*"\s)*src="(\/?[a-z0-9_-]\/?)+\.(png|jpg|jpeg|gif)"(\s(width|height|alt|align|style)="[^"]*")*\s*\/>',
    "prefix"   : r'<img src="0',
    "pumpable" : r"0/-",
    "suffix"   : r"",
    "n"        : 10
  },
# = [758] =
# INPUT: ([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$
# PARSE: OK
# SIZE: 65
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([-.\w]*[0-9a-zA-Z])*
# PREFIX: 0
# PUMPABLE: 00
# SUFFIX:
  {
    "index"    : "758", 
    "exp"      : r"([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    "prefix"   : r"0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "n"        : 5
  },
# = [777] =
# INPUT: ^[A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})$
# PARSE: OK
# SIZE: 39
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([_\.\-]?[a-zA-Z0-9]+)*
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX:
  {
    "index"    : "777", 
    "exp"      : r"^[A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [819] =
# INPUT: ^[\s]*(?:(Public|Private)[\s]+(?:[_][\s]*[\n\r]+)?)?(Function|Sub)[\s]+(?:[_][\s]*[\n\r]+)?([a-zA-Z][\w]{0,254})(?:[\s\n\r_]*\((?:[\s\n\r_]*([a-zA-Z][\w]{0,254})[,]?[\s]*)*\))?
# PARSE: OK
# SIZE: 65358
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[\s\n\r_]*([a-zA-Z][\w]{0,254})[,]?[\s]*)*
# PREFIX: Public _\x0dFunction _\x0da(
# PUMPABLE: A\x09A
# SUFFIX:
  {
    "index"    : "819", 
    "exp"      : r"^[\s]*(?:(Public|Private)[\s]+(?:[_][\s]*[\n\r]+)?)?(Function|Sub)[\s]+(?:[_][\s]*[\n\r]+)?([a-zA-Z][\w]{0,254})(?:[\s\n\r_]*\((?:[\s\n\r_]*([a-zA-Z][\w]{0,254})[,]?[\s]*)*\))?",
    "prefix"   : "Public _\x0dFunction _\x0da(",
    "pumpable" : "A\x09A",
    "suffix"   : r"",
    "n"        : 5
  },
# = [822] =
# INPUT: (?:@[A-Z]\w*\s+)*(?:(?:public|private|protected)\s+)?(?:(?:(?:abstract|final|native|transient|static|synchronized)\s+)*(?:<(?:\?|[A-Z]\w*)(?:\s+(?:extends|super)\s+[A-Z]\w*)?(?:(?:,\s*(?:\?|[A-Z]\w*))(?:\s+(?:extends|super)\s+[A-Z]\w*)?)*>\s+)?(?:(?:(?:[A-Z]\w*(?:<[A-Z]\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\[\]))*)|void)+)\s+(([a-zA-Z]\w*)\s*\(\s*(((?:[A-Z]\w*(?:<(?:\?|[A-Z]\w*)(?:\s+(?:extends|super)\s+[A-Z]\w*)?(?:(?:,\s*(?:\?|[A-Z]\w*))(?:\s+(?:extends|super)\s+[A-Z]\w*)?)*>)?|int|float|double|char|boolean|byte|long|short)(?:(?:\[\])|\.\.\.)?\s+[a-z]\w*)(?:,\s*((?:[A-Z]\w*(?:<[A-Z]\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\[\])|\.\.\.)?\s+[a-z]\w*))*)?\s*\))
# PARSE: OK
# SIZE: 520
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:(?:[A-Z]\w*(?:<[A-Z]\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\[\]))*)|void)+
# PREFIX: A
# PUMPABLE: AA
# SUFFIX: 
  {
    "index"    : "822", 
    "exp"      : r"(?:@[A-Z]\w*\s+)*(?:(?:public|private|protected)\s+)?(?:(?:(?:abstract|final|native|transient|static|synchronized)\s+)*(?:<(?:\?|[A-Z]\w*)(?:\s+(?:extends|super)\s+[A-Z]\w*)?(?:(?:,\s*(?:\?|[A-Z]\w*))(?:\s+(?:extends|super)\s+[A-Z]\w*)?)*>\s+)?(?:(?:(?:[A-Z]\w*(?:<[A-Z]\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\[\]))*)|void)+)\s+(([a-zA-Z]\w*)\s*\(\s*(((?:[A-Z]\w*(?:<(?:\?|[A-Z]\w*)(?:\s+(?:extends|super)\s+[A-Z]\w*)?(?:(?:,\s*(?:\?|[A-Z]\w*))(?:\s+(?:extends|super)\s+[A-Z]\w*)?)*>)?|int|float|double|char|boolean|byte|long|short)(?:(?:\[\])|\.\.\.)?\s+[a-z]\w*)(?:,\s*((?:[A-Z]\w*(?:<[A-Z]\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\[\])|\.\.\.)?\s+[a-z]\w*))*)?\s*\))",
    "prefix"   : r"A",
    "pumpable" : r"AA",
    "suffix"   : r"",
    "n"        : 5
  },
# = [849] =
# INPUT: \w?<\s?\/?[^\s>]+(\s+[^"'=]+(=("[^"]*")|('[^\']*')|([^\s"'>]*))?)*\s*\/?>
# PARSE: OK
# SIZE: 52
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s+[^"'=]+(=("[^"]*")|('[^\']*')|([^\s"'>]*))?)*
# PREFIX: a<0
# PUMPABLE: \x09\x090
# SUFFIX: 
  {
    "index"    : "849", 
    "exp"      : r'''\w?<\s?\/?[^\s>]+(\s+[^"'=]+(=("[^"]*")|('[^\']*')|([^\s"'>]*))?)*\s*\/?>''',
    "prefix"   : r"a<0",
    "pumpable" : "\x09\x090",
    "suffix"   : r"",
    "n"        : 3
  },
# = [858] =
# INPUT: "([^"](?:\\.|[^\\"]*)*)"
# PARSE: OK
# SIZE: 14
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:\\.|[^\\"]*)*
# PREFIX: "!
# PUMPABLE: !
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: (b|[^a]*)*
  {
    "index"    : "858", 
    "exp"      : r"",
    "prefix"   : r'"!',
    "pumpable" : r"!",
    "suffix"   : r"",
    "n"        : 3,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [894] =
# INPUT: ^<\!\-\-(.*)+(\/){0,1}\-\->$
# PARSE: OK
# SIZE: 26
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.*)+
# PREFIX: <!--
# PUMPABLE: 0
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: (.*)+
  {
    "index"    : "894", 
    "exp"      : r"",
    "prefix"   : r'<!--',
    "pumpable" : r"0",
    "suffix"   : r"",
    "n"        : 3,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [939] =
# INPUT: ^\s*((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\,?\s+((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\,?\s+((?:[A-Za-z]+\x20*)+)\,\s+(A[BLKSZRAP]|BC|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ABDEHINOPST]|N[BCDEHJLMSTUVY]|O[HKRN]|P[AERW]|QC|RI|S[CDK]|T[NX]|UT|V[AIT]|W[AIVY]|YT)\s+((\d{5}-\d{4})|(\d{5})|([AaBbCcEeGgHhJjKkLlMmNnPpRrSsTtVvXxYy]\d[A-Za-z]\s?\d[A-Za-z]\d))\s*$
# PARSE: OK
# SIZE: 724
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[A-Za-z]+\x20*)+
# PREFIX: 0 aS.  V
# PUMPABLE: VV
# SUFFIX: 
  {
    "index"    : "939", 
    "exp"      : r"^\s*((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\,?\s+((?:(?:\d+(?:\x20+\w+\.?)+(?:(?:\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\.?)?)|(?:(?:P\.\x20?O\.|P\x20?O)\x20*Box\x20+\d+)|(?:General\x20+Delivery)|(?:C[\\\/]O\x20+(?:\w+\x20*)+))\,?\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\x23)\.?\x20*(?:[a-zA-Z0-9\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\,?\s+((?:[A-Za-z]+\x20*)+)\,\s+(A[BLKSZRAP]|BC|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ABDEHINOPST]|N[BCDEHJLMSTUVY]|O[HKRN]|P[AERW]|QC|RI|S[CDK]|T[NX]|UT|V[AIT]|W[AIVY]|YT)\s+((\d{5}-\d{4})|(\d{5})|([AaBbCcEeGgHhJjKkLlMmNnPpRrSsTtVvXxYy]\d[A-Za-z]\s?\d[A-Za-z]\d))\s*$",
    "prefix"   : r"0 aS.  V",
    "pumpable" : r"VV",
    "suffix"   : r"",
    "n"        : 5
  },
# = [944] =
# INPUT: ^((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*);|(0|[1-9]+[0-9]*);)*?((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*)|(0|[1-9]+[0-9]*)){1}$
# PARSE: OK
# SIZE: 68
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*);|(0|[1-9]+[0-9]*);)*?
# PREFIX: 
# PUMPABLE: 11;
# SUFFIX: 
  {
    "index"    : "944", 
    "exp"      : r"^((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*);|(0|[1-9]+[0-9]*);)*?((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*)|(0|[1-9]+[0-9]*)){1}$",
    "prefix"   : r"",
    "pumpable" : r"11;",
    "suffix"   : r"",
    "n"        : 5
  },
# = [974] =
# INPUT: ^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.(txt|TXT)$
# PARSE: OK
# SIZE: 51
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\(\w[\w ]*.*))+
# PREFIX: a:\0
# PUMPABLE: \0\0
# SUFFIX: 
  {
    "index"    : "974", 
    "exp"      : r"^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.(txt|TXT)$",
    "prefix"   : r"a:\0",
    "pumpable" : r"\0\0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [983] =
# INPUT: ^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.(jpg|JPG)$
# PARSE: OK
# SIZE: 51
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\(\w[\w ]*.*))+
# PREFIX: a:\0
# PUMPABLE: \0\0
# SUFFIX: 
  {
    "index"    : "983", 
    "exp"      : r"^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w ]*.*))+\.(jpg|JPG)$",
    "prefix"   : r"a:\0",
    "pumpable" : r"\0\0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [1013] =
# INPUT: ^([1-9]{1}[0-9]{0,7})+((,[1-9]{1}[0-9]{0,7}){0,1})+$
# PARSE: OK
# SIZE: 173
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((,[1-9]{1}[0-9]{0,7}){0,1})+
# PREFIX: 1
# PUMPABLE: ,1
# SUFFIX: !
#
# See notes for [603]
#
  {
    "index"    : "1013", 
    "exp"      : r"^([1-9]{1}[0-9]{0,7})+((,[1-9]{1}[0-9]{0,7}){0,1})+$",
    "prefix"   : r"1",
    "pumpable" : r",1",
    "suffix"   : r"!",
    "n"        : 5,
    "notes"    : "see inline comments"
  },
# = [1032] =
# INPUT: ^(\S+\.{1})(\S+\.{1})*([^\s\.]+\s*)$
# PARSE: OK
# SIZE: 23
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\S+\.{1})*
# PREFIX: !.
# PUMPABLE: ....
# SUFFIX: 
  {
    "index"    : "1032", 
    "exp"      : r"^(\S+\.{1})(\S+\.{1})*([^\s\.]+\s*)$",
    "prefix"   : r"!.",
    "pumpable" : r"....",
    "suffix"   : r"",
    "n"        : 5
  },
# = [1033] =
# INPUT: ^jdbc:db2://((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:(?:(?:[A-Z|a-z])(?:[\w|-]){0,61}(?:[\w]?[.]))*)(?:(?:[A-Z|a-z])(?:[\w|-]){0,61}(?:[\w]?)))):([0-9]{1,5})/([0-9|A-Z|a-z|_|#|$]{1,16})$
# PARSE: OK
# SIZE: 4155
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:[A-Z|a-z])(?:[\w|-]){0,61}(?:[\w]?[.]))*
# PREFIX: jdbc:db2://
# PUMPABLE: A0.
# SUFFIX: 
  {
    "index"    : "1033", 
    "exp"      : r"^jdbc:db2://((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:(?:(?:[A-Z|a-z])(?:[\w|-]){0,61}(?:[\w]?[.]))*)(?:(?:[A-Z|a-z])(?:[\w|-]){0,61}(?:[\w]?)))):([0-9]{1,5})/([0-9|A-Z|a-z|_|#|$]{1,16})$",
    "prefix"   : r"jdbc:db2://",
    "pumpable" : r"A0.",
    "suffix"   : r"",
    "n"        : 7
  },
# = [1052] =
# INPUT: (http):\\/\\/[\\w\\-_]+(\\.[\\w\\-_]+)+(\\.[\\w\\-_]+)(\\/)([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?^=%&/~\\+#]+)(\\/)((\\d{8}-)|(\\d{9}-)|(\\d{10}-)|(\\d{11}-))+([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?+html^])?
# PARSE: OK
# SIZE: 178
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\.[\\w\\-_]+)+
# PREFIX: http:\/\/w\w-
# PUMPABLE: \w-\\-
# SUFFIX: 
#
# Note: python interprets the range [\\-_] as [\-_] whereas RXXR thinks its just the three symbols '\', '-' and '_'.
# I suppose it can be argued in both ways; on the one hand there is no point in escaping meta-characters (like *)
# within a [] block, but then again it probably makes sense to escape '\' specifically as it is some kind of a
# meta-meta character. But then again, python interprets [\\w] as just the two symbols '\' and 'w', which is
# not consistent with what it does with [\\-_]. RXXR should probably be improved so that it detects this specific
# case (i.e. [\\-x] where x is any symbol), but this is ugly, I'd rather leave it as it is. In the meantime I have
# changed the original expression below so that it behaves like what RXXR thinks it is. This whole mess is not really
# relevant to the actual vulnerability here though, which can be reduced to (\\[\\w]*)*, where there is a redundant '\'.
#
  {
    "index"    : "1052", 
    "exp"      : r"(http):\\/\\/[\\w\\_-]+(\\.[\\w\\_-]+)+(\\.[\\w\\-_]+)(\\/)([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?^=%&/~\\+#]+)(\\/)((\\d{8}-)|(\\d{9}-)|(\\d{10}-)|(\\d{11}-))+([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?+html^])?",
    "prefix"   : r"http:\/\/w\w-",
    "pumpable" : r"\w-\\-",
    "suffix"   : r"",
    "n"        : 5,
    "notes"    : "modified - see inline comments"
  },
# = [1054] =
# INPUT: href\s*=\s*\"((\/)([i])(\/)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#]+)*)\"
# PARSE: OK
# SIZE: 35
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#]+)*
# PREFIX: href="/i/
# PUMPABLE: /0
# SUFFIX: 
#
# See notes for [652]
#
  {
    "index"    : "1054", 
    "exp"      : r"href\s*=\s*\"((\/)([i])(\/)+([a-zA-Z0-9_\-\.,@?^=%&:/~\+#]*[a-zA-Z0-9_\-\@?^=%&/~\+#]+)*)\"",
    "prefix"   : "href=\"/i/",
    "pumpable" : r"/0",
    "suffix"   : r"",
    "n"        : 3,
  },
# = [1075] =
# INPUT: (\/\*[\s\S.]+?\*\/|[/]{2,}.*|\/((\\\/)|.??)*\/[gim]{0,3}|'((\\\')|.??)*'|"((\\\")|.??)*"|-?\d+\.\d+e?-?e?\d*|-?\.\d+e-?\d+|\w+|[\[\]\(\)\{\}:=;"'\-&!|+,.\/*])
# PARSE: OK
# SIZE: 118
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\\\")|.??)*
# PREFIX: "
# PUMPABLE: ]
# SUFFIX:
# 
# Note: expressions like (.?)* are trivially vulnerable. Python seems to work around this
# type of vulnerabilities. This one is also worked around by Java. This expression is
# equivalent to (.|\epsilon)*, so a pumpable character like 'c' can be either matched
# in some iteration or not (the matcher can choose the \epsilon instead). However, from
# EKWF work we know that matching the \epsion is a death-trap: it will lead to non-
# termination. So this is why backtracking matchers do not exhibit this vulnerability.
#
  {
    "index"    : "1075", 
    "exp"      : r'''(\/\*[\s\S.]+?\*\/|[/]{2,}.*|\/((\\\/)|.??)*\/[gim]{0,3}|'((\\\')|.??)*'|"((\\\")|.??)*"|-?\d+\.\d+e?-?e?\d*|-?\.\d+e-?\d+|\w+|[\[\]\(\)\{\}:=;"'\-&!|+,.\/*])''',
    "prefix"   : r'"',
    "pumpable" : r"]",
    "suffix"   : r"",
    "n"        : 5,
    "notes"    : "see inline comments"
  },
# = [1076] =
# INPUT: (\w+[\.\_\-]*)*\w+@[\w]+(.)*\w+$
# PARSE: OK
# SIZE: 24
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\w+[\.\_\-]*)*
# PREFIX: 
# PUMPABLE: 0_
# SUFFIX: 
  {
    "index"    : "1076", 
    "exp"      : r"(\w+[\.\_\-]*)*\w+@[\w]+(.)*\w+$",
    "prefix"   : r"",
    "pumpable" : r"0_",
    "suffix"   : r"",
    "n"        : 5
  },
# = [1093] =
# INPUT: <(script|style)[^>]*?>(?:.|\n)*?</\s*\1\s*>
# PARSE: OK
# SIZE: 31
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:.|\n)*?
# PREFIX: <script>
# PUMPABLE: \x0a
# SUFFIX: 
  {
    "index"    : "1093", 
    "exp"      : r"<(script|style)[^>]*?>(?:.|\n)*?</\s*\1\s*>",
    "flags"    : re.DOTALL,
    "prefix"   : r"<script>",
    "pumpable" : "\x0a",
    "suffix"   : r"",
    "n"        : 10
  },
# = [1119] =
# INPUT: "(\\.|[^"])*"
# PARSE: OK
# SIZE: 10
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\.|[^"])*
# PREFIX: "
# PUMPABLE: \]
# SUFFIX: 
  {
    "index"    : "1119", 
    "exp"      : r'"(\\.|[^"])*"',
    "prefix"   : r'"',
    "pumpable" : "\]",
    "suffix"   : r"",
    "n"        : 10
  },
# = [1155] =
# INPUT: ^(((\\\\([^\\/:\*\?"\|<>\. ]+))|([a-zA-Z]:\\))(([^\\/:\*\?"\|<>\. ]*)([\\]*))*)$
# PARSE: OK
# SIZE: 35
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([^\\/:\*\?"\|<>\. ]*)([\\]*))*
# PREFIX: \\\x00
# PUMPABLE: \
# SUFFIX:  
  {
    "index"    : "1155", 
    "exp"      : r'^(((\\\\([^\\/:\*\?"\|<>\. ]+))|([a-zA-Z]:\\))(([^\\/:\*\?"\|<>\. ]*)([\\]*))*)$',
    "prefix"   : "\\\\\x00",
    "pumpable" : "\\",
    "suffix"   : r" ",
    "n"        : 10
  },
# = [1165] =
# INPUT: (\/\*(\s*|.*?)*\*\/)|(\/\/.*)
# PARSE: OK
# SIZE: 24
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*|.*?)*
# PREFIX: /*
# PUMPABLE: +
# SUFFIX:
#
# Note: python is unable to compile regular expressions like: (.*)*
# 
  {
    "index"    : "1165", 
    "exp"      : r"",
    "prefix"   : r"/*",
    "pumpable" : r"+",
    "suffix"   : r"",
    "n"        : 10,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [1204] =
# INPUT: ^[a-zA-Z\d]+(([\'\,\.\- #][a-zA-Z\d ])?[a-zA-Z\d]*[\.]*)*$
# PARSE: OK
# SIZE: 21
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([\'\,\.\- #][a-zA-Z\d ])?[a-zA-Z\d]*[\.]*)*
# PREFIX: 0
# PUMPABLE: .
# SUFFIX: \x00
  {
    "index"    : "1203", 
    "exp"      : r"^[a-zA-Z\d]+(([\'\,\.\- #][a-zA-Z\d ])?[a-zA-Z\d]*[\.]*)*$",
    "prefix"   : r"0",
    "pumpable" : r".x",
    "suffix"   : "\x00",
    "n"        : 5
  },
# = [1212] =
# INPUT: ^([0-9a-zA-Z]+(?:[_\.\-]?[0-9a-zA-Z]+)*[@](?:[0-9a-zA-Z]+(?:[_\.\-]?[0-9a-zA-Z]+)*\.[a-zA-Z]{2,}|(?:\d{1,}\.){3}\d{1,}))$
# PARSE: OK
# SIZE: 47
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[_\.\-]?[0-9a-zA-Z]+)*
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX: 
  {
    "index"    : "1212", 
    "exp"      : r"^([0-9a-zA-Z]+(?:[_\.\-]?[0-9a-zA-Z]+)*[@](?:[0-9a-zA-Z]+(?:[_\.\-]?[0-9a-zA-Z]+)*\.[a-zA-Z]{2,}|(?:\d{1,}\.){3}\d{1,}))$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5
  },
# = [1218] =
# INPUT: ^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*$
# PARSE: OK
# SIZE: 19
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*
# PREFIX: A
# PUMPABLE: A
# SUFFIX: \x00
  {
    "index"    : "1218", 
    "exp"      : r"^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*$",
    "prefix"   : r"A",
    "pumpable" : r"A",
    "suffix"   : "\x00",
    "n"        : 10
  },
# = [1234] =
# INPUT: ^([a-zA-Z]+[\'\,\.\-]?[a-zA-Z ]*)+[ ]([a-zA-Z]+[\'\,\.\-]?[a-zA-Z ]+)+$
# PARSE: OK
# SIZE: 48
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z]+[\'\,\.\-]?[a-zA-Z ]*)+
# PREFIX: A
# PUMPABLE: AA
# SUFFIX: 
  {
    "index"    : "1234", 
    "exp"      : r"^([a-zA-Z]+[\'\,\.\-]?[a-zA-Z ]*)+[ ]([a-zA-Z]+[\'\,\.\-]?[a-zA-Z ]+)+$",
    "prefix"   : r"A",
    "pumpable" : r"AA",
    "suffix"   : r"",
    "n"        : 3
  },
# = [1244] =
# INPUT: (<(!--|script)(.|\n[^<])*(--|script)>)|(<|<)(/?[\w!?]+)\s?[^<]*(>|>)|(\&[\w]+\;)
# PARSE: OK
# SIZE: 67
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n[^<])*
# PREFIX: <!--
# PUMPABLE: \x0at
# SUFFIX: 
  {
    "index"    : "1244", 
    "exp"      : r"(<(!--|script)(.|\n[^<])*(--|script)>)|(<|<)(/?[\w!?]+)\s?[^<]*(>|>)|(\&[\w]+\;)",
     "flags"    : re.DOTALL,
    "prefix"   : r"<!--",
    "pumpable" : "\x0at",
    "suffix"   : r"",
    "n"        : 10
  },
# = [1279] =
# INPUT: (\/\*(\s*|.*?)*\*\/)|(--.*)
# PARSE: OK
# SIZE: 24
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*|.*?)*
# PREFIX: /*
# PUMPABLE: +
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: (.*)*
#
  {
    "index"    : "1279", 
    "exp"      : r"",
    "prefix"   : r"<!--",
    "pumpable" : "\x0at",
    "suffix"   : r"",
    "n"        : 10,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [1280] =
# INPUT: ^((\d?)|(([-+]?\d+\.?\d*)|([-+]?\d*\.?\d+))|(([-+]?\d+\.?\d*\,\ ?)*([-+]?\d+\.?\d*))|(([-+]?\d*\.?\d+\,\ ?)*([-+]?\d*\.?\d+))|(([-+]?\d+\.?\d*\,\ ?)*([-+]?\d*\.?\d+))|(([-+]?\d*\.?\d+\,\ ?)*([-+]?\d+\.?\d*)))$
# PARSE: OK
# SIZE: 176
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([-+]?\d*\.?\d+\,\ ?)*
# PREFIX: 
# PUMPABLE: 00,
# SUFFIX: 
  {
    "index"    : "1280", 
    "exp"      : r"^((\d?)|(([-+]?\d+\.?\d*)|([-+]?\d*\.?\d+))|(([-+]?\d+\.?\d*\,\ ?)*([-+]?\d+\.?\d*))|(([-+]?\d*\.?\d+\,\ ?)*([-+]?\d*\.?\d+))|(([-+]?\d+\.?\d*\,\ ?)*([-+]?\d*\.?\d+))|(([-+]?\d*\.?\d+\,\ ?)*([-+]?\d+\.?\d*)))$",
    "prefix"   : r"",
    "pumpable" : r"00,",
    "suffix"   : r"",
    "n"        : 5
  },
# = [1284] =
# INPUT: ^/{1}(((/{1}\.{1})?[a-zA-Z0-9 ]+/?)+(\.{1}[a-zA-Z0-9]{2,4})?)$
# PARSE: OK
# SIZE: 48
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((/{1}\.{1})?[a-zA-Z0-9 ]+/?)+
# PREFIX: /0
# PUMPABLE: 0 
# SUFFIX: \x00
  {
    "index"    : "1284", 
    "exp"      : r"^/{1}(((/{1}\.{1})?[a-zA-Z0-9 ]+/?)+(\.{1}[a-zA-Z0-9]{2,4})?)$",
    "prefix"   : r"/0",
    "pumpable" : r"0 ",
    "suffix"   : "\x00",
    "n"        : 5
  },
# = [1298] =
# INPUT: ^\w+(([-+']|[-+.]|\w+))*@\w+([-.]\w+)*\.\w+([-.]\w+)*$
# PARSE: OK
# SIZE: 40
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([-+']|[-+.]|\w+))*
# PREFIX: 0
# PUMPABLE: +
# SUFFIX: 
  {
    "index"    : "1298", 
    "exp"      : r"^\w+(([-+']|[-+.]|\w+))*@\w+([-.]\w+)*\.\w+([-.]\w+)*$",
    "prefix"   : r"0",
    "pumpable" : r"+",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1314] =
# INPUT: ^([A-Z]|[a-z]|[0-9])(([A-Z])*(([a-z])*([0-9])*(%)*(&)*(')*(\+)*(-)*(@)*(_)*(\.)*)|(\ )[^  ])+$
# PARSE: OK
# SIZE: 119
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([A-Z])*(([a-z])*([0-9])*(%)*(&)*(')*(\+)*(-)*(@)*(_)*(\.)*)|(\ )[^  ])+
# PREFIX: a
# PUMPABLE: .
# SUFFIX: \x00
  {
    "index"    : "1314", 
    "exp"      : r"^([A-Z]|[a-z]|[0-9])(([A-Z])*(([a-z])*([0-9])*(%)*(&)*(')*(\+)*(-)*(@)*(_)*(\.)*)|(\ )[^  ])+$",
    "prefix"   : r"a",
    "pumpable" : r".",
    "suffix"   : "\x00",
    "n"        : 6,
  },
# = [1316] =
# INPUT: ^(?:[\w]+[\&\-_\.]*)+@(?:(?:[\w]+[\-_\.]*)\.(?:[a-zA-Z]{2,}?))$
# PARSE: OK
# SIZE: 25
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[\w]+[\&\-_\.]*)+
# PREFIX: 0
# PUMPABLE: A_
# SUFFIX: 
  {
    "index"    : "1316", 
    "exp"      : r"^(?:[\w]+[\&\-_\.]*)+@(?:(?:[\w]+[\-_\.]*)\.(?:[a-zA-Z]{2,}?))$",
    "prefix"   : r"0",
    "pumpable" : r"A_",
    "suffix"   : r"",
    "n"        : 6,
  },
# = [1372] =
# INPUT: /^(https?|ftp)(:\/\/)(([\w]{3,}\.[\w]+\.[\w]{2,6})|([\d]{3}\.[\d]{1,3}\.[\d]{3}\.[\d]{1,3}))(\:[0,9]+)*(\/?$|((\/[\w\W]+)+\.[\w]{3,4})?$)/
# PARSE: OK
# SIZE: 116
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\/[\w\W]+)
# PREFIX: https://aaa.a.aaaaaa:9/!
# PUMPABLE: /0/0
# SUFFIX: 
  {
    "index"    : "1372", 
    "exp"      : r"^(https?|ftp)(:\/\/)(([\w]{3,}\.[\w]+\.[\w]{2,6})|([\d]{3}\.[\d]{1,3}\.[\d]{3}\.[\d]{1,3}))(\:[0,9]+)*(\/?$|((\/[\w\W]+)+\.[\w]{3,4})?$)",
    "prefix"   : r"https://aaa.a.aaaaaa:9/!",
    "pumpable" : r"/0/0",
    "suffix"   : r"",
    "n"        : 6,
  },
# = [1451] =
# INPUT: ^(?:(?:http|https|ftp|telnet|gopher|ms\-help|file|notes)://)?(?:(?:[a-z][\w~%!&',;=\-\.$\(\)\*\+]*):.*@)?(?:(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))(?::[0-9]+)?))?(?:(?:(?:/(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))+)*/(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*)(?:\?[^#]+)?(?:#[a-z0-9]\w*)?)?$
# PARSE: OK
# SIZE: 188
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[a-z0-9][\w\-]*[a-z0-9]*\.)*
# PREFIX: 
# PUMPABLE: u0.
# SUFFIX: 
  {
    "index"    : "1451", 
    "exp"      : r"^(?:(?:http|https|ftp|telnet|gopher|ms\-help|file|notes)://)?(?:(?:[a-z][\w~%!&',;=\-\.$\(\)\*\+]*):.*@)?(?:(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))(?::[0-9]+)?))?(?:(?:(?:/(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))+)*/(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*)(?:\?[^#]+)?(?:#[a-z0-9]\w*)?)?$",
    "prefix"   : r"",
    "pumpable" : r"u0.",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1452] =
# INPUT: ^(?:mailto:)?(?:[a-z][\w~%!&',;=\-\.$\(\)\*\+]*)@(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$
# PARSE: OK
# SIZE: 98
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[a-z0-9][\w\-]*[a-z0-9]*\.)*
# PREFIX: m@
# PUMPABLE: 3a.
# SUFFIX: 
  {
    "index"    : "1452", 
    "exp"      : r"^(?:mailto:)?(?:[a-z][\w~%!&',;=\-\.$\(\)\*\+]*)@(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$",
    "prefix"   : r"m@",
    "pumpable" : r"3a.",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1454] =
# INPUT: ^(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$
# PARSE: OK
# SIZE: 85
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[a-z0-9][\w\-]*[a-z0-9]*\.)*
# PREFIX: 
# PUMPABLE: 3a.
# SUFFIX: 
  {
    "index"    : "1454", 
    "exp"      : r"^(?:[a-z0-9][\w\-]*[a-z0-9]*\.)*(?:(?:(?:[a-z0-9][\w\-]*[a-z0-9]*)(?:\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$",
    "prefix"   : r"",
    "pumpable" : r"3a.",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1455] =
# INPUT: ^(?:(?:\.\./)|/)?(?:\w(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*\w?)?(?:/\w(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*\w?)*(?:\?[^#]+)?(?:#[a-z0-9]\w*)?$
# PARSE: OK
# SIZE: 46
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:/\w(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*\w?)*
# PREFIX: 
# PUMPABLE: /0_
# SUFFIX: \x00
  {
    "index"    : "1455", 
    "exp"      : r"^(?:(?:\.\./)|/)?(?:\w(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*\w?)?(?:/\w(?:[\w`~!$=;\-\+\.\^\(\)\|\{\}\[\]]|(?:%\d\d))*\w?)*(?:\?[^#]+)?(?:#[a-z0-9]\w*)?$",
    "prefix"   : r"",
    "pumpable" : r"/0_",
    "suffix"   : "\x00",
    "n"        : 10,
  },
# = [1473] =
# INPUT: ^(((\.\.){1}/)*|(/){1})?(([a-zA-Z0-9]*)/)*([a-zA-Z0-9]*)+([.jpg]|[.gif])+$
# PARSE: OK
# SIZE: 49
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z0-9]*)+
# PREFIX: 
# PUMPABLE: q
# SUFFIX: 
# Note: python is unable to compile regular expressions like: ([a-z]*)+
  {
    "index"    : "1473", 
    "exp"      : r"",
    "prefix"   : r"",
    "pumpable" : r"q",
    "suffix"   : r"",
    "n"        : 10,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [1538] =
# INPUT: ^\\\\[\w-]+\\(([\w()-][\w\s()-]*[\w()-]+)|([\w()-]+))\$?(\\(([\w()-][\w\s()-]*[\w()-]+)|([\w()-]+)))*\\?$
# PARSE: OK
# SIZE: 51
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\(([\w()-][\w\s()-]*[\w()-]+)|([\w()-]+)))*
# PREFIX: \\a\(
# PUMPABLE: \((
# SUFFIX: \x00
  {
    "index"    : "1538", 
    "exp"      : r"^\\\\[\w-]+\\(([\w()-][\w\s()-]*[\w()-]+)|([\w()-]+))\$?(\\(([\w()-][\w\s()-]*[\w()-]+)|([\w()-]+)))*\\?$",
    "prefix"   : r"\\a\(",
    "pumpable" : r"\((",
    "suffix"   : "\x00",
    "n"        : 10,
  },
# = [1558] =
# INPUT: ^(([01][0-9]|[012][0-3]):([0-5][0-9]))*$
# PARSE: OK
# SIZE: 18
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([01][0-9]|[012][0-3]):([0-5][0-9]))*
# PREFIX: 
# PUMPABLE: 00:00
# SUFFIX: !
  {
    "index"    : "1558", 
    "exp"      : r"^(([01][0-9]|[012][0-3]):([0-5][0-9]))*$",
    "prefix"   : r"",
    "pumpable" : r"00:00",
    "suffix"   : r"!",
    "n"        : 10,
  },
# = [1612] =
# INPUT: /^([0-9a-zA-Z]+|[a-zA-Z]:(\\(\w[\w ]*.*))+|\\(\\(\w[\w ]*.*))+)\.[0-9a-zA-Z]{1,3}$/
# PARSE: OK
# SIZE: 63
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: :(\\(\w[\w ]*.*))
# PREFIX: a:\0
# PUMPABLE: \0\0
# SUFFIX: 
  {
    "index"    : "1612", 
    "exp"      : r"^([0-9a-zA-Z]+|[a-zA-Z]:(\\(\w[\w ]*.*))+|\\(\\(\w[\w ]*.*))+)\.[0-9a-zA-Z]{1,3}$",
    "prefix"   : r"a:\0",
    "pumpable" : r"\0\0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [1637] =
# INPUT: ^\s*((([\w-]+\.)+[\w-]+|([a-zA-Z]{1}|[\w-]{2,}))@(\w+\.)+[A-Za-z]{2,5}[?= ]?[?=,;]?[?= ]?)+?$
# PARSE: OK
# SIZE: 134
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((([\w-]+\.)+[\w-]+|([a-zA-Z]{1}|[\w-]{2,}))@(\w+\.)+[A-Za-z]{2,5}[?= ]?[?=,;]?[?= ]?)+?
# PREFIX: aa.a@a.aA
# PUMPABLE: a.a.a@a.AAA.AA-.-@0.AAA.AA
# SUFFIX: \x00
  {
    "index"    : "1637", 
    "exp"      : r"^\s*((([\w-]+\.)+[\w-]+|([a-zA-Z]{1}|[\w-]{2,}))@(\w+\.)+[A-Za-z]{2,5}[?= ]?[?=,;]?[?= ]?)+?$",
    "prefix"   : r"aa.a@a.aA",
    "pumpable" : r"a.a.a@a.AAA.AA-.-@0.AAA.AA",
    "suffix"   : "\x00",
    "n"        : 5,
  },
# = [1712] =
# INPUT: ^(?:(?:[\w\.\-_]+@[\w\d]+(?:\.[\w]{2,6})+)[,;]?\s?)+$
# PARSE: OK
# SIZE: 104
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:(?:[\w\.\-_]+@[\w\d]+(?:\.[\w]{2,6})+)[,;]?\s?)+
# PREFIX: a@a.a0
# PUMPABLE: a@a.a0.AA.@0.00
# SUFFIX: \x00
  {
    "index"    : "1712", 
    "exp"      : r"^(?:(?:[\w\.\-_]+@[\w\d]+(?:\.[\w]{2,6})+)[,;]?\s?)+$",
    "prefix"   : r"a@a.a0",
    "pumpable" : r"a@a.a0.AA.@0.00",
    "suffix"   : "\x00",
    "n"        : 5,
  },
# = [1726] =
# INPUT: ^(([a-z])+.)+[A-Z]([a-z])+$
# PARSE: OK
# SIZE: 32
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([a-z])+.)+
# PREFIX: a{
# PUMPABLE: aaa{
# SUFFIX: 
  {
    "index"    : "1725", 
    "exp"      : r"^(([a-z])+.)+[A-Z]([a-z])+$",
    "prefix"   : r"a{",
    "pumpable" : r"aaa{",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1780] =
# INPUT: ^[a-zA-Z0-9]+([_.-]?[a-zA-Z0-9]+)?@[a-zA-Z0-9]+([_-]?[a-zA-Z0-9]+)*([.]{1})[a-zA-Z0-9]+([.]?[a-zA-Z0-9]+)*$
# PARSE: OK
# SIZE: 44
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([_-]?[a-zA-Z0-9]+)*
# PREFIX: aa-a@0
# PUMPABLE: a0
# SUFFIX: 
  {
    "index"    : "1780", 
    "exp"      : r"^[a-zA-Z0-9]+([_.-]?[a-zA-Z0-9]+)?@[a-zA-Z0-9]+([_-]?[a-zA-Z0-9]+)*([.]{1})[a-zA-Z0-9]+([.]?[a-zA-Z0-9]+)*$",
    "prefix"   : r"aa-a@0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [1795] =
# INPUT: ^([1-9]{1}(([0-9])?){2})+(,[0-9]{1}[0-9]{2})*$
# PARSE: OK
# SIZE: 45
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([1-9]{1}(([0-9])?){2})+
# PREFIX: 1
# PUMPABLE: 11
# SUFFIX: !
  {
    "index"    : "1795", 
    "exp"      : r"^([1-9]{1}(([0-9])?){2})+(,[0-9]{1}[0-9]{2})*$",
    "prefix"   : r"1",
    "pumpable" : r"11",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [1837] =
# INPUT: ^([a-z]+?\.[a-z]+)+\%$
# PARSE: OK
# SIZE: 23
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-z]+?\.[a-z]+)+
# PREFIX: a.a
# PUMPABLE: a.aaa.a
# SUFFIX: 
  {
    "index"    : "1837", 
    "exp"      : r"^([a-z]+?\.[a-z]+)+\%$",
    "prefix"   : r"a.a",
    "pumpable" : r"a.aaa.a",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [1918] =
# INPUT: (< *balise[ *>|:(.|\n)*>| (.|\n)*>](.|\n)*</balise *>)
# PARSE: OK
# SIZE: 30
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n)*
# PREFIX: <balise\x0a
# PUMPABLE: \x0a
# SUFFIX: 
   {
    "index"    : "1918", 
    "exp"      : r"(< *balise[ *>|:(.|\n)*>| (.|\n)*>](.|\n)*</balise *>)",
    "flags"    : re.DOTALL,
    "prefix"   : "<balise\x0a",
    "pumpable" : "\x0a",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [1928] =
# INPUT: <(?:[^"']+?|.+?(?:"|').*?(?:"|')?.*?)*?>
# PARSE: OK
# SIZE: 23
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[^"']+?|.+?(?:"|').*?(?:"|')?.*?)*?
# PREFIX: <
# PUMPABLE: ?''
# SUFFIX: 
  {
    "index"    : "1928", 
    "exp"      : r'''<(?:[^"']+?|.+?(?:"|').*?(?:"|')?.*?)*?>''',
    "prefix"   : r"<",
    "pumpable" : r"?''",
    "suffix"   : r"",
    "n"        : 3,
  },
# = [1929] =
# INPUT: ((http|ftp|https):\/\/w{3}[\d]*.|(http|ftp|https):\/\/|w{3}[\d]*.)([\w\d\._\-#\(\)\[\]\\,;:]+@[\w\d\._\-#\(\)\[\]\\,;:])?([a-z0-9]+.)*[a-z\-0-9]+.([a-z]{2,3})?[a-z]{2,6}(:[0-9]+)?(\/[\/a-z0-9\._\-,]+)*[a-z0-9\-_\.\s\%]+(\?[a-z0-9=%&\.\-,#]+)?
# PARSE: OK
# SIZE: 127
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-z0-9]+.)*
# PREFIX: http://
# PUMPABLE: x0a{
# SUFFIX: 
  {
    "index"    : "1929", 
    "exp"      : r"((http|ftp|https):\/\/w{3}[\d]*.|(http|ftp|https):\/\/|w{3}[\d]*.)([\w\d\._\-#\(\)\[\]\\,;:]+@[\w\d\._\-#\(\)\[\]\\,;:])?([a-z0-9]+.)*[a-z\-0-9]+.([a-z]{2,3})?[a-z]{2,6}(:[0-9]+)?(\/[\/a-z0-9\._\-,]+)*[a-z0-9\-_\.\s\%]+(\?[a-z0-9=%&\.\-,#]+)?",
    "prefix"   : r"http://",
    "pumpable" : r"x0a{",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [1944] =
# INPUT: <\s*/?\s*\w+(\s*\w+\s*=\s*(['"][^'"]*['"]|[\w#]+))*\s*/?\s*>
# PARSE: OK
# SIZE: 43
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*\w+\s*=\s*(['"][^'"]*['"]|[\w#]+))*
# PREFIX: <0
# PUMPABLE:  a=00A=0
# SUFFIX: 
  {
    "index"    : "1944", 
    "exp"      : r'''<\s*/?\s*\w+(\s*\w+\s*=\s*(['"][^'"]*['"]|[\w#]+))*\s*/?\s*>''',
    "prefix"   : r"<0",
    "pumpable" : r" a=00A=0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [1980] =
# INPUT: <(\w+)(\s(\w*=".*?")?)*((/>)|((/*?)>.*?</\1>))
# PARSE: OK
# SIZE: 42
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s(\w*=".*?")?)*
# PREFIX: <0
# PUMPABLE:  =""\x09=""
# SUFFIX: 
  {
    "index"    : "1980", 
    "exp"      : r'''<(\w+)(\s(\w*=".*?")?)*((/>)|((/*?)>.*?</\1>))''',
    "prefix"   : r"<0",
    "pumpable" : r''' =""\x09=""''',
    "suffix"   : r"",
    "n"        : 7,
  },
# = [2129] =
# INPUT: [A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?:\.)+(?:[A-Z]{2}|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|us)\b
# PARSE: OK
# SIZE: 129
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+
# PREFIX: ^.^@0
# PUMPABLE: 000
# SUFFIX: 
  {
    "index"    : "2129", 
    "exp"      : r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?:\.)+(?:[A-Z]{2}|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|us)\b",
    "prefix"   : r"^.^@0",
    "pumpable" : r"000",
    "suffix"   : r"",
    "n"        : 3,
  },
# = [2135] =
# INPUT: (<(!--.*|script)(.|\n[^<])*(--|script)>)|(<|<)(/?[\w!?]+)\s?[^<]*(>|>)|(\&[\w]+\;)
# PARSE: OK
# SIZE: 69
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n[^<])*
# PREFIX: <!--
# PUMPABLE: \x0at
# SUFFIX: 
  {
    "index"    : "2135", 
    "exp"      : r"(<(!--.*|script)(.|\n[^<])*(--|script)>)|(<|<)(/?[\w!?]+)\s?[^<]*(>|>)|(\&[\w]+\;)",
    "flags"    : re.DOTALL,
    "prefix"   : r"<!--",
    "pumpable" : "\x0at",
    "suffix"   : r"",
    "n"        : 7,
  },
# = [2160] =
# INPUT: ^[a-zA-Z0-9]+(([_][a-zA-Z0-9])?[a-zA-Z0-9]*)*$
# PARSE: OK
# SIZE: 19
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([_][a-zA-Z0-9])?[a-zA-Z0-9]*)*
# PREFIX: 0
# PUMPABLE: 0
# SUFFIX: !
  {
    "index"    : "2160", 
    "exp"      : r"^[a-zA-Z0-9]+(([_][a-zA-Z0-9])?[a-zA-Z0-9]*)*$",
    "prefix"   : r"0",
    "pumpable" : r"0",
    "suffix"   : r"!",
    "n"        : 7,
  },
# = [2186] =
# INPUT: ^\+?[a-z0-9](([-+.]|[_]+)?[a-z0-9]+)*@([a-z0-9]+(\.|\-))+[a-z]{2,6}$
# PARSE: OK
# SIZE: 61
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([-+.]|[_]+)?[a-z0-9]+)*
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX: 
  {
    "index"    : "2186", 
    "exp"      : r"^\+?[a-z0-9](([-+.]|[_]+)?[a-z0-9]+)*@([a-z0-9]+(\.|\-))+[a-z]{2,6}$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2218] =
# INPUT: ^([a-zA-Z](?:(?:(?:\w[\.\_]?)*)\w)+)([a-zA-Z0-9])$
# PARSE: OK
# SIZE: 22
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:\w[\.\_]?)*
# PREFIX: A
# PUMPABLE: 0_
# SUFFIX: 
  {
    "index"    : "2218", 
    "exp"      : r"^([a-zA-Z](?:(?:(?:\w[\.\_]?)*)\w)+)([a-zA-Z0-9])$",
    "prefix"   : r"A",
    "pumpable" : r"0_",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2220] =
# INPUT: ^([a-zA-Z0-9])+(([a-zA-Z0-9\s])+[_-//&a-zA-Z0-9]([a-zA-Z0-9\s])+)*([a-zA-Z0-9])+$
# PARSE: OK
# SIZE: 35
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([a-zA-Z0-9\s])+[_-//&a-zA-Z0-9]([a-zA-Z0-9\s])+)*
# PREFIX: 0
# PUMPABLE: \x090\x09\x0900\x09
# SUFFIX: 
#
# Notes:
# The character range [_-//&a-zA-Z0-9] had to be replaced with [/-_/&a-zA-Z0-9] as python could not
# parse the former (invalid range). The modification should not affect the semantics, as it simply
# swaps the start and end characters of the range [_-/] -> [/-_].
  {
    "index"    : "2220", 
    "exp"      : r"^([a-zA-Z0-9])+(([a-zA-Z0-9\s])+[/-_/&a-zA-Z0-9]([a-zA-Z0-9\s])+)*([a-zA-Z0-9])+$",
    "prefix"   : r"0",
    "pumpable" : "\x090\x09\x0900\x09",
    "suffix"   : r"",
    "n"        : 3,
  },
# = [2223] =
# INPUT: ^(ht|f)tp(s?)\:\/\/[a-zA-Z0-9\-\._]+(\.[a-zA-Z0-9\-\._]+){2,}(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?$
# PARSE: OK
# SIZE: 52
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\.[a-zA-Z0-9\-\._]+){2,}
# PREFIX: https://a.a.-
# PUMPABLE: .-.-
# SUFFIX: !
# Note: python is unable to compile regular expressions like: ([a-z]*)?
  {
    "index"    : "2223", 
    "exp"      : r"",
    "prefix"   : r"https://a.a.-",
    "pumpable" : r".-.-",
    "suffix"   : r"!",
    "n"        : 3,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [2227] =
# INPUT: ^(([a-zA-Z]\:)|(\\))(\\{1}|((\\{1})[^\\]([^/:*?<>"|]*))+)$
# PARSE: OK
# SIZE: 38
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\\{1})[^\\]([^/:*?<>"|]*))+
# PREFIX: a:\!
# PUMPABLE: \|\]
# SUFFIX: "
  {
    "index"    : "2227", 
    "exp"      : r'^(([a-zA-Z]\:)|(\\))(\\{1}|((\\{1})[^\\]([^/:*?<>"|]*))+)$',
    "prefix"   : r"a:\!",
    "pumpable" : r"\|\]",
    "suffix"   : r'"',
    "n"        : 7,
  },
# = [2258] =
# INPUT: ^([0-9]*)+(,[0-9]+)+$
# PARSE: OK
# SIZE: 27
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([0-9]*)+
# PREFIX: 
# PUMPABLE: 0
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: ([a-z]*)+
  {
    "index"    : "2258",
    "exp"      : r"",
    "prefix"   : r"",
    "pumpable" : r"0",
    "suffix"   : r"",
    "n"        : 7,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [2337] =
# INPUT: ^[-\w'+*$^&%=~!?{}#|/`]{1}([-\w'+*$^&%=~!?{}#|`.]?[-\w'+*$^&%=~!?{}#|`]{1}){0,31}[-\w'+*$^&%=~!?{}#|`]?@(([a-zA-Z0-9]{1}([-a-zA-Z0-9]?[a-zA-Z0-9]{1}){0,31})\.{1})+([a-zA-Z]{2}|[a-zA-Z]{3}|[a-zA-Z]{4}|[a-zA-Z]{6}){1}$
# PARSE: OK
# SIZE: 9065
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([a-zA-Z0-9]{1}([-a-zA-Z0-9]?[a-zA-Z0-9]{1}){0,31})\.{1})+
# PREFIX: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^@a.
# PUMPABLE: 0000.
# SUFFIX: 
  {
    "index"    : "2337",
    "exp"      : r"^[-\w'+*$^&%=~!?{}#|/`]{1}([-\w'+*$^&%=~!?{}#|`.]?[-\w'+*$^&%=~!?{}#|`]{1}){0,31}[-\w'+*$^&%=~!?{}#|`]?@(([a-zA-Z0-9]{1}([-a-zA-Z0-9]?[a-zA-Z0-9]{1}){0,31})\.{1})+([a-zA-Z]{2}|[a-zA-Z]{3}|[a-zA-Z]{4}|[a-zA-Z]{6}){1}$",
    "prefix"   : r"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^@a.",
    "pumpable" : r"0000.",
    "suffix"   : r"",
    "n"        : 5,
    "skip"     : True,
    "notes"    : "skipped - python hangs"
  },
# = [2339] =
# INPUT: <(/)?(a|abbr|acronym|address|applet|area|b|base|basefont|bdo|big|blockquote|body|br|button|caption|center|cite|code|col|colgroup|dd|del|dir|div|dfn|dl|dt|em|fieldset|font|form|frame|frameset|h[1-6]|head|hr|html|i|iframe|img|input|ins|isindex|kbd|label|legend|li|link|map|menu|meta|noframes|noscript|object|ol|optgroup|option|p|param|pre|q|s|samp|script|select|small|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|xmp){1}(\s(\"[^\"]*\"*|[^>])*)*>
# PARSE: OK
# SIZE: 476
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s(\"[^\"]*\"*|[^>])*)*
# PREFIX: <u
# PUMPABLE: \x09"
# SUFFIX: 
  {
    "index"    : "2339",
    "exp"      : r"<(/)?(a|abbr|acronym|address|applet|area|b|base|basefont|bdo|big|blockquote|body|br|button|caption|center|cite|code|col|colgroup|dd|del|dir|div|dfn|dl|dt|em|fieldset|font|form|frame|frameset|h[1-6]|head|hr|html|i|iframe|img|input|ins|isindex|kbd|label|legend|li|link|map|menu|meta|noframes|noscript|object|ol|optgroup|option|p|param|pre|q|s|samp|script|select|small|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|xmp){1}(\s(\"[^\"]*\"*|[^>])*)*>",
    "prefix"   : r"<u",
    "pumpable" : '\x09"',
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2349] =
# INPUT: ^((\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)\s*[,]{0,1}\s*)+$
# PARSE: OK
# SIZE: 90
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)\s*[,]{0,1}\s*)+
# PREFIX: a-a@a.0
# PUMPABLE: a@0.0.00.0-0A@0.0.00.0.0
# SUFFIX: \x00
  {
    "index"    : "2349",
    "exp"      : r"^((\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)\s*[,]{0,1}\s*)+$",
    "prefix"   : r"a-a@a.0",
    "pumpable" : r"a@0.0.00.0-0A@0.0.00.0.0",
    "suffix"   : "\x00",
    "n"        : 2,
  },
# = [2361] =
# INPUT: ^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$
# PARSE: OK
# SIZE: 66
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([-.\w]*[0-9a-zA-Z])*
# PREFIX: 0
# PUMPABLE: 00
# SUFFIX: 
  {
    "index"    : "2361",
    "exp"      : r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
    "prefix"   : r"0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2379] =
# INPUT: [^(\&)](\w*)+(\=)[\w\d ]*
# PARSE: OK
# SIZE: 18
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\w*)+
# PREFIX: !
# PUMPABLE: 0
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: (\w*)+
  {
    "index"    : "2379",
    "exp"      : r"[^(\&)](\w*)+(\=)[\w\d ]*",
    "prefix"   : r"!",
    "pumpable" : r"0",
    "suffix"   : r"",
    "n"        : 5,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [2424] =
# INPUT: ^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[a-z0-9]+)?)+)*$
# PARSE: OK
# SIZE: 48
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\.([a-z]+([a-z0-9-]*[a-z0-9]+)?)+)*
# PREFIX: a
# PUMPABLE: .aa0
# SUFFIX: !
  {
    "index"    : "2424",
    "exp"      : r"^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[a-z0-9]+)?)+)*$",
    "prefix"   : r"a",
    "pumpable" : r".aa0",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [2433] =
# INPUT: ((?:[^",]|(?:"(?:\\{2}|\\"|[^"])*?"))*)
# PARSE: OK
# SIZE: 16
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:\\{2}|\\"|[^"])*?
# PREFIX: "
# PUMPABLE: \\
# SUFFIX: 
  {
    "index"    : "2433",
    "exp"      : r'((?:[^",]|(?:"(?:\\{2}|\\"|[^"])*?"))*)',
    "prefix"   : r'"',
    "pumpable" : r"\\",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2435] =
# INPUT: ^[a-zA-Z]+(([\'\,\.\-][a-zA-Z])?[a-zA-Z]*)*$
# PARSE: OK
# SIZE: 19
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([\'\,\.\-][a-zA-Z])?[a-zA-Z]*)*
# PREFIX: A
# PUMPABLE: A
# SUFFIX: !
  {
    "index"    : "2435",
    "exp"      : r"^[a-zA-Z]+(([\'\,\.\-][a-zA-Z])?[a-zA-Z]*)*$",
    "prefix"   : r"A",
    "pumpable" : r"A",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [2453] =
# INPUT: ^(([A-Za-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_\`\{\|\}\~]+\.*)*[A-Za-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_\`\{\|\}\~]+@((\w+\-+)|(\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})$
# PARSE: OK
# SIZE: 2070
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([A-Za-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_\`\{\|\}\~]+\.*)*
# PREFIX: 
# PUMPABLE: !!
# SUFFIX: 
  {
    "index"    : "2453",
    "exp"      : r"^(([A-Za-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_\`\{\|\}\~]+\.*)*[A-Za-z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_\`\{\|\}\~]+@((\w+\-+)|(\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})$",
    "prefix"   : r"",
    "pumpable" : r"!!",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2477] =
# INPUT: ^([A-Z]|[a-z]|[0-9])([A-Z]|[a-z]|[0-9]|([A-Z]|[a-z]|[0-9]|(%|&|'|\+|\-|@|_|\.|\ )[^%&'\+\-@_\.\ ]|\.$|([%&'\+\-@_\.]\ [^\ ]|\ [%&'\+\-@_\.][^%&'\+\-@_\.])))+$
# PARSE: OK
# SIZE: 109
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([A-Z]|[a-z]|[0-9]|([A-Z]|[a-z]|[0-9]|(%|&|'|\+|\-|@|_|\.|\ )[^%&'\+\-@_\.\ ]|\.$|([%&'\+\-@_\.]\ [^\ ]|\ [%&'\+\-@_\.][^%&'\+\-@_\.])))+
# PREFIX: Aa
# PUMPABLE: 0
# SUFFIX: \x00
# TIME: 0.001867 (s)
  {
    "index"    : "2477",
    "exp"      : r"^([A-Z]|[a-z]|[0-9])([A-Z]|[a-z]|[0-9]|([A-Z]|[a-z]|[0-9]|(%|&|'|\+|\-|@|_|\.|\ )[^%&'\+\-@_\.\ ]|\.$|([%&'\+\-@_\.]\ [^\ ]|\ [%&'\+\-@_\.][^%&'\+\-@_\.])))+$",
    "prefix"   : r"Aa",
    "pumpable" : r"0",
    "suffix"   : "\x00",
    "n"        : 5,
  },
# = [2488] =
# INPUT: ^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w].*))+(.pdf)$
# PARSE: OK
# SIZE: 45
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\\(\w[\w].*))+
# PREFIX: a:\a0
# PUMPABLE: \pq\pq
# SUFFIX: 
  {
    "index"    : "2488",
    "exp"      : r"^(([a-zA-Z]:)|(\\{2}\w+)\$?)(\\(\w[\w].*))+(.pdf)$",
    "prefix"   : r"a:\a0",
    "pumpable" : r"\pq\pq",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2543] =
# INPUT: <asp:requiredfieldvalidator(\s*\w+\s*=\s*\"?\s*\w+\s*\"?\s*)+\s*>\s*<\/asp:requiredfieldvalidator>
# PARSE: OK
# SIZE: 117
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*\w+\s*=\s*\"?\s*\w+\s*\"?\s*)+
# PREFIX: <asp:requiredfieldvalidatora =0
# PUMPABLE:  a=\x090
# SUFFIX: 
  {
    "index"    : "2543",
    "exp"      : r"<asp:requiredfieldvalidator(\s*\w+\s*=\s*\"?\s*\w+\s*\"?\s*)+\s*>\s*<\/asp:requiredfieldvalidator>",
    "prefix"   : r"<asp:requiredfieldvalidatora =0",
    "pumpable" : " a=\x090",
    "suffix"   : r"",
    "n"        : 6,
  },
# = [2591] =
# INPUT: <(.|\n)*?>
# PARSE: OK
# SIZE: 9
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.|\n)*?
# PREFIX: <
# PUMPABLE: \x0a
# SUFFIX: 
  {
    "index"    : "2591",
    "exp"      : r"<(.|\n)*?>",
    "flags"    : re.DOTALL,
    "prefix"   : r"<",
    "pumpable" : "\x0a",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [2599] =
# INPUT: /^(([^\.\-\,a-wy-z]([\(]?(\+|[x])?\d+[\)]?)?[\s\.\-\,]?([\(]?\d+[\)]?)?[\s\.\-\,]?(\d+[\s\.\-\,]?)+[^\.\-\,a-z])|((\+|[x])?\d+))$/i
# PARSE: OK
# SIZE: 78
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ?(\d+[\s\.\-\,]?)
# PREFIX: x0
# PUMPABLE: 00
# SUFFIX: ,
  {
    "index"    : "2599",
    "exp"      : r"^(([^\.\-\,a-wy-z]([\(]?(\+|[x])?\d+[\)]?)?[\s\.\-\,]?([\(]?\d+[\)]?)?[\s\.\-\,]?(\d+[\s\.\-\,]?)+[^\.\-\,a-z])|((\+|[x])?\d+))$",
    "prefix"   : r"x0",
    "pumpable" : r"00",
    "suffix"   : r",",
    "n"        : 4,
  },
# = [2672] =
# INPUT: ^[^\~\`\!\@\#\$\%\^\&\*\(\)\-\_\=\+\\\|\[\]\{\}\;\:\"\'\,\<\./\>\?\s](([a-zA-Z0-9]*[-_\./]?[a-zA-Z0-9]{1,})*)$
# PARSE: OK
# SIZE: 17
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z0-9]*[-_\./]?[a-zA-Z0-9]{1,})*
# PREFIX: \x00
# PUMPABLE: 0a
# SUFFIX: !
  {
    "index"    : "2672",
    "exp"      : r"^[^\~\`\!\@\#\$\%\^\&\*\(\)\-\_\=\+\\\|\[\]\{\}\;\:\"\'\,\<\./\>\?\s](([a-zA-Z0-9]*[-_\./]?[a-zA-Z0-9]{1,})*)$",
    "prefix"   : "\x00",
    "pumpable" : r"0a",
    "suffix"   : r"!",
    "n"        : 4,
  },
# = [2675] =
# INPUT: <(\s*/?\s*)\w+?(\s*(([\w-]+="[^"]*?")|([\w-]+='[^']*?')|([\w-]+=[^'"<>\s]+)))*(\s*/?\s*)>
# PARSE: OK
# SIZE: 62
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\s*(([\w-]+="[^"]*?")|([\w-]+='[^']*?')|([\w-]+=[^'"<>\s]+)))*
# PREFIX: <0
# PUMPABLE:  a=""-=''-=\x00AA=""
# SUFFIX: 
  {
    "index"    : "2675",
    "exp"      : r'''<(\s*/?\s*)\w+?(\s*(([\w-]+="[^"]*?")|([\w-]+='[^']*?')|([\w-]+=[^'"<>\s]+)))*(\s*/?\s*)>''',
    "prefix"   : r"<0",
    "pumpable" : ''' a=""-=''-=\x00AA=""''',
    "suffix"   : r"!",
    "n"        : 4,
  },
# = [2691] =
# INPUT: ^.*[_A-Za-z0-9]+[\t ]+[\*&]?[\t ]*[_A-Za-z0-9](::)?[_A-Za-z0-9:]+[\t ]*\(( *[ \[\]\*&A-Za-z0-9_]+ *,? *)*\).*$
# PARSE: OK
# SIZE: 47
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ( *[ \[\]\*&A-Za-z0-9_]+ *,? *)*
# PREFIX: a aa(
# PUMPABLE:  [
# SUFFIX: 
  {
    "index"    : "2691",
    "exp"      : r"^.*[_A-Za-z0-9]+[\t ]+[\*&]?[\t ]*[_A-Za-z0-9](::)?[_A-Za-z0-9:]+[\t ]*\(( *[ \[\]\*&A-Za-z0-9_]+ *,? *)*\).*$",
    "prefix"   : r"a aa(",
    "pumpable" : r" [",
    "suffix"   : r"",
    "n"        : 4,
  },
# = [2723] =
# INPUT: ^((CN=(['\w\d\s\-\&\.]+(\\/)*(\\,)*)+,\s*)*(OU=(['\w\d\s\-\&\.]+(\\/)*(\\,)*)+,\s*)*(DC=['\w\d\s\-\&]+[,]*\s*){1,}(DC=['\w\d\s\-\&]+\s*){1})$
# PARSE: OK
# SIZE: 120
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (OU=(['\w\d\s\-\&\.]+(\\/)*(\\,)*)+,\s*)*
# PREFIX: 
# PUMPABLE: OU=\x09\x09,
# SUFFIX: 
  {
    "index"    : "2723",
    "exp"      : r"^((CN=(['\w\d\s\-\&\.]+(\\/)*(\\,)*)+,\s*)*(OU=(['\w\d\s\-\&\.]+(\\/)*(\\,)*)+,\s*)*(DC=['\w\d\s\-\&]+[,]*\s*){1,}(DC=['\w\d\s\-\&]+\s*){1})$",
    "prefix"   : r"",
    "pumpable" : "OU=\x09\x09,",
    "suffix"   : r"",
    "n"        : 10,
  },
# = [2724] =
# INPUT: ^[a-z0-9_.-]*@[a-z0-9-]+(.[a-z]{2,4})+$
# PARSE: OK
# SIZE: 32
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (.[a-z]{2,4})+
# PREFIX: @aaaa
# PUMPABLE: aaaaaaa
# SUFFIX: {
  {
    "index"    : "2724",
    "exp"      : r"^[a-z0-9_.-]*@[a-z0-9-]+(.[a-z]{2,4})+$",
    "prefix"   : r"@aaaa",
    "pumpable" : r"aaaaaaa",
    "suffix"   : r"{",
    "n"        : 4,
  },
# = [2729] =
# INPUT: ^((https|http)://)?(www.)?(([a-zA-Z0-9\-]{2,})\.)+([a-zA-Z0-9\-]{2,4})(/[\w\.]{0,})*((\?)(([\w\%]{0,}=[\w\%]{0,}&?)|[\w]{0,})*)?$
# PARSE: OK
# SIZE: 90
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (([\w\%]{0,}=[\w\%]{0,}&?)|[\w]{0,})*
# PREFIX: https://wwwaaa.aa?
# PUMPABLE: 0
# SUFFIX: !
  {
    "index"    : "2729",
    "exp"      : r"^((https|http)://)?(www.)?(([a-zA-Z0-9\-]{2,})\.)+([a-zA-Z0-9\-]{2,4})(/[\w\.]{0,})*((\?)(([\w\%]{0,}=[\w\%]{0,}&?)|[\w]{0,})*)?$",
    "prefix"   : r"https://wwwaaa.aa?",
    "pumpable" : r"0",
    "suffix"   : r"!",
    "n"        : 10,
  },
# = [2734] =
# INPUT: ^\s*(([/-9!#-'*+=?A-~-]+(?:\.[/-9!#-'*+=?A-~-]+)*|"(?:[^"\r\n\\]|\\.)*")@([A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?(?:\.[A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?)*|\[(?:[^\[\]\r\n\\]|\\.)*\]))\s*$
# PARSE: OK
# SIZE: 52
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:\.[A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?)*
# PREFIX: A.A@A
# PUMPABLE: .A0
# SUFFIX: \x00
  {
    "index"    : "2734",
    "exp"      : r'''^\s*(([/-9!#-'*+=?A-~-]+(?:\.[/-9!#-'*+=?A-~-]+)*|"(?:[^"\r\n\\]|\\.)*")@([A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?(?:\.[A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?)*|\[(?:[^\[\]\r\n\\]|\\.)*\]))\s*$''',
    "prefix"   : r"A.A@A",
    "pumpable" : r".A0",
    "suffix"   : "\x00",
    "n"        : 10,
  },
# = [2772] =
# INPUT: /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}([a-z0-9]|([a-z0-9][\-]))+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/
# PARSE: OK
# SIZE: 67
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: )(([\-.]|[_]+)?([a-zA-Z0-9]+))
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX: 
  {
    "index"    : "2772",
    "exp"      : r"^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}([a-z0-9]|([a-z0-9][\-]))+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2773] =
# INPUT: /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/
# PARSE: OK
# SIZE: 53
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: )(([\-.]|[_]+)?([a-zA-Z0-9]+))
# PREFIX: 0
# PUMPABLE: a0
# SUFFIX: 
  {
    "index"    : "2773",
    "exp"      : r"^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$",
    "prefix"   : r"0",
    "pumpable" : r"a0",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2796] =
# INPUT: ^(/(?:(?:(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*)(?:/(?:(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*))*))$
# PARSE: OK
# SIZE: 44
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (?:/(?:(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*))*
# PREFIX: /
# PUMPABLE: /=!
# SUFFIX: \x00
  {
    "index"    : "2796",
    "exp"      : r"^(/(?:(?:(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*)(?:/(?:(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\-_.!~*'():\@&=+\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*))*))$",
    "prefix"   : r"/",
    "pumpable" : r"/=!",
    "suffix"   : "\x00",
    "n"        : 10,
  },
# = [2849] =
# INPUT: /^"|'+(.*)+"$|'$/
# PARSE: OK
# SIZE: 23
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: +(.*)
# PREFIX: '
# PUMPABLE: (
# SUFFIX: 
#
# Note: python is unable to compile regular expressions like: (.*)+
  {
    "index"    : "2849",
    "exp"      : r'''^"|'+(.*)+"$|'$''',
    "prefix"   : r"'",
    "pumpable" : r"(",
    "suffix"   : r"",
    "n"        : 10,
    "skip"     : True,
    "notes"    : "skipped - python cannot parse"
  },
# = [2901] =
# INPUT: ^(\d+(,\d+)*)+$
# PARSE: OK
# SIZE: 28
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\d+(,\d+)*)+
# PREFIX: 0
# PUMPABLE: 00
# SUFFIX: !
  {
    "index"    : "2901",
    "exp"      : r"^(\d+(,\d+)*)+$",
    "prefix"   : r"0",
    "pumpable" : r"00",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [2912] =
# INPUT: ^((([a-zA-Z\'\.\-]+)?)((,\s*([a-zA-Z]+))?)|([A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})))(;{1}(((([a-zA-Z\'\.\-]+){1})((,\s*([a-zA-Z]+))?))|([A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})){1}))*$
# PARSE: OK
# SIZE: 135
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (;{1}(((([a-zA-Z\'\.\-]+){1})((,\s*([a-zA-Z]+))?))|([A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})){1}))*
# PREFIX: 
# PUMPABLE: ;aaA@0.AA
# SUFFIX: !
  {
    "index"    : "2912",
    "exp"      : r"^((([a-zA-Z\'\.\-]+)?)((,\s*([a-zA-Z]+))?)|([A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})))(;{1}(((([a-zA-Z\'\.\-]+){1})((,\s*([a-zA-Z]+))?))|([A-Za-z0-9](([_\.\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\.\-]?[a-zA-Z0-9]+)*)\.([A-Za-z]{2,})){1}))*$",
    "prefix"   : r"",
    "pumpable" : r";aaA@0.AA",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [2952] =
# INPUT: ([a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+)+@([a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)+(\.[a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)(\.[a-zA-z0-9]+)*
# PARSE: OK
# SIZE: 52
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ([a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+)+
# PREFIX: aa-
# PUMPABLE: A---
# SUFFIX: 
  {
    "index"    : "2952",
    "exp"      : r"([a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+[a-zA-Z0-9\_\-\.]+)+@([a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)+(\.[a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)(\.[a-zA-z0-9]+)*",
    "prefix"   : r"aa-",
    "pumpable" : r"A---",
    "suffix"   : r"",
    "n"        : 2,
  },
# = [2956] =
# INPUT: ^((\.)?([a-zA-Z0-9_-]?)(\.)?([a-zA-Z0-9_-]?)(\.)?)+$
# PARSE: OK
# SIZE: 60
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: ((\.)?([a-zA-Z0-9_-]?)(\.)?([a-zA-Z0-9_-]?)(\.)?)+
# PREFIX: 
# PUMPABLE: .
# SUFFIX: !
  {
    "index"    : "2956",
    "exp"      : r"^((\.)?([a-zA-Z0-9_-]?)(\.)?([a-zA-Z0-9_-]?)(\.)?)+$",
    "prefix"   : r"",
    "pumpable" : r".",
    "suffix"   : r"!",
    "n"        : 5,
  },
# = [2962] =
# INPUT: ^([a-zA-Z]+)://([a-zA-Z0-9_\-]+)((\.[a-zA-Z0-9_\-]+|[0-9]{1,3})+)\.([a-zA-Z]{2,6}|[0-9]{1,3})((:[0-9]+)?)((/[a-zA-Z0-9_\-,.;=%]*)*)((\?[a-zA-Z0-9_\-,.;=&%]*)?)$
# PARSE: OK
# SIZE: 102
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (\.[a-zA-Z0-9_\-]+|[0-9]{1,3})+
# PREFIX: a://a0
# PUMPABLE: 00
  {
    "index"    : "2962",
    "exp"      : r"^([a-zA-Z]+)://([a-zA-Z0-9_\-]+)((\.[a-zA-Z0-9_\-]+|[0-9]{1,3})+)\.([a-zA-Z]{2,6}|[0-9]{1,3})((:[0-9]+)?)((/[a-zA-Z0-9_\-,.;=%]*)*)((\?[a-zA-Z0-9_\-,.;=&%]*)?)$",
    "prefix"   : r"a://a0",
    "pumpable" : r"00",
    "suffix"   : r"",
    "n"        : 5,
  },
# = [2965] =
# INPUT: ^((http|https|ftp)\://)?([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)*(/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-]*)*$
# PARSE: OK
# SIZE: 155
# PUMPABLE: YES
# VULNERABLE: YES {}
# KLEENE: (/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-]*)*
# PREFIX: http://a.aA
# PUMPABLE: /!/0
# SUFFIX: !
  {
    "index"    : "2965",
    "exp"      : r"^((http|https|ftp)\://)?([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,4})(\:[0-9]+)*(/[^/][a-zA-Z0-9\.\,\?\'\\/\+&%\$#\=~_\-]*)*$",
    "prefix"   : r"http://a.aA",
    "pumpable" : r"/!/0",
    "suffix"   : r"!",
    "n"        : 10,
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

def validate_regexlib():
  print "{0:^90}".format("=[REGEXLIB]=")
  print hline
  print header_format.format("ID", "PUMPS", "TIMES", "GROWTH", "NOTES")
  print hline
  for tpl in regexlib_suite:
    if (stress_id == ""):
      profile(tpl)
    elif (stress_id == tpl["index"]):
      stress(tpl)

# main
validate_regexlib()
