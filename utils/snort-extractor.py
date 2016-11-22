#
# Copyright (c) 2012 James Kirrage, Asiri Rathnayake and Hayo Thielecke
#

import argparse
import os
import re

def main():
  parser = argparse.ArgumentParser(description = "Extracts all PCRE regexes from a Snort ruleset")
  parser.add_argument("ruledir", help="Directory in which Snort .rules files are stored")
  args = parser.parse_args()
    
  ruledir = args.ruledir
  rulefiles = []
    
  # Recursively build up a list of all .rules files in this directory
  if os.path.isdir(ruledir):     
    for root, _, files in os.walk(ruledir):
      for f in files:
        if f.endswith(".rules"):
          rulefiles.append(os.path.join(root,f))
  else: 
    print "Input location must be a directory."
   
  # Parse each file 
  try:
    for f in rulefiles:
      with open(f, 'r') as rulesfile:
        parse_rules_file(rulesfile)
  except IOError as e:
    print "Could not open snort rule file:\n\t", e
                    
# Extracts the regexes in a single rules file
def parse_rules_file (infile):
  # Regex to extract a PCRE regex from a Snort rule definition
  rule_match_c = re.compile(r'.*pcre\s*:\s*"((?:\\.|[^"])*)"')
    
  # Check each line and extract the regex (if available)
  for line in infile:
    regex = re.match(rule_match_c, line)
    if regex is not None:
      print "{}".format(regex.group(1))    

if __name__ == '__main__':
  main()
