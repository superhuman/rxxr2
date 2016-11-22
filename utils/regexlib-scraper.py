#
# Copyright (c) 2012 James Kirrage, Asiri Rathnayake and Hayo Thielecke
#

import urllib2
import re
import HTMLParser
from bs4 import BeautifulSoup

# Entry point
def main():
  pagec = num_pages()

  # set of regexes, allows to eliminate repeated entries
  expset = set()  

  if -1 == pagec:
    print "Unable to determine the number of pages to scrape, aborting..."
  else:
    for i in range(pagec):
      req = urllib2.Request("http://regexlib.com/Search.aspx?k=&c=-1&m=-1&ps=100&p={}&AspxAutoDetectCookieSupport=1".format(i + 1))
      resp = urllib2.urlopen(req)
      scrape(resp.read(), expset)

# Figure out the total number of pages of regexes to be crawled
def num_pages():
  req = urllib2.Request("http://regexlib.com/Search.aspx?k=&c=-1&m=-1&ps=100&p=1&AspxAutoDetectCookieSupport=1")
  resp = urllib2.urlopen(req)
  pagec_exp = re.compile(r'<span id="ctl00_ContentPlaceHolder1_Pager1_TotalPagesLabel">(\d+)</span>')
  pages = re.findall(pagec_exp, resp.read())
  if len(pages) > 0:
    return int(pages[0])
  else:
    return -1

# Parse page and extract all regexes in it
def scrape(page, expset):
  soup = BeautifulSoup(page)
  # Filter out all the table-row elements containing titles, decriptions & regexes 
  rows = soup.findAll("tr", {"title", "description", "expression"})

  # Loop through the results
  it = iter(rows)
  while (True):
    try:
      # Get the ID of this regex from the link to it 
      # i.e.  <a href='REDetails.aspx?regexp_id=3642' ...>
      regid = it.next().findAll('a')[0]['href'].split('=')[1]
      # Get the contents of the div containing the regex
      regdiv = it.next().findAll('div')[0].contents
      # Get the contents of the div containing the description
      descdiv = it.next().findAll('div')[0].contents
    except StopIteration:
      break
 
    # If the length of the regex is 0, do not parse any further
    if len(regdiv) == 0:
      continue
    else: 
      regex = regdiv[0].extract()

    # Check if this regex has already been added
    if regex in expset:
      continue
    else:
      expset.add(regex) 
        
    # If the length of the description is 0, add a default description
    if len(descdiv) == 0:
      desc = "[Default]" 
    else: 
      desc = descdiv[0].extract()

    # Print the results        
    print ("# {}".format(format_desc(desc)))
    print ("# ID: {}".format(regid))
    fregex = format_regex(regex);
    if "\n" in fregex:
      # These expressions need to be processed manually
      print ("# Multiline")
    print ("{}\n".format(fregex))

# Some pre-processing on the regex description string
def format_desc(desc):
  # Grab the first line of the description, un-escape HTML entities and encode the whole string in UTF-8
  # The UTF-8 encoding is necessary because some decriptions contain non-ascii characters in them 
  return HTMLParser.HTMLParser().unescape(desc.split("\n")[0].strip()).encode('utf-8')
    
# Minimal pre-processesing on the regex string (does not change the semantics of the expression)
def format_regex(regex):
  # Un-encode html entities
  regex = HTMLParser.HTMLParser().unescape(regex);
  # Convert windows-stype line terminators to Unix-stype line terminators
  regex = regex.replace("\r\n","\n").strip()
  # Some regex strings contain embedded unicode characters, these need to be preserved
  return regex.encode('utf-8')
        
if __name__ == '__main__':
  main()
