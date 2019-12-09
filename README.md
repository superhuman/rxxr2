This is a clone of http://www.cs.bham.ac.uk/~hxt/research/rxxr2/ as of
2016-11-22 My hope is to add support for the few features missing to run the
code on all the regexes in the Superhuman email client. PR's welcome :).

# Installation

Install OCaml

## macOS

```
brew install ocaml
```

## GNU/Linux

```
sudo dnf install ocaml # Fedora
sudo apt-get install ocaml # Debian/Ubuntu
```

Install OPAM:

```
sh <(curl -sL https://raw.githubusercontent.com/ocaml/opam/master/shell/install.sh)
```

Clone this REPO:

```
git clone https://github.com/ConradIrwin/rxxr2
```

Build the code

```
cd rxxr2/code
./build.sh
```

Run the script

```
./code/scan.bin -i data/input/snort-raw.txt
```

If you want to validate a regular expression add it to a file:

```
echo '/([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$/' > input.txt
./code/scan.bin -i input.txt
```

If your regular expression is vulnerable to DoS attacks, it will print out: `VULNERABLE: YES`,
if your regular expression is not, it will print out: `VULNERABLE: NO`

For more information on regular expression denial of service, see [OWASP](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS).

There is also an included web-server, you can build with:

```
cd rxxr2/code
dune build http.exe  # even on non-windows platforms, this command works
```

And then run the output binary:

```
PORT=8080 ./_build/default/http.exe
```

It will listen on port 8080 and you make requests to it like:

```
curl -X POST http://localhost:8080/check --data '{"regexes":["a\\1","[gh](a|b|ab)*c"]}'
{
  "results": [
    {
      "input": "a.*",
      "result": "ok"
    },
    {
      "input": "[gh](a|b|ab)*c",
      "result": "vulnerable",
      "kleene": "(a|b|ab)*",
      "prefix": "g",
      "pumpable": "ab",
      "suffix": ""
    }
  ]
}
```

# Layout

+ code/
  - source code for RXXR
+ data/
  - input data-sets (Snort, RegexLib) and RXXR outputs for those regexes
  - scripts for validating the vulnerabilities discovered above
+ utils/
  - scripts used to scrape regexes from Snort and RegexLib

# License

```
Copyright (c) 2016 University of Birmingham

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

# regex.rip setup

There's a Google Cloud Project (regex-rip) that has Google Cloud Build set up
to pick up changes from master and deploy them to Google Cloud Run.
