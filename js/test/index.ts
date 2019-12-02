import { expect } from "chai";
import { NFA, intersectRanges } from "../src/nfa";

const nfa = (string: any) => {
  return (string[0] as string).replace(/\n */g, "\n").replace(/^\n/, "");
};

let tests: { [string: string]: string } = {
  "/a/": nfa`
  0: a -> 1
  1 [accepting]
`,
  "/a?/": nfa`
  0 [accepting]
  0: a -> 1
  1 [accepting]
`
};

Object.keys(tests).forEach(regex => {
  it("should compile " + regex + " correctly", () => {
    expect(NFA.fromString(regex).summarize()).to.equal(tests[regex]);
  });
});

let matching = [
  { regex: "/.*/", input: "a" },
  { regex: "/a/", input: "ba" },
  { regex: "/a/", input: "b" },
  { regex: "/\\wm/", input: "moon about" },
  { regex: "/\\Wa/", input: "moon about" },
  { regex: "/\\bm/", input: "moon about" },
  { regex: "/\\Ba/", input: "moon about" },
  { regex: "/^a/", input: "moon about" },
  { regex: "/a{3,10}/", input: "moon about" },
  { regex: "/a{3,10}/", input: "moon aaabout" }
];

for (let { regex, input } of matching) {
  let shouldMatch = eval(regex).test(input);

  it(`should ${shouldMatch ? "match" : "not match"} ${regex} against ${JSON.stringify(input)}`, function() {
    expect(NFA.fromString(regex).match(input)).to.equal(shouldMatch);
  });
}

it("should intersect ranges correctly", function() {
  expect(intersectRanges([{ from: 0, to: 0xffff }], [{ from: 10, to: 11 }])).to.deep.equal([{ from: 10, to: 11 }]);
  expect(intersectRanges([{ from: 0, to: 10 }], [{ from: 15, to: 25 }])).to.deep.equal([]);
  expect(intersectRanges([{ from: 0, to: 20 }], [{ from: 15, to: 25 }])).to.deep.equal([{ from: 15, to: 20 }]);
  expect(intersectRanges([{ from: 15, to: 25 }], [{ from: 0, to: 20 }])).to.deep.equal([{ from: 15, to: 20 }]);
  expect(
    intersectRanges(
      [
        { from: 0, to: 47 },
        { from: 49, to: 96 }
      ],
      [{ from: 48, to: 57 }]
    )
  ).to.deep.equal([{ from: 49, to: 57 }]);
  expect(
    intersectRanges(
      [{ from: 10, to: 25 }],
      [
        { from: 0, to: 15 },
        { from: 20, to: 30 }
      ]
    )
  ).to.deep.equal([
    { from: 10, to: 15 },
    { from: 20, to: 25 }
  ]);
});

let fromTestsTxt = [
  {
    input: "/(a|ab|b)*c|.*/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "ab",
    suffix: ""
  },
  {
    input: "/.*|(a|ab|b)*c/",
    isPumpable: true,
    vulnerable: "NO {}"
  },
  {
    input: "/.*c|(a|ab|b)*c/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "ab",
    suffix: ""
  },
  {
    input: "/.*b|(a|ab|b)*c/",
    isPumpable: true,
    vulnerable: "NO {}"
  },
  {
    input: "/(.*b|(a|ab|b)*c)d/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "ab",
    suffix: ""
  },
  {
    input: "/a.*|(b|a|ab)*c/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "bab",
    suffix: ""
  },
  {
    input: "/c.*|(c|d)(a|b|ab)*e/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "d",
    pumpable: "ab",
    suffix: ""
  },
  {
    input: "/d.*|((c|d)(a|a))*b/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "ca",
    suffix: ""
  },
  {
    input: "/a.*|(c*a(b|b))*d/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "cab",
    suffix: ""
  },
  {
    input: "/(a|a|b|b)*(a.*|c)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "b",
    suffix: ""
  },
  {
    input: "/(a|b).*|c*(a|b|ab)*d/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "c",
    pumpable: "ab",
    suffix: ""
  },
  {
    input: "/(ab|a*b|aab.*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "ab",
    suffix: "!"
  },
  {
    input:
      "/([\\d\\w-.]+?\\.(a[cdefgilmnoqrstuwz]|b[abdefghijmnorstvwyz]|c[acdfghiklmnoruvxyz]|d[ejkmnoz]|e[ceghrst]|f[ijkmnor]|g[abdefghilmnpqrstuwy]|h[kmnrtu]|i[delmnoqrst]|j[emop]|k[eghimnprwyz]|l[abcikrstuvy]|m[acdghklmnopqrstuvwxyz]|n[acefgilopruz]|om|p[aefghklmnrstwy]|qa|r[eouw]|s[abcdeghijklmnortuvyz]|t[cdfghjkmnoprtvwz]|u[augkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw]|aero|arpa|biz|com|coop|edu|info|int|gov|mil|museum|name|net|org|pro)(\\b|\\W(?<!&|=)(?!\\.\\s|\\.{3}).*?))(\\s|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(432)}"
  },
  {
    input: "/<a\\s*href=(.*?)[\\s|>]/",
    isPumpable: false
  },
  {
    input: "/\\/((978[\\--– ])?[0-9][0-9\\--– ]{10}[\\--– ][0-9xX])|((978)?[0-9]{9}[0-9Xx])\\//",
    wasParseError: "{ParsingData.NonAsciiInput(9, 226)}"
  },
  {
    input:
      "/^[a-zA-Z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:\\.[a-zA-Z0-9!#$%&'*+\\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+(?:[a-zA-Z]{2}|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel)$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\+][0-9]{1,3}([ \\.\\-])?)?([\\(]{1}[0-9]{3}[\\)])?([0-9A-Z \\.\\-]{1,32})((x|ext|extension)?[0-9]{1,4}?)$/",
    isPumpable: false
  },
  {
    input:
      "/^(d{0}|(31(?!(FEB|APR|JUN|SEP|NOV)))|((30|29)(?!FEB))|(29(?=FEB(((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(29(?=FEB(((0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])(JAN|FEB|MAR|MAY|APR|JUL|JUN|AUG|OCT|SEP|NOV|DEC)((1[6-9]|[2-9]\\d)\\d{2}|\\d{2}|d{0})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(10)}"
  },
  {
    input: "/^(-?[1-9](\\.\\d+)?)((\\s?[X*]\\s?10[E^]([+-]?\\d+))|(E([+-]?\\d+)))$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{4}-){3}\\d{4}$|^(\\d{4} ){3}\\d{4}$|^\\d{16}$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z '-]+)$/",
    isPumpable: false
  },
  {
    input: "/^(?=^.{1,254}$)(^(?:(?!\\.|-)([a-z0-9\\-\\*]{1,63}|([a-z0-9\\-]{1,62}[a-z0-9]))\\.)+(?:[a-z]{2,})$)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^\\s*[+-]?\\s*(?:\\d{1,3}(?:(,?)\\d{3})?(?:\\1\\d{3})*(\\.\\d*)?|\\.\\d+)\\s*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]+[NnSs] [0-9]+[WwEe]$/",
    isPumpable: false
  },
  {
    input: "/^\\d*[0-9](|.\\d*[0-9]|)*$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(?s)( class=\\w+(?=([^<]*>)))|(<!--\\[if.*?<!\\[endif\\]-->)|(<!\\[if !\\w+\\]>)|(<!\\[endif\\]>)|(<o:p>[^<]*<\\/o:p>)|(<span[^>]*>)|(<\\/span>)|(font-family:[^>]*[;'])|(font-size:[^>]*[;'])(?-s)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(15)}"
  },
  {
    input: "/^(([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w ]*.*))+\\.((html|HTML)|(htm|HTM))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\0",
    pumpable: "\\0\\0",
    suffix: ""
  },
  {
    input: "/^[^'<>?%!\\s]{1,20}$/",
    isPumpable: false
  },
  {
    input:
      "/(?=^.{12,25}$)(?=(?:.*?\\d){2})(?=.*[a-z])(?=(?:.*?[A-Z]){2})(?=(?:.*?[!@#$%*()_+^&}{:;?.]){2})(?!.*\\s)[0-9a-zA-Z!@#$%*()_+^&]*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?=^.{1,}$)(?!.*\\s)[0-9a-zA-Z!@#$%*()_+^&\\[\\]]*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^(?:[\\w]\\:|\\\\)(\\\\[a-z_\\-\\s0-9\\.]+)+\\.(txt|gif|pdf|doc|docx|xls|xlsx)$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[0-9]+.*)(?=.*[a-zA-Z]+.*)[0-9a-zA-Z]{6,}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^((?-i:0x)?[A-Fa-f0-9]{32}|[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}|\\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\\})$/",
    isPumpable: false,
    wasParseError: "?-i"
  },
  {
    input: "/^[\\w\\.=-]+@[\\w\\.-]+\\.[\\w]{2,3}$/",
    isPumpable: false
  },
  {
    input:
      "/(<meta [.\\w\\W]*?\\>)|(<style [.\\w\\W]*?<\\/style>)|(<link [.\\w\\W]*?\\>)|(<script [.\\w\\W]*?<\\/script>)/",
    isPumpable: false
  },
  {
    input:
      "/^((?!000)(?!666)(?:[0-6]\\d{2}|7[0-2][0-9]|73[0-3]|7[5-6][0-9]|77[0-2]))-((?!00)\\d{2})-((?!0000)\\d{4})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/(?<=[\\?|\\&])(?<key>[^\\?=\\&\\#]+)=?(?<value>[^\\?=\\&\\#]*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(14, 60)}"
  },
  {
    input: "/\\/[^\\/]+$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      '/<script(?:(?:.*(?<src>(?<=src=")[^"]*(?="))[^>]*)|[^>]*)>(?<content>(?:(?:\\n|.)(?!(?:\\n|.)<script))*)</script>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 60)}"
  },
  {
    input: "/^[0-9]{6}-[0-9pPtTfF][0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{1,2}[\\d]{1,2}([A-Za-z])?\\s?[\\d][A-Za-z]{2}$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^([0-2][0-9]\\:[0-5][0-9]\\:[0-5][0-9])\\s+up\\s+([0-9\\:]{1,5})\\s*(days|day|min|mins)?(?:\\,\\s+([0-9\\:]{1,5})\\s*(days|day|min|mins)?)?\\,\\s+([0-9]{1,4})\\susers?\\,\\s+load\\s+average\\:\\s+([0-9\\.]{1,6})\\,\\s+([0-9\\.]{1,6})\\,\\s+([0-9\\.]{1,6})$\\//",
    isPumpable: false
  },
  {
    input:
      "/^(?=[^&])(?:(?<scheme>[^:\\/?#]+):)?(?:\\/\\/(?<authority>[^\\/?#]*))?(?<path>[^?#]*)(?:\\?(?<query>[^#]*))?(?:#(?<fragment>.*))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(14, 60)}"
  },
  {
    input: "/\\b(([\\w-]+:\\/\\/?|www[.])[^\\s()<>]+(?:\\([\\w\\d]+\\)|([^[:punct:]\\s]|\\/)))/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^[89][0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/[0][^0]|([^0]{1}(.){1})|[^0]*/",
    isPumpable: false
  },
  {
    input: "/^[0-9]+\\.?[0-9]?[0-9]?[0,5]?$/",
    isPumpable: false
  },
  {
    input: "/^((\\+){0,1}91(\\s){0,1}(\\-){0,1}(\\s){0,1}){0,1}9[0-9](\\s){0,1}(\\-){0,1}(\\s){0,1}[1-9]{1}[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/(?!^0*$)(?!^0*\\.0*$)^\\d{1,10}(\\.\\d{1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/Percentage allowing upto 4 places of decimal/",
    isPumpable: false
  },
  {
    input: "/^[1-9][0-9]{3}\\s?[a-zA-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[\\u0081-\\uFFFF]{1,}$/",
    wasParseError: "{ParsingData.UnsupportedEscape(3, 117)}"
  },
  {
    input: "/akku Dell Vostro 1310/",
    isPumpable: false
  },
  {
    input: "/^([GB])*(([1-9]\\d{8})|([1-9]\\d{11}))$/",
    isPumpable: false
  },
  {
    input: "/^\\+?972(\\-)?0?[23489]{1}(\\-)?[^0\\D]{1}\\d{6}$/",
    isPumpable: false
  },
  {
    input: "/http:\\/\\/(?:www\\.|)uploaded\\.to\\/\\?id=[a-z0-9]{6}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\/[^imsxeADSUXu]([imsxeADSUXu]*)$\\//",
    isPumpable: false
  },
  {
    input: "/'([dmstrl])([ .,?!\\)\\\\/<])/",
    isPumpable: false
  },
  {
    input: "/^.*(([^\\.][\\.][wW][mM][aA])|([^\\.][\\.][mM][pP][3]))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{4}\\d{6}[a-zA-Z]{6}\\d{2}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{3,4}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9a-zA-z]{3}$/",
    isPumpable: false
  },
  {
    input: "/(?=(?:[^\\']*\\'[^\\']*\\')*(?![^\\']*\\'))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/<\\/{0,1}(?!\\/|b>|i>|p>|a\\s|a>|br|em>|ol|li|strong>)[^>]*>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(8)}"
  },
  {
    input: "/<\\/?(\\w+)(\\s*\\w*\\s*=\\s*(\"[^\"]*\"|'[^']'|[^>]*))*|\\/?>/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      '/<a\\s{1}href="(?<url>.*?)"(\\s?target="(?<target>_(blank|new|parent|self|top))")?(\\s?class="(?<class>.*?)")?(\\s?style="(?<style>.*?)")?>(?<title>.*?)</a>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(15, 60)}"
  },
  {
    input:
      "/^(((ht|f)tp(s?))\\:\\/\\/)?(www.|[a-zA-Z].)[a-zA-Z0-9\\-\\.]+\\.(com|edu|gov|mil|net|org|biz|info|name|museum|us|ca|uk)(\\:[0-9]+)*(\\/($|[a-zA-Z0-9\\.\\,\\;\\?\\'\\\\\\+&%\\$#\\=~_\\-]+))*$/",
    isPumpable: false
  },
  {
    input: "/^(?![0-9]{6})[0-9a-zA-Z]{6}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[\\n <\"']*([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)/",
    isPumpable: false
  },
  {
    input: "/^\\w+\\.((?:\\w+\\.)+\\w+)$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*@(([0-9a-zA-Z])+([-\\w]*[0-9a-zA-Z])*\\.)+[a-zA-Z]{2,9})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "00",
    suffix: ""
  },
  {
    input: "/^(\\+48\\s*)?\\d{2}\\s*\\d{3}(\\s*|\\-)\\d{2}(\\s*|\\-)\\d{2}$/",
    isPumpable: false
  },
  {
    input: "/^((\\d{3}[- ]\\d{3}[- ]\\d{2}[- ]\\d{2})|(\\d{3}[- ]\\d{2}[- ]\\d{2}[- ]\\d{3}))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?>(?:\\-(?=\\d|\\())|(?:(?<=\\d|\\))(?:\\+|\\/|\\*)(?=\\d|\\(|\\-))|(?<parenthesis>(?<=^|\\+|\\/|\\-|\\*|\\()\\((?=\\d|\\(|\\-))|(?<-parenthesis>(?<=\\d|\\)))(?!\\d))|(?:(?<=\\(|\\-|\\+|\\*|\\/|^)(?:\\d+(?:\\,\\d{1,4})?)(?=$|\\)|\\-|\\+|\\*|\\/))) + (?(parenthesis)(?!)))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(64, 60)}"
  },
  {
    input:
      "/^(((\\(\\d{3}\\)|\\d{3})( |-|\\.))|(\\(\\d{3}\\)|\\d{3}))?\\d{3}( |-|\\.)?\\d{4}(( |-|\\.)?([Ee]xt|[Xx])[.]?( |-|\\.)?\\d{4})?$/",
    isPumpable: false
  },
  {
    input: "/(?:^(?:-)?(?:\\d{1,3}\\.(?:\\d{3}\\.)*\\d{3})(?:\\,\\d+)?$|^(?:-)?\\d*(?:\\,\\d+)?$)/",
    isPumpable: false
  },
  {
    input: '/(?:[\\w]*) *= *"(?:(?:(?:(?:(?:\\\\\\W)*\\\\\\W)*[^"]*)\\\\\\W)*[^"]*")/',
    isPumpable: true,
    isVulnerable: true,
    prefix: ' ="',
    pumpable: "\\\\\\]\\]",
    suffix: ""
  },
  {
    input:
      "/(?:(?:http|https):\\/\\/(?:(?:[^\\/&=()\\/§, ]*?)*\\.)+(?:\\w{2,3})+?)(?:\\/+[^ ?,'§$&()={\\[\\]}]*)*(?:\\?+.*)?$/",
    wasParseError: "{ParsingData.NonAsciiInput(34, 194)}"
  },
  {
    input:
      "/(<[^>]*?tag[^>]*?(?:identify_by)[^>]*>)((?:.*?(?:<[ \\r\\t]*tag[^>]*>?.*?(?:<.*?\\/.*?tag.*?>)?)*)*)(<[^>]*?\\/[^>]*?tag[^>]*?>)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<tagidentify_by>",
    pumpable: "<<tag</><tag<tag></</>/tagtag>",
    suffix: ""
  },
  {
    input: "/^\\d{1,3}[.]\\d{1,3}[.]\\d{1,3}[.]\\d{1,3}$/",
    isPumpable: false
  },
  {
    input: "/[0-9]{4}-[0-9]{3}/",
    isPumpable: false
  },
  {
    input: "/^([A-Za-z]|[A-Za-z][0-9]*|[0-9]*[A-Za-z])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "A",
    suffix: "!"
  },
  {
    input:
      "/(\\+1|1)?[ \\-\\.]?\\(?(?<areacode>[0-9]{3})\\)?[ \\-\\.]?(?<prefix>[0-9]{3})[ \\-\\.]?(?<number>[0-9]{4})[ \\.]*(ext|x)?[ \\.]*(?<extension>[0-9]{0,5})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(21, 60)}"
  },
  {
    input: "/(http[s]?:\\/\\/)?([A-Za-z0-9-]\\.)*(?<domainName>([A-Za-z0-9-]+\\.)[A-Za-z]{2,3})\\/?.$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(33, 60)}"
  },
  {
    input: "/^(|(0\\d)|(1[0-2])):(([0-5]\\d)):(([0-5]\\d))\\s([AP]M)$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))/",
    isPumpable: false
  },
  {
    input: "/((19|20)[0-9]{2})-(([1-9])|(0[1-9])|(1[0-2]))-((3[0-1])|([0-2][0-9])|([0-9]))/",
    isPumpable: false
  },
  {
    input: "/^1+0+$/",
    isPumpable: false
  },
  {
    input: "/^([1][12]|[0]?[1-9])[\\/-]([3][01]|[12]\\d|[0]?[1-9])[\\/-](\\d{4}|\\d{2})$/",
    isPumpable: false
  },
  {
    input: "/[\\x00-\\x1F\\x7F]/",
    isPumpable: false
  },
  {
    input: "/^\\$[+-]?([0-9]+|[0-9]{1,3}(,[0-9]{3})*)(\\.[0-9]{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^http[s]?:\\/\\/([a-zA-Z0-9\\-]+\\.)*([a-zA-Z]{3,61}|[a-zA-Z]{1,}\\.[a-zA-Z]{2})\\/.*$/",
    isPumpable: false
  },
  {
    input: "/[0-9]{4}[0-3]{1}[0-9}{1}[0-9]{5}/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/(15(8[48]|9[26]))|((1[6-9]|[2-9]\\d)(0[48]|[13579][26]|[2468][048]))|(([2468][048]|16|3579[26])00)/",
    isPumpable: false
  },
  {
    input: "/^[a-z0-9_]{1}[a-z0-9\\-_]*(\\.[a-z0-9\\-_]+)*@[a-z0-9]{1}[a-z0-9\\-_]*(\\.[a-z0-9\\-_]+)*\\.[a-z]{2,4}$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z]*( [a-zA-Z]*)?/",
    isPumpable: false
  },
  {
    input: "/(\\d{2}\\.\\d{3}\\.\\d{3}\\/\\d{4}\\-\\d{2})|(\\d{3}\\.\\d{3}\\.\\d{3}\\-\\d{2})/",
    isPumpable: false
  },
  {
    input: "/^\\d*[0-9](\\.\\d?[0-9])?$/",
    isPumpable: false
  },
  {
    input: "/^((\\d{0,1}[0-9](\\.\\d{0,1}[0-9])?)|(100))$/",
    isPumpable: false
  },
  {
    input: "/<[^>]*\\n?.*=(\"|')?(.*\\.jpg)(\"|')?.*\\n?[^<]*>/",
    isPumpable: false
  },
  {
    input: "/([A-Z]:\\\\[^/:\\*;\\/\\:\\?<>\\|]+)|(\\\\{2}[^/:\\*;\\/\\:\\?<>\\|]+)/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}\\.?\\t*\\s*){2}\\(\\r*\\n*([0-9]{1,})/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z.\\s']{1,50})$/",
    isPumpable: false
  },
  {
    input: "/([a-zA-Z]{1}[a-zA-Z]*[\\s]{0,1}[a-zA-Z])+([\\s]{0,1}[a-zA-Z]+)/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/",
    isPumpable: false
  },
  {
    input: "/((^[0-9]*).?((BIS)|(TER)|(QUATER))?)?((\\W+)|(^))(([a-z]+.)*)([0-9]{5})?.(([a-z\\'']+.)*)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "aaa{",
    suffix: "aa00!"
  },
  {
    input: "/username=(.*)&password=(.*)/",
    isPumpable: false
  },
  {
    input: "/\\b[A-z0-9._%-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b/",
    isPumpable: false
  },
  {
    input: "/^((8|\\+38)-?)?(\\(?044\\)?)?-?\\d{3}-?\\d{2}-?\\d{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^(([0-9]{1})|([0-9]{1}[0-9]{1})|([1-3]{1}[0-6]{1}[0-5]{1}))d(([0-9]{1})|(1[0-9]{1})|([1-2]{1}[0-3]{1}))h(([0-9]{1})|([1-5]{1}[0-9]{1}))m$/",
    isPumpable: false
  },
  {
    input:
      "/^[a-zA-Z]+(([\\'\\,\\.\\- ][a-zA-Z ])?[a-zA-Z]*)*\\s+<(\\w[-._\\w]*\\w@\\w[-._\\w]*\\w\\.\\w{2,3})>$|^(\\w[-._\\w]*\\w@\\w[-._\\w]*\\w\\.\\w{2,3})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "A",
    suffix: ""
  },
  {
    input: "/^[^\\s]+@[^\\.][^\\s]{1,}\\.[A-Za-z]{2,10}$/",
    isPumpable: false
  },
  {
    input: "/^[\\w-]+(\\.[\\w-]+)*@([a-z0-9-]+(\\.[a-z0-9-]+)*?\\.[a-z]{2,6}|(\\d{1,3}\\.){3}\\d{1,3})(:\\d{4})?$/",
    isPumpable: false
  },
  {
    input: "/^[-]?([1-9]{1}[0-9]{0,}(\\.[0-9]{0,2})?|0(\\.[0-9]{0,2})?|\\.[0-9]{1,2})$/",
    isPumpable: false
  },
  {
    input: "/(\\+)?([-\\._\\(\\) ]?[\\d]{3,20}[-\\._\\(\\) ]?){2,10}/",
    isPumpable: false
  },
  {
    input:
      "/(?n:^(?=\\d)((?<day>31(?!(.0?[2469]|11))|30(?!.0?2)|29(?(.0?2)(?=.{3,4}(1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00))|0?[1-9]|1\\d|2[0-8])(?<sep>[\\/.-])(?<month>0?[1-9]|1[012])\\2(?<year>(1[6-9]|[2-9]\\d)\\d{2})(?:(?=\\x20\\d)\\x20|$))?(?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(?i:\\ [AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input: "/^([0-9a-fA-F]{4}|0)(\\:([0-9a-fA-F]{4}|0)){7}$/",
    isPumpable: false
  },
  {
    input: "/^(102[0-3]|10[0-1]\\d|[1-9][0-9]{0,2}|0)$/",
    isPumpable: false
  },
  {
    input:
      "/^(4915[0-1]|491[0-4]\\d|490\\d\\d|4[0-8]\\d{3}|[1-3]\\d{4}|[2-9]\\d{3}|1[1-9]\\d{2}|10[3-9]\\d|102[4-9])$/",
    isPumpable: false
  },
  {
    input: "/^(6553[0-5]|655[0-2]\\d|65[0-4]\\d\\d|6[0-4]\\d{3}|5\\d{4}|49[2-9]\\d\\d|491[6-9]\\d|4915[2-9])$/",
    isPumpable: false
  },
  {
    input: "/^(4915[0-1]|491[0-4]\\d|490\\d\\d|4[0-8]\\d{3}|[1-3]\\d{4}|[1-9]\\d{0,3}|0)$/",
    isPumpable: false
  },
  {
    input: "/^(6553[0-5]|655[0-2]\\d|65[0-4]\\d\\d|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3}|0)$/",
    isPumpable: false
  },
  {
    input:
      '/^((([hH][tT][tT][pP][sS]?|[fF][tT][pP])\\:\\/\\/)?([\\w\\.\\-]+(\\:[\\w\\.\\&%\\$\\-]+)*@)?((([^\\s\\(\\)\\<\\>\\\\\\"\\.\\[\\]\\,@;:]+)(\\.[^\\s\\(\\)\\<\\>\\\\\\"\\.\\[\\]\\,@;:]+)*(\\.[a-zA-Z]{2,4}))|((([01]?\\d{1,2}|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d{1,2}|2[0-4]\\d|25[0-5])))(\\b\\:(6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3}|0)\\b)?((\\/[^\\/][\\w\\.\\,\\?\\\'\\\\\\/\\+&%\\$#\\=~_\\-@]*)*[^\\.\\,\\?\\"\\\'\\(\\)\\[\\]!;<>{}\\s\\x7F-\\xFF])?)$/',
    wasParseError: "{ParsingData.NonAsciiInput(389, 255)}"
  },
  {
    input:
      "/^((0?[1-9]|1[012])(\\s*:\\s*([0-5]\\d))?(\\s*:\\s*([0-5]\\d))?(\\s*([AaPp])[Mm]?)$|(2[0-3]|[1]\\d|0?\\d)(\\s*:\\s*([0-5]\\d))(\\s*:\\s*([0-5]\\d))?)$/",
    isPumpable: false
  },
  {
    input:
      "/^(1\\s*[-\\/\\.]?)?(\\((\\d{3})\\)|(\\d{3}))\\s*[-\\/\\.]?\\s*(\\d{3})\\s*[-\\/\\.]?\\s*(\\d{4})\\s*(([xX]|[eE][xX][tT])\\.?\\s*(\\d+))*$/",
    isPumpable: false
  },
  {
    input: "/^((([sS][r-tR-Tx-zX-Z])\\s*([sx-zSX-Z])?\\s*([a-zA-Z]{2,3}))?\\s*(\\d\\d)\\s*-?\\s*(\\d{6,7}))$/",
    isPumpable: false
  },
  {
    input: "/^#?(([fFcC0369])\\2){3}$/",
    wasParseError: "{ParsingData.InvalidBackreference(16)}"
  },
  {
    input:
      '/\\<\\!doctype\\s+(([^\\s\\>]+)\\s+)?(([^\\s\\>]+)\\s*)?(\\"([^\\/]+)\\/\\/([^\\/]+)\\/\\/([^\\s]+)\\s([^\\/]+)\\/\\/([^\\"]+)\\")?(\\s*\\"([^\\"]+)\\")?\\>/',
    isPumpable: false
  },
  {
    input: "/^#(\\d{6})|^#([A-F]{6})|^#([A-F]|[0-9]){6}/",
    isPumpable: false
  },
  {
    input: "/^\\s*([\\(]?)\\[?\\s*\\d{3}\\s*\\]?[\\)]?\\s*[\\-]?[\\.]?\\s*\\d{3}\\s*[\\-]?[\\.]?\\s*\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{2}[0-9]{6}[A-DFM]{1}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{1,2}[1-9][0-9]?[A-Z]? [0-9][A-Z]{2,}|GIR 0AA$/",
    isPumpable: false
  },
  {
    input: "/(\\$(([0-9]?)[a-zA-Z]+)([0-9]?))/",
    isPumpable: false
  },
  {
    input: "/^\\{(.+)|^\\\\(.+)|(\\}*)/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z0-9][a-zA-Z0-9_]*(\\.{0,1})?[a-zA-Z0-9\\-_]+)*(\\.{0,1})@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|([a-zA-Z0-9\\-]+(\\.([a-zA-Z]{2,10}))(\\.([a-zA-Z]{2,10}))?(\\.([a-zA-Z]{2,10}))?))[\\s]*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "A0",
    suffix: ""
  },
  {
    input: "/\\/^[a-zA-Z\\s]+$\\//",
    isPumpable: false
  },
  {
    input:
      "/^(?<path>(\\/?(?<step>\\w+))+)(?<predicate>\\[(?<comparison>\\s*(?<lhs>@\\w+)\\s*(?<operator><=|>=|<>|=|<|>)\\s*(?<rhs>('[^']*'|\"[^\"]*\"))\\s*(and|or)?)+\\])*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[a-zA-Z][0-9][a-zA-Z]\\s?[0-9][a-zA-Z][0-9]$/",
    isPumpable: false
  },
  {
    input: "/^((\\d{5}-\\d{4})|(\\d{5})|([A-Z]\\d[A-Z]\\s\\d[A-Z]\\d))$/",
    isPumpable: false
  },
  {
    input:
      "/(?<=(?:\\n|:|^)\\s*?)(if|end\\sif|elseif|else|for\\seach|for|next|call|class|exit|do|loop|const|dim|erase|option\\s(?:explicit|implicit)|(?:public|private|end)\\ssub|(?:public|private|end)\\sfunction|private|public|redim|select\\scase|end\\sselect|case\\selse|case|set|while|wend|with|end\\swith|on\\serror\\sgoto\\s0|on\\serror\\sresume\\snext|exit|end\\sclass|property\\slet|property\\sget|property\\sset)(?=\\s|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/(?<=(?:\\n|:|&|\\()\\s*?)(Application\\.Unlock|Application\\.Lock|Application\\.Contents\\.RemoveAll|Application\\.Contents\\.Remove|Request\\.BinaryRead|Request\\.ClientCertificate|Request\\.Cookies|Request\\.Form|Request\\.QueryString|Request\\.ServerVariables|Request\\.TotalBytes|Response\\.AddHeader|Response\\.AppendToLog|Response\\.BinaryWrite|Response\\.Clear|Response\\.End|Response\\.Flush|Response\\.Redirect|Response\\.Write|Response\\.Buffer|Response\\.CacheControl|Response\\.Charset|Response\\.CodePage|Response\\.ContentType|Response\\.Cookies|Response\\.Expires|Response\\.ExpiresAbsolute|Response\\.IsClientConnected|Response\\.LCID|Response\\.PICS|Response\\.Status|Server\\.ScriptTimeout|Server\\.CreateObject|Server\\.Execute|Server\\.GetLastError|Server\\.HTMLEncode|Server\\.MapPath|Server\\.Transfer|Server\\.URLEncode|Session\\.Abandon|Session\\.Contents\\.Remove|Session\\.Contents\\.RemoveAll|Session\\.CodePage|Session\\.Contents|Session\\.LCID|Session\\.SessionID|Session\\.StaticObjects|Session\\.Timeout|Application|Session|Request)(?=\\s|\\.|\\()/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/(?<=\\s|:|&|\\()(Abs|Array|Asc|Atn|CBool|CByte|CCur|CDate|CDbl|Chr|CInt|CLng|Conversions|Cos|CreateObject|CSng|CStr|DateAdd|DateDiff|DatePart|DateSerial|DateValue|Date|Day|DerivedMath|Escape|Eval|Exp|Filter|FormatCurrency|FormatDateTime|FormatNumber|FormatPercent|GetLocale|GetObject|GetRef|Hex|Hour|InputBox|InStr|InStrRev|Int|Fix|IsArray|IsDate|IsEmpty|IsNull|IsNumeric|IsObject|Join|LBound|LCase|Left|Len|LoadPicture|Log|LTrim|RTrim|Trim|Maths|Mid|Minute|Month|MonthName|MsgBox|Now|Oct|Replace|RGB|Right|Rnd|Round|ScriptEngineBuildVersion|ScriptEngineMajorVersion|ScriptEngineMinorVersion|ScriptEngine|Second|SetLocale|Sgn|Sin|Space|Split|Sqr|StrComp|String|StrReverse|Tan|Timer|TimeSerial|TimeValue|Time|TypeName|UBound|UCase|Unescape|VarType|WeekdayName|Weekday|Year)(?=\\()/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?<=[\\s=&\\+\\-,\\(\\)])(True|False|Nothing|Empty|Null)(?=[\\s=&\\+\\-,\\(\\)])/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?<=\\s)(And|Or|Eqv|Imp|Is|Mod|Not|Xor)(?=\\s)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[ \\t]*?(?=\\r?\\n)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(7)}"
  },
  {
    input: "/(?<Code>[\\s\\S]*?)(?<NonCode>'.*?\\r?\\n|(?<quot>\"|')(?:(?:(?!\\<quot>).|\\<quot>{2})*)(?:\\<quot>))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(?<Code>[\\s\\S]*?)(?<Comment>'.*?\\r?\\n|(?<quot>\"|')(?:(?:(?!\\<quot>).|\\<quot>{2})*)(?:\\<quot>))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^((((19|20)(([02468][048])|([13579][26]))-02-29))|((20[0-9][0-9])|(19[0-9][0-9]))-((((0[1-9])|(1[0-2]))-((0[1-9])|(1\\d)|(2[0-8])))|((((0[13578])|(1[02]))-31)|(((0[1,3-9])|(1[0-2]))-(29|30)))))$/",
    isPumpable: false
  },
  {
    input: "/^\\\\(\\\\[\\w-]+){1,}(\\\\[\\w-()]+(\\s[\\w-()]+)*)+(\\\\(([\\w-()]+(\\s[\\w-()]+)*)+\\.[\\w]+)?)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "\\\\a\\a( a\\(",
    pumpable: "0(",
    suffix: "\\x00"
  },
  {
    input:
      "/^(([0-9]{3})[ \\-\\/]?([0-9]{3})[ \\-\\/]?([0-9]{3}))|([0-9]{9})|([\\+]?([0-9]{3})[ \\-\\/]?([0-9]{2})[ \\-\\/]?([0-9]{3})[ \\-\\/]?([0-9]{3}))$/",
    isPumpable: false
  },
  {
    input: '/ICON=[a-zA-Z0-9/\\+-;:/-/\\"=]*/',
    isPumpable: false
  },
  {
    input:
      "/^((\\(\\d{3}\\) ?)|(\\d{3}-)|(\\(\\d{2}\\) ?)|(\\d{2}-)|(\\(\\d{1}\\) ?)|(\\d{1}-))?\\d{3}-(\\d{3}|\\d{4})/",
    isPumpable: false
  },
  {
    input: "/^\\(?\\d{3}?\\)?\\-?\\d{3}?\\-?\\d{4}?$/",
    isPumpable: false
  },
  {
    input:
      "/(^(((GIR)\\s{0,1}((0AA))))|(([A-PR-UWYZ][0-9][0-9]?)|([A-PR-UWYZ][A-HK-Y][0-9][0-9]?)|([A-PR-UWYZ][0-9][A-HJKSTUW])|([A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRVWXY]))\\s{0,1}([0-9][ABD-HJLNP-UW-Z]{2})$)/",
    isPumpable: false
  },
  {
    input:
      "/(^([0-9]|[0-1][0-9]|[2][0-3]):([0-5][0-9])(\\s{0,1})(AM|PM|am|pm|aM|Am|pM|Pm{2,2})$)|(^([0-9]|[1][0-9]|[2][0-3])(\\s{0,1})(AM|PM|am|pm|aM|Am|pM|Pm{2,2})$)/",
    isPumpable: false
  },
  {
    input:
      "/^((31(?!([-])(Feb|Apr|June?|Sep|Nov)))|((30|29)(?!([-])Feb))|(29(?=([-])Feb([-])(((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])([-])(Jan|Feb|Ma(r|y)|Apr|Ju(l|n)|Aug|Oct|(Sep|Nov|Dec))([-])((1[6-9]|[2-9]\\d)\\d{2}\\s(([0-1]?[0-9])|([2][0-3])):([0-5]?[0-9])(:([0-5]?[0-9]))?)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/^[0,1]?\\d{1}\\/(([0-2]?\\d{1})|([3][0,1]{1}))\\/(([1]{1}[9]{1}[9]{1}\\d{1})|([2-9]{1}\\d{3}))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z][a-zA-Z\\-' ]*[a-zA-Z ]$/",
    isPumpable: false
  },
  {
    input: '/;?(?:(?:"((?:[^"]|"")*)")|([^;]*))/',
    isPumpable: false
  },
  {
    input: "/^[A-Za-z0-9_]+$/",
    isPumpable: false
  },
  {
    input: "/(str\\=)\\s*(?<value>([a-zA-Z0-9\\,\\.]{1})*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(12, 60)}"
  },
  {
    input: "/^\\d{1,3}\\.\\d{1,4}$/",
    isPumpable: false
  },
  {
    input: "/^[0][5][0]-\\d{7}|[0][5][2]-\\d{7}|[0][5][4]-\\d{7}|[0][5][7]-\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{6,15})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^[0-9]{10}$|^\\(0[1-9]{1}\\)[0-9]{8}$|^[0-9]{8}$|^[0-9]{4}[ ][0-9]{3}[ ][0-9]{3}$|^\\(0[1-9]{1}\\)[ ][0-9]{4}[ ][0-9]{4}$|^[0-9]{4}[ ][0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/([A-Z][\\w\\d\\.\\-]+)(?:(?:\\+)([\\w\\d\\.\\-]+))?@([A-Z0-9][\\w\\.-]*[A-Z0-9]\\.[A-Z][A-Z\\.]*[A-Z])/",
    isPumpable: false
  },
  {
    input:
      "/A(?:CCESS|LLEY|PPROACH|R(?:CADE|TERY)|VE(?:NUE)?)|B(?:A(?:NK|SIN|Y)|E(?:ACH|ND)|L(?:DG|VD)|O(?:ULEVARD|ARDWALK|WL)|R(?:ACE|AE|EAK|IDGE|O(?:ADWAY|OK|W))|UILDING|YPASS)|C(?:A(?:NAL|USEWAY)|ENTRE(?:WAY)?|HASE|IRC(?:LET?|U(?:IT|S))|L(?:OSE)?|O(?:MMON|NCOURSE|PSE|R(?:NER|SO)|UR(?:SE|T(?:YARD)?)|VE)|R(?:ES(?:CENT|T)?|IEF|OSS(?:ING)?)|U(?:LDESAC|RVE))|D(?:ALE|EVIATION|IP|OWNS|R(?:IVE(?:WAY)?)?)|E(?:ASEMENT|DGE|LBOW|N(?:D|TRANCE)|S(?:PLANADE|TATE)|X(?:P(?:(?:RESS)?WAY)|TENSION))|F(?:AIRWAY|IRETRAIL|O(?:LLOW|R(?:D|MATION))|R(?:(?:EEWAY|ONT(?:AGE)?)))|G(?:A(?:P|RDENS?|TE(?:S|WAY)?)|L(?:ADE|EN)|R(?:ANGE|EEN|O(?:UND|VET?)))|H(?:AVEN|E(?:ATH|IGHTS)|I(?:GHWAY|LL)|UB|WY)|I(?:NTER(?:CHANGE)?|SLAND)|JUNCTION|K(?:EY|NOLL)|L(?:A(?:NE(?:WAY)?)?|IN(?:E|K)|O(?:O(?:KOUT|P)|WER))|M(?:ALL|E(?:A(?:D|NDER)|WS)|OTORWAY)|NOOK|O(?:UTLOOK|VERPASS)|P(?:A(?:R(?:ADE|K(?:LANDS|WAY)?)|SS|TH(?:WAY)?)|DE|IER|L(?:A(?:CE|ZA))?|O(?:CKET|INT|RT)|RO(?:MENADE|PERTY)|URSUIT)?|QUA(?:D(?:RANT)?|YS?)|R(?:AMBLE|D|E(?:ACH|S(?:ERVE|T)|T(?:REAT|URN))|I(?:D(?:E|GE)|NG|S(?:E|ING))|O(?:AD(?:WAY)?|TARY|U(?:ND|TE)|W)|UN)|S(?:(?:ER(?:VICE)?WAY)|IDING|LOPE|PUR|QUARE|T(?:EPS|RAND|R(?:EET|IP))?|UBWAY)|T(?:ARN|CE|ERRACE|HRO(?:UGHWAY|WAY)|O(?:LLWAY|P|R)|RA(?:CK|IL)|URN)|UNDERPASS|V(?:AL(?:E|LEY)|I(?:EW|STA))|W(?:A(?:LK(?:WAY)?|Y)|HARF|YND)/",
    isPumpable: false
  },
  {
    input: "/^(?:(?:0?[1-9])|(?:[12]\\d)|3[01])\\/(?:(?:0?[1-9])|(?:1[012]))\\/(?:(?:19|20))\\d{2}$/",
    isPumpable: false
  },
  {
    input: '/(?:\\s*)(?<=[-|/])(?<name>\\w*)[:|=]("((?<value>.*?)(?<!\\\\)")|(?<value>[\\w]*))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(19, 60)}"
  },
  {
    input: "/<body[\\d\\sa-z\\W\\S\\s]*>/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{3,4}[ |\\-]{0,1}[0-9]{6}[ |\\-]{0,1}[0-9A-Za-z]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{4}[ |\\-]{0,1}[0-9]{6}[ |\\-]{0,1}[0-9A-Za-z]{3}$/",
    isPumpable: false
  },
  {
    input: '/^\\[assembly: AssemblyVersion\\(\\"([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/',
    isPumpable: false
  },
  {
    input: "/\\d{2}.?\\d{3}.?\\d{3}\\/?\\d{4}-?\\d{2}/",
    isPumpable: false
  },
  {
    input:
      "/(SELECT\\s[\\w\\*\\)\\(\\,\\s]+\\sFROM\\s[\\w]+)|(UPDATE\\s[\\w]+\\sSET\\s[\\w\\,\\'\\=]+)|(INSERT\\sINTO\\s[\\d\\w]+[\\s\\w\\d\\)\\(\\,]*\\sVALUES\\s\\([\\d\\w\\'\\,\\)]+)|(DELETE\\sFROM\\s[\\d\\w\\'\\=]+)/",
    isPumpable: false
  },
  {
    input: "/^[-+]?\\d+(\\.\\d)?\\d*$/",
    isPumpable: false
  },
  {
    input: "/\\b([0]?[1-9]|[1,2]\\d|3[0,1])[-\\/]([0]?[1-9]|[1][0,1,2])[-\\/](\\d{1,2}|[1][9]\\d\\d|[2][0]\\d\\d)\\b/",
    isPumpable: false
  },
  {
    input: "/^(\\d{5}-\\d{2}-\\d{7})*$/",
    isPumpable: false
  },
  {
    input: "/.*(\\.[Jj][Pp][Gg]|\\.[Gg][Ii][Ff]|\\.[Jj][Pp][Ee][Gg]|\\.[Pp][Nn][Gg])/",
    isPumpable: false
  },
  {
    input: "/^[$]?[0-9]*(\\.)?[0-9]?[0-9]?$/",
    isPumpable: false
  },
  {
    input: "/[A-Z][a-z]+/",
    isPumpable: false
  },
  {
    input: "/^\\d{9}[\\d|X]$/",
    isPumpable: false
  },
  {
    input: "/(\\w+)\\s+\\1/",
    isPumpable: false
  },
  {
    input: "/^(\\d{4}[- ]){3}\\d{4}|\\d{16}$/",
    isPumpable: false
  },
  {
    input: "/^((4\\d{3})|(5[1-5]\\d{2})|(6011))-?\\d{4}-?\\d{4}-?\\d{4}|3[4,7]\\d{13}$/",
    isPumpable: false
  },
  {
    input: "/^.{4,8}$/",
    isPumpable: false
  },
  {
    input: "/^\\d*$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^\\d*\\.?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?\\d*\\.?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9]+$/",
    isPumpable: false
  },
  {
    input: "/^\\d+$/",
    isPumpable: false
  },
  {
    input: "/^(\\+|-)?\\d+$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]\\w{3,14}$/",
    isPumpable: false
  },
  {
    input: "/^\\w+@[a-zA-Z_]+?\\.[a-zA-Z]{2,3}$/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,2}\\/\\d{1,2}\\/\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/foo/",
    isPumpable: false
  },
  {
    input: "/^[1-5]$/",
    isPumpable: false
  },
  {
    input: "/^[12345]$/",
    isPumpable: false
  },
  {
    input: "/^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$/",
    isPumpable: false
  },
  {
    input: "/^[2-9]\\d{2}-\\d{3}-\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}-\\d{4}|\\d{5}|[A-Z]\\d[A-Z] \\d[A-Z]\\d$/",
    isPumpable: false
  },
  {
    input: "/^\\d$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}-\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}$|^\\d{5}-\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/((\\(\\d{3}\\) ?)|(\\d{3}-))?\\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input: "/[\\w-]+@([\\w-]+\\.)+[\\w-]+/",
    isPumpable: false
  },
  {
    input: "/\\d{4}-?\\d{4}-?\\d{4}-?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d).{4,8}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{4,8}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[-+]?\\d+(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^(20|21|22|23|[0-1]\\d)[0-5]\\d$/",
    isPumpable: false
  },
  {
    input: "/^( [1-9]|[1-9]|0[1-9]|10|11|12)[0-5]\\d$/",
    isPumpable: false
  },
  {
    input: "/^(|(0[1-9])|(1[0-2]))\\/((0[1-9])|(1\\d)|(2\\d)|(3[0-1]))\\/((\\d{4}))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^((((0[13578])|(1[02]))[\\/]?(([0-2][0-9])|(3[01])))|(((0[469])|(11))[\\/]?(([0-2][0-9])|(30)))|(02[\\/]?[0-2][0-9]))[\\/]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^DOMAIN\\\\\\w+$/",
    isPumpable: false
  },
  {
    input: "/\\.com\\/(\\d+)$/",
    isPumpable: false
  },
  {
    input: "/^([\\s\\S]){1,20}([\\s\\.])/",
    isPumpable: false
  },
  {
    input: '/"<[ \\t]*[iI][mM][gG][ \\t]*[sS][rR][cC][ \\t]*=[ \\t]*[\'\\"]([^\'\\"]+)"/',
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z][a-zA-Z\\&amp;\\-\\.\\'\\s]*|)$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^(((?:(?:f|ht)tps?(?!\\:\\/\\/[-\\.\\w]+@)|mailto(?=\\:\\/\\/[-\\.\\w]+@))\\:\\/\\/)?(?:((?:(?:(?:2(?:[0-4]\\d|5[0-5])|[01]?\\d?\\d))(?:\\.(?:2(?:[0-4]\\d|5[0-5])|[01]?\\d?\\d)){3})|(?:(?:[a-zA-Z0-9](?:[-\\w]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}(?:(?:\\/[-\\w]+(?=\\/))*)?)|(?:[0-9a-zA-Z](?:[-.\\w]*[0-9a-zA-Z])?@(?:[0-9a-zA-Z](?:[-\\w]*[0-9a-zA-Z])?\\.)+[a-zA-Z]{2,6}(?![\\/\\?])))(\\/[-\\w]+)?(?:(?<=\\w)\\.([a-zA-Z0-9]{2,4}))?(?:(?<=\\w)\\?([a-zA-Z][-\\w]*=[-\\w]+(?:&[a-zA-Z][-\\w]*=[-\\w]+)*))?))$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(18)}"
  },
  {
    input:
      "/^\\s*\\(?((\\+0?44)?\\)?[ \\-]?(\\(0\\))|0)((20[7,8]{1}\\)?[ \\-]?[1-9]{1}[0-9]{2}[ \\-]?[0-9]{4})|([1-8]{1}[0-9]{3}\\)?[ \\-]?[1-9]{1}[0-9]{2}[ \\-]?[0-9]{3}))\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/(?:\\[(?:[\\u0000-\\u005C]|[\\u005E-\\uFFFF]|\\]\\])+\\])|(?:\\u0022(?:[\\u0000-\\u0021]|[\\u0023-\\uFFFF]|\\u0022\\u0022)+\\u0022)|(?:[a-zA-Z_][a-zA-Z0-9_]*)/",
    wasParseError: "{ParsingData.UnsupportedEscape(10, 117)}"
  },
  {
    input: "/(^\\d{5}\\-\\d{3}$)|(^\\d{2}\\.\\d{3}\\-\\d{3}$)|(^\\d{8}$)/",
    isPumpable: false
  },
  {
    input:
      "/(?<entryname>[\\w_0-9]+)\\s*=\\s+\\(\\s*DESCRIPTION\\s*=\\s+\\(\\s*ADDRESS_LIST\\s*=\\s+\\(\\s*ADDRESS\\s*=\\s*\\(\\s*PROTOCOL\\s*=\\s*(?<protocol>\\w+)\\)\\s*\\(\\s*HOST\\s*=\\s*(?<host>[^\\)]+)\\)\\s*\\(\\s*PORT\\s*=\\s*(?<port>\\d+)\\s*\\)\\s*\\)\\s+\\)\\s+\\(\\s*CONNECT_DATA\\s*=\\s+\\(\\s*SERVICE_NAME\\s*=\\s*(?<svcname>\\w+)\\s*\\)\\s+\\)\\s+\\)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^(atuvwdxyzad|abcefdghijd|almnodpqrsd|aß?ded???µd?p?sd)(ktuvwdxyzad|kbcefdghijd|klmnodpqrsd|kß?ded???µd?p?sd)*/",
    wasParseError: "{ParsingData.NonAsciiInput(39, 195)}"
  },
  {
    input: "/^[1-9]{1}[0-9]{3}\\s?[A-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^([0-1]?\\d|2[0-3]):([0-5]\\d)$/",
    isPumpable: false
  },
  {
    input:
      "/(?<expo>public\\:|protected\\:|private\\:) (?<ret>(const )*(void|int|unsigned int|long|unsigned long|float|double|(class .*)|(enum .*))) (?<decl>__thiscall|__cdecl|__stdcall|__fastcall|__clrcall) (?<ns>.*)\\:\\:(?<class>(.*)((<.*>)*))\\:\\:(?<method>(.*)((<.*>)*))\\((?<params>((.*(<.*>)?)(,)?)*)\\)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/([0-0]{1}[1-9]{1}[0-9]{9})|[1-9]{1}[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/(src|href|action)\\s*=\\s*('|\"|(?!\"|'))(?!(http:|ftp:|mailto:|https:|#))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(29)}"
  },
  {
    input:
      "/[0-9][0-9][0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|1[0-9]|2[0-9]|3[0-1])\\s{1}(0[0-9]|1[0-9]|2[0-3]):([0-5][0-9])/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:[123]|I{1,3})\\s*)?(?:[A-Z][a-zA-Z]+|Song of Songs|Song of Solomon).?\\s*(?:1?[0-9]?[0-9]):\\s*\\d{1,3}(?:[,-]\\s*\\d{1,3})*(?:;\\s*(?:(?:[123]|I{1,3})\\s*)?(?:[A-Z][a-zA-Z]+|Song of Songs|Song of Solomon)?.?\\s*(?:1?[0-9]?[0-9]):\\s*\\d{1,3}(?:[,-]\\s*\\d{1,3})*)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^\\$[0-9]+(\\.[0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input:
      '/^[^\']*?\\<\\s*Assembly\\s*:\\s*AssemblyVersion\\s*\\(\\s*"(\\*|[0-9]+.\\*|[0-9]+.[0-9]+.\\*|[0-9]+.[0-9]+.[0-9]+.\\*|[0-9]+.[0-9]+.[0-9]+.[0-9]+)"\\s*\\)\\s*\\>.*$/',
    isPumpable: false
  },
  {
    input: "/([a-zA-Z0-9_\\-\\.]+)(@[a-zA-Z0-9_\\-\\.]+)/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?:http|ftp|gopher|telnet|news):\\/\\/)(?:w{3}\\.)?(?:[a-zA-Z0-9\\/;\\?&=:\\-_\\$\\+!\\*'\\(\\|\\\\~\\[\\]#%\\.])+)/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:[a-zA-Z0-9\\/;\\?&=:\\-_\\$\\+!\\*'\\(\\|\\\\~\\[\\]#%\\.](?!www))+(?:\\.[Cc]om|\\.[Ee]du|\\.[gG]ov|\\.[Ii]nt|\\.[Mm]il|\\.[Nn]et|\\.[Oo]rg|\\.[Bb]iz|\\.[Ii]nfo|\\.[Nn]ame|\\.[Pp]ro|\\.[Aa]ero|\\.[cC]oop|\\.[mM]useum|\\.[Cc]at|\\.[Jj]obs|\\.[Tt]ravel|\\.[Aa]rpa|\\.[Mm]obi|\\.[Aa]c|\\.[Aa]d|\\.[aA]e|\\.[aA]f|\\.[aA]g|\\.[aA]i|\\.[aA]l|\\.[aA]m|\\.[aA]n|\\.[aA]o|\\.[aA]q|\\.[aA]r|\\.[aA]s|\\.[aA]t|\\.[aA]u|\\.[aA]w|\\.[aA]z|\\.[aA]x|\\.[bB]a|\\.[bB]b|\\.[bB]d|\\.[bB]e|\\.[bB]f|\\.[bB]g|\\.[bB]h|\\.[bB]i|\\.[bB]j|\\.[bB]m|\\.[bB]n|\\.[bB]o|\\.[bB]r|\\.[bB]s|\\.[bB]t|\\.[bB]v|\\.[bB]w|\\.[bB]y|\\.[bB]z|\\.[cC]a|\\.[cC]c|\\.[cC]d|\\.[cC]f|\\.[cC]g|\\.[cC]h|\\.[cC]i|\\.[cC]k|\\.[cC]l|\\.[cC]m|\\.[cC]n|\\.[cC]o|\\.[cC]r|\\.[cC]s|\\.[cC]u|\\.[cC]v|\\.[cC]x|\\.[cC]y|\\.[cC]z|\\.[dD]e|\\.[dD]j|\\.[dD]k|\\.[dD]m|\\.[dD]o|\\.[dD]z|\\.[eE]c|\\.[eE]e|\\.[eE]g|\\.[eE]h|\\.[eE]r|\\.[eE]s|\\.[eE]t|\\.[eE]u|\\.[fF]i|\\.[fF]j|\\.[fF]k|\\.[fF]m|\\.[fF]o|\\.[fF]r|\\.[gG]a|\\.[gG]b|\\.[gG]d|\\.[gG]e|\\.[gG]f|\\.[gG]g|\\.[gG]h|\\.[gG]i|\\.[gG]l|\\.[gG]m|\\.[gG]n|\\.[gG]p|\\.[gG]q|\\.[gG]r|\\.[gG]s|\\.[gG]t|\\.[gG]u|\\.[gG]w|\\.[gG]y|\\.[hH]k|\\.[hH]m|\\.[hH]n|\\.[hH]r|\\.[hH]t|\\.[hH]u|\\.[iI]d|\\.[iI]e|\\.[iI]l|\\.[iI]m|\\.[iI]n|\\.[iI]o|\\.[iI]q|\\.[iI]r|\\.[iI]s|\\.[iI]t|\\.[jJ]e|\\.[jJ]m|\\.[jJ]o|\\.[jJ]p|\\.[kK]e|\\.[kK]g|\\.[kK]h|\\.[kK]i|\\.[kK]m|\\.[kK]n|\\.[kK]p|\\.[kK]r|\\.[kK]w|\\.[kK]y|\\.[kK]z|\\.[lL]a|\\.[lL]b|\\.[lL]c|\\.[lL]i|\\.[lL]k|\\.[lL]r|\\.[lL]s|\\.[lL]t|\\.[lL]u|\\.[lL]v|\\.[lL]y|\\.[mM]a|\\.[mM]c|\\.[mM]d|\\.[mM]g|\\.[mM]h|\\.[mM]k|\\.[mM]l|\\.[mM]m|\\.[mM]n|\\.[mM]o|\\.[mM]p|\\.[mM]q|\\.[mM]r|\\.[mM]s|\\.[mM]t|\\.[mM]u|\\.[mM]v|\\.[mM]w|\\.[mM]x|\\.[mM]y|\\.[mM]z|\\.[nN]a|\\.[nN]c|\\.[nN]e|\\.[nN]f|\\.[nN]g|\\.[nN]i|\\.[nN]l|\\.[nN]o|\\.[nN]p|\\.[nN]r|\\.[nN]u|\\.[nN]z|\\.[oO]m|\\.[pP]a|\\.[pP]e|\\.[pP]f|\\.[pP]g|\\.[pP]h|\\.[pP]k|\\.[pP]l|\\.[pP]m|\\.[pP]n|\\.[pP]r|\\.[pP]s|\\.[pP]t|\\.[pP]w|\\.[pP]y|\\.[qP]a|\\.[rR]e|\\.[rR]o|\\.[rR]u|\\.[rR]w|\\.[sS]a|\\.[sS]b|\\.[sS]c|\\.[sS]d|\\.[sS]e|\\.[sS]g|\\.[sS]h|\\.[Ss]i|\\.[sS]j|\\.[sS]k|\\.[sS]l|\\.[sS]m|\\.[sS]n|\\.[sS]o|\\.[sS]r|\\.[sS]t|\\.[sS]v|\\.[sS]y|\\.[sS]z|\\.[tT]c|\\.[tT]d|\\.[tT]f|\\.[tT]g|\\.[tT]h|\\.[tT]j|\\.[tT]k|\\.[tT]l|\\.[tT]m|\\.[tT]n|\\.[tT]o|\\.[tT]p|\\.[tT]r|\\.[tT]t|\\.[tT]v|\\.[tT]w|\\.[tT]z|\\.[uU]a|\\.[uU]g|\\.[uU]k|\\.[uU]m|\\.[uU]s|\\.[uU]y|\\.[uU]z|\\.[vV]a|\\.[vV]c|\\.[vV]e|\\.[vV]g|\\.[vV]i|\\.[vV]n|\\.[vV]u|\\.[wW]f|\\.[wW]s|\\.[yY]e|\\.[yY]t|\\.[yY]u|\\.[zZ]a|\\.[zZ]m|\\.[zZ]w))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(50)}"
  },
  {
    input:
      "/(?:(?:w{3}\\.)(?:[a-zA-Z0-9\\/;\\?&=:\\-_\\$\\+!\\*'\\(\\|\\\\~\\[\\]#%\\.])+[\\.com|\\.edu|\\.gov|\\.int|\\.mil|\\.net|\\.org|\\.biz|\\.info|\\.name|\\.pro|\\.aero|\\.coop|\\.museum|\\.cat|\\.jobs|\\.travel|\\.arpa|\\.mobi|\\.ac|\\.ad|\\.ae|\\.af|\\.ag|\\.ai|\\.al|\\.am|\\.an|\\.ao|\\.aq|\\.ar|\\.as|\\.at|\\.au|\\.aw|\\.az|\\.ax|\\.ba|\\.bb|\\.bd|\\.be|\\.bf|\\.bg|\\.bh|\\.bi|\\.bj|\\.bm|\\.bn|\\.bo|\\.br|\\.bs|\\.bt|\\.bv|\\.bw|\\.by|\\.bz|\\.ca|\\.cc|\\.cd|\\.cf|\\.cg|\\.ch|\\.ci|\\.ck|\\.cl|\\.cm|\\.cn|\\.co|\\.cr|\\.cs|\\.cu|\\.cv|\\.cx|\\.cy|\\.cz|\\.de|\\.dj|\\.dk|\\.dm|\\.do|\\.dz|\\.ec|\\.ee|\\.eg|\\.eh|\\.er|\\.es|\\.et|\\.eu|\\.fi|\\.fj|\\.fk|\\.fm|\\.fo|\\.fr|\\.ga|\\.gb|\\.gd|\\.ge|\\.gf|\\.gg|\\.gh|\\.gi|\\.gl|\\.gm|\\.gn|\\.gp|\\.gq|\\.gr|\\.gs|\\.gt|\\.gu|\\.gw|\\.gy|\\.hk|\\.hm|\\.hn|\\.hr|\\.ht|\\.hu|\\.id|\\.ie|\\.il|\\.im|\\.in|\\.io|\\.iq|\\.ir|\\.is|\\.it|\\.je|\\.jm|\\.jo|\\.jp|\\.ke|\\.kg|\\.kh|\\.ki|\\.km|\\.kn|\\.kp|\\.kr|\\.kw|\\.ky|\\.kz|\\.la|\\.lb|\\.lc|\\.li|\\.lk|\\.lr|\\.ls|\\.lt|\\.lu|\\.lv|\\.ly|\\.ma|\\.mc|\\.md|\\.mg|\\.mh|\\.mk|\\.ml|\\.mm|\\.mn|\\.mo|\\.mp|\\.mq|\\.mr|\\.ms|\\.mt|\\.mu|\\.mv|\\.mw|\\.mx|\\.my|\\.mz|\\.na|\\.nc|\\.ne|\\.nf|\\.ng|\\.ni|\\.nl|\\.no|\\.np|\\.nr|\\.nu|\\.nz|\\.om|\\.pa|\\.pe|\\.pf|\\.pg|\\.ph|\\.pk|\\.pl|\\.pm|\\.pn|\\.pr|\\.ps|\\.pt|\\.pw|\\.py|\\.qa|\\.re|\\.ro|\\.ru|\\.rw|\\.sa|\\.sb|\\.sc|\\.sd|\\.se|\\.sg|\\.sh|\\..si|\\.sj|\\.sk|\\.sl|\\.sm|\\.sn|\\.so|\\.sr|\\.st|\\.sv|\\.sy|\\.sz|\\.tc|\\.td|\\.tf|\\.tg|\\.th|\\.tj|\\.tk|\\.tl|\\.tm|\\.tn|\\.to|\\.tp|\\.tr|\\.tt|\\.tv|\\.tw|\\.tz|\\.ua|\\.ug|\\.uk|\\.um|\\.us|\\.uy|\\.uz|\\.va|\\.vc|\\.ve|\\.vg|\\.vi|\\.vn|\\.vu|\\.wf|\\.ws|\\.ye|\\.yt|\\.yu|\\.za|\\.zm|\\.zw](?:[a-zA-Z0-9/;\\?&=:\\-_\\$\\+!\\*'\\(\\|\\\\~\\[\\]#%\\.])*)/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?:\\+)?1[\\-\\s\\.])?(?:\\s?\\()?(?:[2-9][0-8][0-9])(?:\\))?(?:[\\s|\\-|\\.])?)(?:(?:(?:[2-9][0-9|A-Z][0-9|A-Z])(?:[\\s|\\-|\\.])?)(?:[0-9|A-Z][0-9|A-Z][0-9|A-Z][0-9|A-Z]))/",
    isPumpable: false
  },
  {
    input: "/for mobile:^[0][1-9]{1}[0-9]{9}$/",
    isPumpable: false
  },
  {
    input: "/^[0][1-9]{2}(-)[0-9]{8}$  and  ^[0][1-9]{3}(-)[0-9]{7}$  and  ^[0][1-9]{4}(-)[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*/",
    isPumpable: false
  },
  {
    input: "/^((\\+){1}91){1}[1-9]{1}[0-9]{9}$/",
    isPumpable: false
  },
  {
    input: "/^(?<full>(?<part1>[ABCEGHJKLMNPRSTVXY]{1}\\d{1}[A-Z]{1})(?:[ ](?=\\d))?(?<part2>\\d{1}[A-Z]{1}\\d{1}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[1-9]{1}$|^[1-9]{1}[0-9]{1}$|^[1-3]{1}[0-6]{1}[0-5]{1}$|^365$/",
    isPumpable: false
  },
  {
    input: "/^\\s*(?'num'\\d+(\\.\\d+)?)\\s*(?'unit'((w(eek)?)|(wk)|(d(ay)?)|(h(our)?)|(hr))s?)(\\s*$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 39)}"
  },
  {
    input:
      "/^(GIR\\\\s{0,1}0AA|[A-PR-UWYZ]([0-9]{1,2}|([A-HK-Y][0-9]|[A-HK-Y][0-9]([0-9]|[ABEHMNPRV-Y]))|[0-9][A-HJKS-UW])\\\\s{0,1}[0-9][ABD-HJLNP-UW-Z]{2})$/",
    isPumpable: false
  },
  {
    input: "/^.*(?=.{8,})(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(^[a-zA-Z0-9@\\$=!:.#%]+$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input: "/^[-+]?(?:\\d+\\.?|\\.\\d)\\d*(?:[Ee][-+]?\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^([\\+]|0)[(\\s]{0,1}[2-9][0-9]{0,2}[\\s-)]{0,2}[0-9][0-9][0-9\\s-]*[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]*[a-zA-Z]([-.\\w]*[0-9a-zA-Z])*@([a-zA-Z][-\\w\\.]*[0-9a-zA-Z]\\.)+[a-zA-Z]{2,9})$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/([+(]?\\d{0,2}[)]?)([-\\/.\\s]?\\d+)+/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/[({]?(0x)?[0-9a-fA-F]{8}([-,]?(0x)?[0-9a-fA-F]{4}){2}((-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12})|(,\\{0x[0-9a-fA-F]{2}(,0x[0-9a-fA-F]{2}){7}\\}))[)}]?/",
    isPumpable: false
  },
  {
    input: "/^(0[1-9]|[12][0-9]|3[01])\\/(0[1-9]|1[012])\\/((19|20)\\d{2}|\\d{2})$/",
    isPumpable: false
  },
  {
    input: "/^p(ost)?[ |\\.]*o(ffice)?[ |\\.]*(box)?[ 0-9]*[^[a-z ]]*/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^-?\\d+([.,]?\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^\\d+([.,]?\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^-?\\d+([^.,])?$/",
    isPumpable: false
  },
  {
    input: "/^\\d+([^.,])?$/",
    isPumpable: false
  },
  {
    input: "/(^([0-9]*[.][0-9]*[1-9]+[0-9]*)$)|(^([0-9]*[1-9]+[0-9]*[.][0-9]+)$)|(^([1-9]+[0-9]*)$)/",
    isPumpable: false
  },
  {
    input: '/((?<html>(href|src)\\s*=\\s*")|(?<css>url\\())(?<url>.*?)(?(html)"|\\))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^(GIR|[A-Z]\\d[A-Z\\d]?|[A-Z]{2}\\d[A-Z\\d]?)[ ]??(\\d[A-Z]{0,2})??$/",
    isPumpable: false
  },
  {
    input: "/^(GIR|[A-Z]\\d[A-Z\\d]??|[A-Z]{2}\\d[A-Z\\d]??)[ ]??(\\d[A-Z]{2})$/",
    isPumpable: false
  },
  {
    input: "/(\\s(\\bon[a-zA-Z][a-z]+)\\s?\\=\\s?[\\'\\\"]?(javascript\\:)?[\\w\\(\\),\\' ]*;?[\\'\\\"]?)+/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^((0[1-9])|(1[0-2]))\\/(\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/(href=|url|import).*[\\'\"]([^(http:)].*css)[\\'\"]/",
    isPumpable: false
  },
  {
    input:
      "/^(([a-h,A-H,j-n,J-N,p-z,P-Z,0-9]{9})([a-h,A-H,j-n,J-N,p,P,r-t,R-T,v-z,V-Z,0-9])([a-h,A-H,j-n,J-N,p-z,P-Z,0-9])(\\d{6}))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1,2}[0-9][0-9A-Za-z]{0,1} {0,1}[0-9][A-Za-z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^\\$?(\\d{1,3},?(\\d{3},?)*\\d{3}(\\.\\d{0,2})?|\\d{1,3}(\\.\\d{0,2})?|\\.\\d{1,2}?)$/",
    isPumpable: false
  },
  {
    input: "/^((6011)((-|\\s)?[0-9]{4}){3})$/",
    isPumpable: false
  },
  {
    input: "/^((5[1-5])([0-9]{2})((-|\\s)?[0-9]{4}){3})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9!@#$%^&*()-_=+;:'\"|~`<>?/{}]{1,5})$/",
    isPumpable: false
  },
  {
    input: "/^([^\\.]+).([^\\.]+).([^\\.]+).([^\\.]+)$/",
    isPumpable: false
  },
  {
    input: "/^\\$?\\d{1,3}(,?\\d{3})*(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,8}$|^\\d{1,3},\\d{3}$|^\\d{1,2},\\d{3},\\d{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:(?:0?[1-9]|1\\d|2[0-8])\\/(?:0?[1-9]|1[0-2]))\\/(?:(?:1[6-9]|[2-9]\\d)\\d{2}))$|^(?:(?:(?:31\\/0?[13578]|1[02])|(?:(?:29|30)\\/(?:0?[1,3-9]|1[0-2])))\\/(?:(?:1[6-9]|[2-9]\\d)\\d{2}))$|^(?:29\\/0?2\\/(?:(?:(?:1[6-9]|[2-9]\\d)(?:0[48]|[2468][048]|[13579][26]))))$/",
    isPumpable: false
  },
  {
    input: "/&( )/",
    isPumpable: false
  },
  {
    input: "/^(?:\\([2-9]\\d{2}\\)\\ ?|[2-9]\\d{2}(?:\\-?|\\ ?))[2-9]\\d{2}[- ]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^(?:\\([2-9]\\d{2}\\)\\ ?|(?:[2-9]\\d{2}\\-))[2-9]\\d{2}\\-\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?[0-9]+[.]?[0-9]*([eE][-+]?[0-9]+)?$/",
    isPumpable: false
  },
  {
    input: "/^\\p{Sc}?[A-Z]{0,3}?[ ]?(\\d{1,3})(\\.|\\,)(\\d{0,4})?[ ]?\\p{Sc}?[A-Z]{0,3}?$/",
    wasParseError: "{ParsingData.UnsupportedEscape(2, 112)}"
  },
  {
    input:
      "/^[_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.(([0-9]{1,3})|([a-zA-Z]{2,3})|(aero|coop|info|museum|name))$/",
    isPumpable: false
  },
  {
    input:
      "/^((([a-z]|[0-9]|!|#|$|%|&|'|\\*|\\+|\\-|\\/|=|\\?|\\^|_|`|\\{|\\||\\}|~)+(\\.([a-z]|[0-9]|!|#|$|%|&|'|\\*|\\+|\\-|\\/|=|\\?|\\^|_|`|\\{|\\||\\}|~)+)*)@((((([a-z]|[0-9])([a-z]|[0-9]|\\-){0,61}([a-z]|[0-9])\\.))*([a-z]|[0-9])([a-z]|[0-9]|\\-){0,61}([a-z]|[0-9])\\.(af|ax|al|dz|as|ad|ao|ai|aq|ag|ar|am|aw|au|at|az|bs|bh|bd|bb|by|be|bz|bj|bm|bt|bo|ba|bw|bv|br|io|bn|bg|bf|bi|kh|cm|ca|cv|ky|cf|td|cl|cn|cx|cc|co|km|cg|cd|ck|cr|ci|hr|cu|cy|cz|dk|dj|dm|do|ec|eg|sv|gq|er|ee|et|fk|fo|fj|fi|fr|gf|pf|tf|ga|gm|ge|de|gh|gi|gr|gl|gd|gp|gu|gt| gg|gn|gw|gy|ht|hm|va|hn|hk|hu|is|in|id|ir|iq|ie|im|il|it|jm|jp|je|jo|kz|ke|ki|kp|kr|kw|kg|la|lv|lb|ls|lr|ly|li|lt|lu|mo|mk|mg|mw|my|mv|ml|mt|mh|mq|mr|mu|yt|mx|fm|md|mc|mn|ms|ma|mz|mm|na|nr|np|nl|an|nc|nz|ni|ne|ng|nu|nf|mp|no|om|pk|pw|ps|pa|pg|py|pe|ph|pn|pl|pt|pr|qa|re|ro|ru|rw|sh|kn|lc|pm|vc|ws|sm|st|sa|sn|cs|sc|sl|sg|sk|si|sb|so|za|gs|es|lk|sd|sr|sj|sz|se|ch|sy|tw|tj|tz|th|tl|tg|tk|to|tt|tn|tr|tm|tc|tv|ug|ua|ae|gb|us|um|uy|uz|vu|ve|vn|vg|vi|wf|eh|ye|zm|zw|com|edu|gov|int|mil|net|org|biz|info|name|pro|aero|coop|museum|arpa))|(((([0-9]){1,3}\\.){3}([0-9]){1,3}))|(\\[((([0-9]){1,3}\\.){3}([0-9]){1,3})\\])))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9._\\-]+@[a-z0-9\\-]+(\\.[a-z]+){1,}$/",
    isPumpable: false
  },
  {
    input:
      "/(?<Element>((\\*|\\w+)?)) (?<Complement>((\\.|\\#|\\-|\\w|\\:)*)) (?<FamilySeparator>([\\s\\>\\+\\~]|[\\,\\{]))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/<\\/?(tag1|tag2)[^>]*\\/?>/",
    isPumpable: false
  },
  {
    input: "/<(tag1|tag2)[^>]*\\/?>.*<\\/(?:\\1)>/",
    isPumpable: false
  },
  {
    input: '/(src|href|action)="(?!http://|#|mailto:|&)([^/#"])/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(19)}"
  },
  {
    input: '/<a((?:(?! title=)[^">]*"[^">]*")+)>([^<]+)<\\/a>/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(6)}"
  },
  {
    input: "/(<(tag1|tag2)[^>]*\\/?>)[\\w\\S\\s]*?(<\\/(?:\\2)>)/",
    isPumpable: false
  },
  {
    input: "/\\b(?!000)(?!666)(?!9)[0-9]{3}[ -]?(?!00)[0-9]{2}[ -]?(?!0000)[0-9]{4}\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/\\d{3})[- .]?(\\d{3}[- .]?\\d{4}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^(.*)/",
    isPumpable: false
  },
  {
    input: "/start\\s*([^$]*)\\s*(.*?)/",
    isPumpable: false
  },
  {
    input: "/wonder\\s*([^$]*)\\s*with/",
    isPumpable: false
  },
  {
    input:
      "/((?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Sept|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?))(\\s+)[0-9]{2,4}/",
    isPumpable: false
  },
  {
    input: "/^(.|\\n){0,16}$/",
    isPumpable: false
  },
  {
    input: '/(?<=,)\\s*(?=,)|^(?=,)|[^\\"]{2,}(?=\\")|([^,\\"]+(?=,|$))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^(\\$\\ |\\$)?((0|00|[1-9]\\d*|([1-9]\\d{0,2}(\\,\\d{3})*))(\\.\\d{1,4})?|(\\.\\d{1,4}))$/",
    isPumpable: false
  },
  {
    input: "/^([ \\u00c0-\\u01ffa-zA-Z'])+$/",
    wasParseError: "{ParsingData.UnsupportedEscape(5, 117)}"
  },
  {
    input: "/^\\s*[a-zA-Z0-9,\\s]+\\s*$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9!@#$&_]+$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z0-9]+([\\-])?[a-zA-Z0-9]+)+(\\.)?)+[a-zA-Z]{2,6}$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a0",
    pumpable: "0AA0",
    suffix: ""
  },
  {
    input:
      "/^(((ht|f)tp(s?))\\:\\/\\/)?((([a-zA-Z0-9_\\-]{2,}\\.)+[a-zA-Z]{2,})|((?:(?:25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)(?(\\.?\\d)\\.)){4}))(:[a-zA-Z0-9]+)?(\\/[a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~]*)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(102, 40)}"
  },
  {
    input: "/{.*}/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(0)}"
  },
  {
    input:
      "/^(?:-([0-9]{1,2})|([0-9]{4}))?(?:-?(?:([0-9]{2})?(?:-?([0-9]{2}))?|W([0-9]{2})(?:-?([1-7]))?|([0-9]{3})))?(?:T([0-9]{2})(?::?([0-9]{2})(?::?([0-9]{2}))?)?(?:[,\\.]([0-9]+))?(?:(Z)|([+-])([0-9]{2})(?::?([0-9]{2}))?)?)?$/",
    isPumpable: false
  },
  {
    input: "/([A-Za-z0-9.]+\\s*)+,/",
    isPumpable: true,
    isVulnerable: true,
    prefix: ".",
    pumpable: "..",
    suffix: ""
  },
  {
    input: "/^[0-9]*\\/{1}[1-9]{1}[0-9]*$/",
    isPumpable: false
  },
  {
    input:
      "/^(ht|f)tp(s?)\\:\\/\\/(([a-zA-Z0-9\\-\\._]+(\\.[a-zA-Z0-9\\-\\._]+)+)|localhost)(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\'\\/\\\\\\+&%\\$#_]*)?([\\d\\w\\.\\/\\%\\+\\-\\=\\&\\?\\:\\\\\\\"\\'\\,\\|\\~\\;]*)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "https://localhosta.-",
    pumpable: ".-.-",
    suffix: "!"
  },
  {
    input:
      "/^(?=0?[1-9]\\/|1[012]\\/)(?:(?<month>(?<month31days>0?[13578]|1[02])|(?<month30days>0?[469]|11)|(?<monthFeb>0?2))\\/)(?<day>(?(month31days)(?:[012]?[1-9]|3[01]))(?(month30days)(?:[012]?[1-9]|30))(?(monthFeb)(?:[01]?[1-9]|2(?(?=\\d\\/(?:(?:(?:04|08|12|16|20|24|28|32|36|40|44|48|52|56|60|64|68|72|76|80|84|88|92|96)00)|(?:\\d\\d(?:04|08|12|16|20|24|28|32|36|40|44|48|52|56|60|64|68|72|76|80|84|88|92|96))))[0-9]|[0-8]))))\\/(?<year>(?!0000)\\d{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(26, 60)}"
  },
  {
    input:
      "/^(?<line1>(?!\\s+)[^\\n]+)\\n(?:(?<line2>(?!\\s+)[^\\n]+)\\n)?(?<city>[^,\\n]+), +(?<state>-i:A[LKSZRAEP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY]) +(?<zip>(?<zip5>\\d{5})(?:[ -]?(?<zip4>\\d{4}))?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?-i:A[LKSZRAEP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])$/",
    isPumpable: false
  },
  {
    input: "/^(?!00000)(?<zip>(?<zip5>\\d{5})(?:[ -](?=\\d))?(?<zip4>\\d{4})?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(12, 60)}"
  },
  {
    input: "/^(?:(?:25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)(?(?=\\.?\\d)\\.)){4}$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(41, 40)}"
  },
  {
    input:
      "/^(?:(?<1>[(])?(?<AreaCode>[2-9]\\d{2})(?(1)[)])(?(1)(?<2>[ ])|(?:(?<3>[-])|(?<4>[ ])))?)?(?<Prefix>[1-9]\\d{2})(?(AreaCode)(?:(?(1)(?(2)[- ]|[-]?))|(?(3)[-])|(?(4)[- ]))|[- ]?)(?<Suffix>\\d{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input:
      "/^(?:(?<1>[(])?(?<AreaCode>[2-9]\\d{2})(?(1)[)])(?(1)(?<2>[ ])|(?:(?<3>[-])|(?<4>[ ])))?)?(?<Prefix>[1-9]\\d{2})(?(AreaCode)(?:(?(1)(?(2)[- ]|[-]?))|(?(3)[-])|(?(4)[- ]))|[- ]?)(?<Suffix>\\d{4})(?:[ ]?[xX]?(?<Ext>\\d{2,4}))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/^(?<field1>[^,]+),(?<field2>[^,]+),(?<field3>[^,]+)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?!000)(?!666)(?<SSN3>[0-6]\\d{2}|7(?:[0-6]\\d|7[012]))([- ]?)(?!00)(?<SSN2>\\d\\d)\\1(?!0000)(?<SSN4>\\d{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 60)}"
  },
  {
    input:
      "/^(?:(?<Visa>4\\d{3})|(?<Mastercard>5[1-5]\\d{2})|(?<Discover>6011)|(?<DinersClub>(?:3[68]\\d{2})|(?:30[0-5]\\d))|(?<AmericanExpress>3[47]\\d{2}))([ -]?)(?(DinersClub)(?:\\d{6}\\1\\d{4})|(?(AmericanExpress)(?:\\d{6}\\1\\d{5})|(?:\\d{4}\\1\\d{4}\\1\\d{4})))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/(?n:(^\\$?(?!0,?\\d)\\d{1,3}(?=(?<1>,)|(?<1>))(\\k<1>\\d{3})*(\\.\\d\\d)?)$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      "/(?n:(^(?(?![^,]+?,)((?<first>[A-Z][a-z]*?) )?((?<second>[A-Z][a-z]*?) )?((?<third>[A-Z][a-z]*?) )?)(?<last>[A-Z](('|[a-z]{1,2})[A-Z])?[a-z]+))(?(?=,)(, (?<first>[A-Z][a-z]*?))?( (?<second>[A-Z][a-z]*?))?( (?<third>[A-Z][a-z]*?))?)$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input: "/(?-i)(?=^.{8,}$)((?!.*\\s)(?=.*[A-Z])(?=.*[a-z]))(?=(1)(?=.*\\d)|.*[^A-Za-z0-9])^.*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/\\/^(?P<salutation>(Mr|MR|Ms|Miss|Mrs|Dr|Sir)(\\.?))?\\s*((?<first>[A-Za-z\\-]*?) )?((?<second>[A-Za-z\\-]*?) )?((?<third>[A-Za-z\\-]*?) )?(?(?!(PHD|MD|3RD|2ND|RN|JR|II|SR|III))(?<last>([A-Za-z](([a-zA-Z\\-\\']{1,2})[A-Za-z\\-\\'])?[a-zA-Z\\-\\']+)))( (?P<suffix>(PHD|MD|3RD|2ND|RN|JR|II|SR|III)))?$\\//",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 80)}"
  },
  {
    input: "/^((\\d|[1-9]\\d|2[0-4]\\d|25[0-5]|1\\d\\d)(?:\\.(\\d|[1-9]\\d|2[0-4]\\d|25[0-5]|1\\d\\d)){3})$/",
    isPumpable: false
  },
  {
    input:
      "/^((?<dir>[\\-ld])(?<permission>([\\-r][\\-w][\\-xs]){3})\\s+(?<filecode>\\d+)\\s+(?<owner>\\w+)\\s+(?<group>\\w+)\\s+(?<size>\\d+)\\s+(?<timestamp>(?<year>\\d{4})-(?<month>\\d{2})-(?<day>\\d?\\d)\\s+(?<hour>\\d{2}):(?<minute>\\d{2}))\\s+(?<name>\\w.+))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input:
      "/^((?<dir>[\\-ld])(?<permission>([\\-r][\\-w][\\-xs]){3})\\s+(?<filecode>\\d+)\\s+(?<owner>\\w+)\\s+(?<group>\\w+)\\s+(?<size>\\d+)\\s+(?<timestamp>(?<month>[a-z|A-Z]{3})\\s+(?<day>(\\d?\\d))\\s+(?<hour>\\d?\\d):(?<minute>\\d{2}))\\s+(?<name>\\w.+))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input:
      "/^((0*[0-1]?[0-9]{1,2}\\.)|(0*((2[0-4][0-9])|(25[0-5]))\\.)){3}((0*[0-1]?[0-9]{1,2})|(0*((2[0-4][0-9])|(25[0-5]))))$/",
    isPumpable: false
  },
  {
    input: "/\\$[0-9]?[0-9]?[0-9]?((\\,[0-9][0-9][0-9])*)?(\\.[0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input: "/^\\b\\d{2,3}-*\\d{7}\\b$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{1,}?\\.[\\d]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{2}[-][0-9]{2}[-][0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[+]447\\d{9}$/",
    isPumpable: false
  },
  {
    input: "/(^[+]?\\d*\\.?\\d*[1-9]+\\d*$)|(^[+]?[1-9]+\\d*\\.\\d*$)/",
    isPumpable: false
  },
  {
    input: "/e(vi?)?/",
    isPumpable: false
  },
  {
    input: "/(vi(v))?d/",
    isPumpable: false
  },
  {
    input: "/^((\\d{5}-\\d{4})|(\\d{5})|([AaBbCcEeGgHhJjKkLlMmNnPpRrSsTtVvXxYy]\\d[A-Za-z]\\s?\\d[A-Za-z]\\d))$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9]+)([\\._-]?[a-zA-Z0-9]+)*@([a-zA-Z0-9]+)([\\._-]?[a-zA-Z0-9]+)*([\\.]{1}[a-zA-Z0-9]{2,})+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input: "/([0-9][0-9])((0[1-9])|(1[0-2]))((0[1-9])|([1-2][0-9])|(3[0-1]))\\-([0-9][0-9])\\-([0-9][0-9][0-9][0-9])/",
    isPumpable: false
  },
  {
    input: "/\\(([0-9]{2}|0{1}((x|[0-9]){2}[0-9]{2}))\\)\\s*[0-9]{3,4}[- ]*[0-9]{4}/",
    isPumpable: false
  },
  {
    input: "/^([a-z0-9]+([\\-a-z0-9]*[a-z0-9]+)?\\.){0,}([a-z0-9]+([\\-a-z0-9]*[a-z0-9]+)?){1,63}(\\.[a-z0-9]{2,7})+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "0000000000000000000000000000000000000000000000000000000000000000.",
    suffix: ""
  },
  {
    input: "/((xmlns:.*?=[\",'].*?[\",'])|(xmlns=[\",'].*?[\",']))/",
    isPumpable: false
  },
  {
    input: "/<\\s*?[^>]+\\s*?>/",
    isPumpable: false
  },
  {
    input:
      "/^(((\\d{4})(0[13578]|10|12)(0[1-9]|[12][0-9]|3[01]))|((\\d{4})(0[469]|11)([0][1-9]|[12][0-9]|30))|((\\d{4})(02)(0[1-9]|1[0-9]|2[0-8]))|(([02468][048]00)(02)(29))|(([13579][26]00) (02)(29))|(([0-9][0-9][0][48])(02)(29))|(([0-9][0-9][2468][048])(02)(29))|(([0-9][0-9][13579][26])(02)(29))|(00000000)|(88888888)|(99999999))?$/",
    isPumpable: false
  },
  {
    input: "/[()+-.0-9]*/",
    isPumpable: false
  },
  {
    input: "/^((\\\\{2}\\w+)\\$?)((\\\\{1}\\w+)*$)/",
    isPumpable: false
  },
  {
    input: "/.*?((?:\\b|\\+)\\d[\\d \\-\\(\\)]+\\d)\\b.*/",
    isPumpable: false
  },
  {
    input:
      "/^(((0|128|192|224|240|248|252|254).0.0.0)|(255.(0|128|192|224|240|248|252|254).0.0)|(255.255.(0|128|192|224|240|248|252|254).0)|(255.255.255.(0|128|192|224|240|248|252|254)))$/",
    isPumpable: false
  },
  {
    input:
      "/^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})(\\/([0-9]|[0-2][0-9]|3[0-2]))$/",
    isPumpable: false
  },
  {
    input:
      "/(^(((([1-9])|([0][1-9])|([1-2][0-9])|(30))\\-([A,a][P,p][R,r]|[J,j][U,u][N,n]|[S,s][E,e][P,p]|[N,n][O,o][V,v]))|((([1-9])|([0][1-9])|([1-2][0-9])|([3][0-1]))\\-([J,j][A,a][N,n]|[M,m][A,a][R,r]|[M,m][A,a][Y,y]|[J,j][U,u][L,l]|[A,a][U,u][G,g]|[O,o][C,c][T,t]|[D,d][E,e][C,c])))\\-[0-9]{4}$)|(^(([1-9])|([0][1-9])|([1][0-9])|([2][0-8]))\\-([F,f][E,e][B,b])\\-[0-9]{2}(([02468][1235679])|([13579][01345789]))$)|(^(([1-9])|([0][1-9])|([1][0-9])|([2][0-9]))\\-([F,f][E,e][B,b])\\-[0-9]{2}(([02468][048])|([13579][26]))$)/",
    isPumpable: false
  },
  {
    input: "/([a-zA-Z]:(\\\\w+)*\\\\[a-zA-Z0_9]+)?.xls/",
    isPumpable: false
  },
  {
    input: "/^[^']*$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((0?[1-9])|(1\\d)|(2[0-8]))\\.((0?[1-9])|(1[0-2])))|((31\\.((0[13578])|(1[02])))|((29|30)\\.((0?[1,3-9])|(1[0-2])))))\\.((20[0-9][0-9]))|(29\\.0?2\\.20(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input: "/^((0?[1-9])|((1|2)[0-9])|30|31)$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0[13578])|([13578])|(1[02]))[\\/](([1-9])|([0-2][0-9])|(3[01])))|(((0[469])|([469])|(11))[\\/](([1-9])|([0-2][0-9])|(30)))|((2|02)[\\/](([1-9])|([0-2][0-9]))))[\\/]\\d{4}$|^\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(\\d{1,2})\\W+(\\d{1,2})\\W*(\\d{2,4})?|(\\d{4})\\W(\\d{1,2})\\W(\\d{1,2})|([a-zA-Z]+)\\W*(\\d{1,2})\\W+(\\d{2,4})|(\\d{4})\\W*([a-zA-Z]+)\\W*(\\d{1,2})|(\\d{1,2})\\W*([a-zA-Z]+)\\W*(\\d{2,4})|(\\d{1,2})\\W*([a-zA-Z]+)|([a-zA-Z]+)\\W*(\\d{1,2})|(\\d{2})(\\d{2})(\\d{2,4})?/",
    isPumpable: false
  },
  {
    input:
      "/^(.{0,}(([a-zA-Z][^a-zA-Z])|([^a-zA-Z][a-zA-Z])).{4,})|(.{1,}(([a-zA-Z][^a-zA-Z])|([^a-zA-Z][a-zA-Z])).{3,})|(.{2,}(([a-zA-Z][^a-zA-Z])|([^a-zA-Z][a-zA-Z])).{2,})|(.{3,}(([a-zA-Z][^a-zA-Z])|([^a-zA-Z][a-zA-Z])).{1,})|(.{4,}(([a-zA-Z][^a-zA-Z])|([^a-zA-Z][a-zA-Z])).{0,})$/",
    isPumpable: false
  },
  {
    input: "/^\\d[0-9]*[-\\/]\\d[0-9]*$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(A[KLRZ]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|P[AR]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY]))$/",
    isPumpable: false
  },
  {
    input:
      "/^(19[0-9]{2}|[2-9][0-9]{3})-((0(1|3|5|7|8)|10|12)-(0[1-9]|1[0-9]|2[0-9]|3[0-1])|(0(4|6|9)|11)-(0[1-9]|1[0-9]|2[0-9]|30)|(02)-(0[1-9]|1[0-9]|2[0-9]))\\x20(0[0-9]|1[0-9]|2[0-3])(:[0-5][0-9]){2}$/",
    isPumpable: false
  },
  {
    input: "/(^[a-zA-Z][a-zA-Z0-9_]*)|(^[_][a-zA-Z0-9_]+)/",
    isPumpable: false
  },
  {
    input: "/[+-](^0.*)/",
    isPumpable: false
  },
  {
    input:
      "/(((0*[1-9]|[12][0-9]|3[01])([-.\\/])(0*[13578]|10|12)([-.\\/])(\\d{4}))|((0*[1-9]|[12][0-9]|30)([-.\\/])(0*[469]|11)([-.\\/])(\\d{4}))|((0*[1-9]|1[0-9]|2[0-8])([-.\\/])(02|2)([-.\\/])(\\d{4}))|((29)(\\.|-|\\/)(02|2)([-.\\/])([02468][048]00))|((29)([-.\\/])(02|2)([-.\\/])([13579][26]00))|((29)([-.\\/])(02|2)([-.\\/])([0-9][0-9][0][48]))|((29)([-.\\/])(02|2)([-.\\/])([0-9][0-9][2468][048]))|((29)([-.\\/])(02|2)([-.\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input: "/([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})/",
    isPumpable: false
  },
  {
    input:
      "/<a\\s*(?:href=[\\'\"]([^\\'\"]+)[\\'\"])?\\s*(?:title=[\\'\"]([^\\'\"]+)[\\'\"])?.*?>((?:(?!</a>).)*)</a>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(75)}"
  },
  {
    input:
      "/^(http|https|ftp)\\:\\/\\/([a-zA-Z0-9\\.\\-]+(\\:[a-zA-Z0-9\\.&%\\$\\-]+)*@)?((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,4})(\\:[0-9]+)?(\\/[^\\/][a-zA-Z0-9\\.\\,\\?\\'\\\\/\\+&%\\$#\\=~_\\-@]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "http://a.aA",
    pumpable: "/!/0",
    suffix: "!"
  },
  {
    input:
      "/^(http|https|ftp)\\:\\/\\/([a-zA-Z0-9\\.\\-]+(\\:[a-zA-Z0-9\\.&%\\$\\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]+\\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(\\:[0-9]+)*(\\/($|[a-zA-Z0-9\\.\\,\\?\\'\\\\\\+&%\\$#\\=~_\\-]+))*$/",
    isPumpable: false
  },
  {
    input: "/<input[^>]*?type[\\/s]*=[\\/s]*(['|\"]?)text\\1[^>]*?value[/s]*=[/s]*(['|\"])(.*?)\\2[^>]*?>/",
    isPumpable: false
  },
  {
    input: "/<select(.|\\n)*?selected(.|\\n)*?>(.*?)<\\/option>(.|\\n)*?<\\/select>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<select",
    pumpable: "\\x0a",
    suffix: ""
  },
  {
    input: "/<textarea(.|\\n)*?>((.|\\n)*?)<\\/textarea>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<textarea",
    pumpable: "\\x0a",
    suffix: ""
  },
  {
    input: "/^(9,)*([1-9]\\d{2}-?)*[1-9]\\d{2}-?\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\s(SUN|MON|TUE|WED|THU|FRI|SAT)\\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\\s+(0?[1-9]|[1-2][0-9]|3[01])\\s+(2[0-3]|[0-1][0-9]):([0-5][0-9]):((60|[0-5][0-9]))\\s+(19[0-9]{2}|[2-9][0-9]{3}|[0-9]{2}))$/",
    isPumpable: false
  },
  {
    input: "/^100$|^100.00$|^\\d{0,2}(\\.\\d{1,2})? *%?$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9])|(0[1-9])|(1[0-2]))\\/((0[1-9])|([1-31]))\\/((\\d{2})|(\\d{4}))$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]*[1-9]+[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9]?\\d|1\\d\\d|2[0-4]\\d|25[0-5]).){3}([1-9]?\\d|1\\d\\d|2[0-4]\\d|25[0-5])$/",
    isPumpable: false
  },
  {
    input: "/\\(?(\\d{3})(?:\\)*|\\)\\s*-*|\\.*|\\s*|\\/*|)(\\d{3})(?:\\)*|-*|\\.*|\\s*|\\/*|)(\\d{4})(?:\\s?|,\\s?)/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^((\\d|\\d\\d|[0-1]\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|\\d\\d|[0-1]\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|\\d\\d|[0-1]\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|\\d\\d|[0-1]\\d\\d|2[0-4]\\d|25[0-5]))$/",
    isPumpable: false
  },
  {
    input:
      "/[a-zA-Z\\u0410-\\u042F\\u0430-\\u044F\\u0401\\u0451\\u0101\\u0100\\u010c\\u010d\\u0112\\u0113\\u011E\\u011F\\u012A\\u012B\\u0136\\u0137\\u013b\\u013C\\u0145\\u0146\\u0160\\u0161\\u016A\\u016B\\u017D\\u017E]$/",
    wasParseError: "{ParsingData.UnsupportedEscape(8, 117)}"
  },
  {
    input: "/^[0-9]{5}([\\s-]{1}[0-9]{4})?$/",
    isPumpable: false
  },
  {
    input:
      "/^http:\\/\\/([a-zA-Z0-9_\\-]+)([\\.][a-zA-Z0-9_\\-]+)+([\\/][a-zA-Z0-9\\~\\(\\)_\\-]*)+([\\.][a-zA-Z0-9\\(\\)_\\-]+)*$/",
    isPumpable: false
  },
  {
    input: "/^((\\d[-. ]?)?((\\(\\d{3}\\))|\\d{3}))?[-. ]?\\d{3}[-. ]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]\\w{0,30}$/",
    isPumpable: false
  },
  {
    input: "/^[ABCEGHJKLMNPRSTVXY][0-9][A-Z]\\s?[0-9][A-Z][0-9]$/",
    isPumpable: false
  },
  {
    input: "/^((0[0-9])|(1[0-2])|(2[1-9])|(3[0-2])|(6[1-9])|(7[0-2])|80)([0-9]{7})$/",
    isPumpable: false
  },
  {
    input: '/(\\[url=?"?)([^\\]"]*)("?\\])([^\\[]*)(\\[/url\\])/',
    isPumpable: false
  },
  {
    input: "/^[1-9][0-9]{0,2}$/",
    isPumpable: false
  },
  {
    input: "/(SELECT\\s(?:DISTINCT)?[A-Za-z0-9_\\*\\)\\(,\\s\\.'\\+\\|\\:=]+?)\\s(?:FROM\\s[\\w\\.]+)/",
    isPumpable: false
  },
  {
    input: "/^[-+]??(\\\\d++[.]\\\\d*?|[.]\\\\d+?|\\\\d+(?=[eE]))([eE][-+]??\\\\d++)?$/",
    wasParseError: "{ParsingData.UnsupportedPossessiveQuantifier(12)}"
  },
  {
    input:
      "/<\\*?font(?(?=[^>]+color.*>)(.*?color\\s*?[=|:]\\s*?)('+\\#*?[\\w\\s]*'+|\"+\\#*?[\\w\\s]*\"+|\\#*\\w*\\b).*?>|.*?>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(10, 40)}"
  },
  {
    input: "/^((\\+\\s?\\d{2}|\\(?00\\s?\\d{2}\\)?)\\s?\\d{2}\\s?\\d{3}\\s?\\d{4})/",
    isPumpable: false
  },
  {
    input:
      '/^(?:(?:[^@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff\\.]|\\x5c(?=[@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff]))(?:[^@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff\\.]|(?<=\\x5c)[@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff]|\\x5c(?=[@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff])|\\.(?=[^\\.])){1,62}(?:[^@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff\\.]|(?<=\\x5c)[@,"\\[\\]\\x5c\\x00-\\x20\\x7f-\\xff])|"(?:[^"]|(?<=\\x5c)"){1,62}")@(?:(?:[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\\.?)+\\.[a-z]{2,6}|\\[(?:[0-1]?\\d?\\d|2[0-4]\\d|25[0-5])(?:\\.(?:[0-1]?\\d?\\d|2[0-4]\\d|25[0-5])){3}\\])$/',
    wasParseError: "{ParsingData.NonAsciiInput(29, 255)}"
  },
  {
    input: "/^((\\+)?(\\d{2}[-])?(\\d{10}){1})?(\\d{11}){0,1}?$/",
    isPumpable: false
  },
  {
    input:
      "/(https?:\\/\\/)?((?:(\\w+-)*\\w+)\\.)+(?:com|org|net|edu|gov|biz|info|name|museum|[a-z]{2})(\\/?\\w?-?=?_?\\??&?)+[\\.]?[a-z0-9\\?=&_\\-%#]*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: '/(?=^.{8,30}$)(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+}{"":;\'?/>.<,]).*$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(http|ftp|https):\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,4}(\\/\\S*)?$/",
    isPumpable: false
  },
  {
    input: "/(?<=\\d{7}_).+((?=\\x5B\\d\\x5D)|.{3})/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[URL=[a-zA-Z0-9.:\\/_\\-]+\\][a-zA-Z0-9._\\/ ]+\\[\\/URL\\]/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/[B\\][a-zA-Z0-9._\\/ ]+\\[\\/B\\]/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^([0-9]|0[0-9]|1[0-9]|2[0-3]):([0-9]|[0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/\\/(?<=[^a-zA-Z0-9])((\\+351|00351|351)?)(2\\d{1}|(9(3|6|2|1)))\\d{7}(?=[^a-zA-Z0-9])\\//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^[0-9]{5}$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\!#\\$%&'\\*\\+\\/\\=?\\^`\\{\\|\\}~a-zA-Z0-9_-]+[\\.]?)+[\\!#\\$%&'\\*\\+\\/\\=?\\^`\\{\\|\\}~a-zA-Z0-9_-]+@{1}((([0-9A-Za-z_-]+)([\\.]{1}[0-9A-Za-z_-]+)*\\.{1}([A-Za-z]){1,6})|(([0-9]{1,3}[\\.]{1}){3}([0-9]{1,3}){1}))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "!",
    pumpable: "!!",
    suffix: ""
  },
  {
    input: "/(((\\[?(?<Database>[\\w]+)\\]?)?\\.)?(\\[?(?<Owner>[\\w]+)\\]?)?\\.)?\\[?(?<Object>[\\w]+)\\]?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input:
      "/((?<Owner>\\[?[\\w\\d]+\\]?)\\.{1})?(?<Column>\\[?[\\w\\d]+\\]?)(\\s*(([><=]{1,2})|(Not|In\\(|Between){1,2})\\s*)(?<Value>[\\w\\d\\']+)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/([^\\=&]+)(?<!param1|param2|param3)\\=([^\\=&]+)(&)?/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(9)}"
  },
  {
    input:
      "/^3(?:[47]\\d([ -]?)\\d{4}(?:\\1\\d{4}){2}|0[0-5]\\d{11}|[68]\\d{12})$|^4(?:\\d\\d\\d)?([ -]?)\\d{4}(?:\\2\\d{4}){2}$|^6011([ -]?)\\d{4}(?:\\3\\d{4}){2}$|^5[1-5]\\d\\d([ -]?)\\d{4}(?:\\4\\d{4}){2}$|^2014\\d{11}$|^2149\\d{11}$|^2131\\d{11}$|^1800\\d{11}$|^3\\d{15}$/",
    wasParseError: "{ParsingData.InvalidBackreference(92)}"
  },
  {
    input:
      "/^(((((0[1-9])|(1\\d)|(2[0-8]))\\/((0[1-9])|(1[0-2])))|((31\\/((0[13578])|(1[02])))|((29|30)\\/((0[1,3-9])|(1[0-2])))))\\/((20[0-9][0-9])|(19[0-9][0-9])))|((29\\/02\\/(19|20)(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input: "/^(0|(-?(((0|[1-9]\\d*)\\.\\d+)|([1-9]\\d*))))$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}(-\\d{4})?$/",
    isPumpable: false
  },
  {
    input:
      "/([0]{1}[6]{1}[-\\s]*([1-9]{1}[\\s]*){8})|([0]{1}[1-9]{1}[0-9]{1}[0-9]{1}[-\\s]*([1-9]{1}[\\s]*){6})|([0]{1}[1-9]{1}[0-9]{1}[-\\s]*([1-9]{1}[\\s]*){7})/",
    isPumpable: false
  },
  {
    input: "/\\d+,?\\d+\\$?/",
    isPumpable: false
  },
  {
    input: "/^(\\/w|\\/W|[^<>+?$%{}&])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "/W",
    suffix: "$"
  },
  {
    input: "/\\b([A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}(?<!BG|GB|NK|KN|TN|NT|ZZ))[0-9]{6}[A-DFM]{1}\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(44)}"
  },
  {
    input:
      "/^(((0[1-9]{1})|(1[0-2]{1}))\\/?(([0-2]{1}[1-9]{1})|(3[0-1]{1}))\\/?(([12]{1}[0-9]{1})?[0-9]{2}) ?(([01]{1}[0-9]{1})|(2[0-4]{1}))\\:?([0-5]{1}[0-9]{1}))$/",
    isPumpable: false
  },
  {
    input: "/((\\(\\d{3}\\) ?)|(\\d{3}[- \\.]))?\\d{3}[- \\.]\\d{4}(\\s(x\\d+)?){0,1}$/",
    isPumpable: false
  },
  {
    input: "/\\d{3}-\\d{6}/",
    isPumpable: false
  },
  {
    input:
      "/^((?:(?:(?:[a-zA-Z0-9][\\.\\-\\+_]?)*)[a-zA-Z0-9])+)\\@((?:(?:(?:[a-zA-Z0-9][\\.\\-_]?){0,62})[a-zA-Z0-9])+)\\.([a-zA-Z0-9]{2,6})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "0a",
    suffix: ""
  },
  {
    input: "/^((?:(?:(?:\\w[\\.\\-\\+]?)*)\\w)+)\\@((?:(?:(?:\\w[\\.\\-\\+]?){0,62})\\w)+)\\.(\\w{2,6})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "00",
    suffix: ""
  },
  {
    input: "/^(([a-zA-Z]{3})?([0-9]{4}))$/",
    isPumpable: false
  },
  {
    input: '/\\[link="(?<link>((.|\\n)*?))"\\](?<text>((.|\\n)*?))\\[\\/link\\]/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(10, 60)}"
  },
  {
    input:
      "/^(((((0[13578])|([13578])|(1[02]))[\\-\\/\\s]?((0[1-9])|([1-9])|([1-2][0-9])|(3[01])))|((([469])|(11))[\\-\\/\\s]?((0[1-9])|([1-9])|([1-2][0-9])|(30)))|((02|2)[\\-\\/\\s]?((0[1-9])|([1-9])|([1-2][0-9]))))[\\-\\/\\s]?\\d{4})(\\s(((0[1-9])|([1-9])|(1[0-2]))\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])\\s))([AM|PM|am|pm]{2,2})))?$/",
    isPumpable: false
  },
  {
    input: "/(\\w+([-+.']\\w+)*@(gmail.com))/",
    isPumpable: false
  },
  {
    input: "/^([0]?\\d|1\\d|2[0-3]):([0-5]\\d):([0-5]\\d)$/",
    isPumpable: false
  },
  {
    input:
      "/(?<dice>\\d*)(?<dsides>(?<separator>[\\d\\D])(?<sides>\\d+))(?<modifier>(?<sign>[\\+\\-])(?<addend>\\d))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^([0])([1])([1,2,3,4,6,7,8,9])([0-9][0-9][0-9][0-9][0-9][0-9][0-9])/",
    isPumpable: false
  },
  {
    input: "/^01[1,2,3,4,6,7,8,9]\\d{7,8}$/",
    isPumpable: false
  },
  {
    input: "/'(?<document>.*)'\\)(?<path>.*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?=\\d)(?:(?:31(?!.(?:0?[2469]|11))|(?:30|29)(?!.0?2)|29(?=.0?2.(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(?:\\x20|$))|(?:2[0-8]|1\\d|0?[1-9]))([-.\\/])(?:1[012]|0?[1-9])\\1(?:1[6-9]|[2-9]\\d)?\\d\\d)?(\\x20?((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^([A-Z|a-z]{2}-\\d{2}-[A-Z|a-z]{2}-\\d{1,4})?([A-Z|a-z]{3}-\\d{1,4})?$/",
    isPumpable: false
  },
  {
    input:
      "/<a[a-zA-Z0-9 =\"'.:;?]*(href=[\\\"\\'](http:\\/\\/|\\.\\/|\\/)?\\w+(\\.\\w+)*(\\/\\w+(\\.\\w+)?)*(\\/|\\?\\w*=\\w*(&\\w*=\\w*)*)?[\\\"\\'])*(>[a-zA-Z0-9 =\"'<>.:;?]*</a>)/",
    isPumpable: false
  },
  {
    input: "/<a [a-zA-Z0-9 =\"'.:;?]*href=*[a-zA-Z0-9 =\"'.:;>?]*[^>]*>([a-zA-Z0-9 =\"'.:;>?]*[^<]*<)\\s*/a\\s*>/",
    isPumpable: false
  },
  {
    input: "/<a.*?href=(.*?)(?((?:\\s.*?)>.*?<\\/a>)(?:(?:\\s.*?)>(.*?)<\\/a>)|(?:>(.*?)<\\/a>))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 40)}"
  },
  {
    input: "/^[0-9]*(\\.)?[0-9]+$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z|a-z]{2}\\s{1}\\d{2}\\s{1}[A-Z|a-z]{1,2}\\s{1}\\d{1,4})?([A-Z|a-z]{3}\\s{1}\\d{1,4})?$/",
    isPumpable: false
  },
  {
    input: '/\\A[^,"]*(?=,)|(?:[^",]*"[^"]*"[^",]*)+|[^",]*"[^"]*\\Z|(?<=,)[^,]*(?=,)|(?<=,)[^,]*\\Z|\\A[^,]*\\Z/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(8)}"
  },
  {
    input: "/^[1]$|^[3]$|^[4]$|^[6]$|^[1]0$/",
    isPumpable: false
  },
  {
    input: "/^[A]$|^[C]$|^[D]$|^[F]$|^[H]$|^[K]$|^[L]$|^[M]$|^[O]$|^[P]$/",
    isPumpable: false
  },
  {
    input: "/^(?i:([a-z])\\1?(?!\\1)){2,}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(15)}"
  },
  {
    input: "/(?=^.{8,}$)(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\\s)[0-9a-zA-Z!@#$%^&*()]*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^(?:(?'1'[0-9a-fA-F]{2})(?:\\:)(?'2'[0-9a-fA-F]{2})(?:\\:)(?'3'[0-9a-fA-F]{2})(?:\\:)(?'4'[0-9a-fA-F]{2})(?:\\:)(?'5'[0-9a-fA-F]{2})(?:\\:)(?'6'[0-9a-fA-F]{2}))$|^(?:(?'1'[0-9a-fA-F]{2})(?:\\-)(?'2'[0-9a-fA-F]{2})(?:\\-)(?'3'[0-9a-fA-F]{2})(?:\\-)(?'4'[0-9a-fA-F]{2})(?:\\-)(?'5'[0-9a-fA-F]{2})(?:\\-)(?'6'[0-9a-fA-F]{2}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 39)}"
  },
  {
    input:
      "/(?:(?'1'[0-9a-fA-F]{2})(?:\\:)(?'2'[0-9a-fA-F]{2})(?:\\:)(?'3'[0-9a-fA-F]{2})(?:\\:)(?'4'[0-9a-fA-F]{2})(?:\\:)(?'5'[0-9a-fA-F]{2})(?:\\:)(?'6'[0-9a-fA-F]{2}))|(?:(?'1'[0-9a-fA-F]{2})(?:\\-)(?'2'[0-9a-fA-F]{2})(?:\\-)(?'3'[0-9a-fA-F]{2})(?:\\-)(?'4'[0-9a-fA-F]{2})(?:\\-)(?'5'[0-9a-fA-F]{2})(?:\\-)(?'6'[0-9a-fA-F]{2}))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 39)}"
  },
  {
    input: "/^[0-9,+,(), ,]{1,}(,[0-9]+){0,}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z][a-zA-Z0-9_]+$/",
    isPumpable: false
  },
  {
    input:
      "/^(http(s?)\\:\\/\\/)*[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\'\\/\\\\\\+&%\\$#_]*)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "i",
    pumpable: "00",
    suffix: "!"
  },
  {
    input:
      "/^(([A-Za-z]+[^0-9]*)([0-9]+[^\\W]*)([\\W]+[\\W0-9A-Za-z]*))|(([A-Za-z]+[^\\W]*)([\\W]+[^0-9]*)([0-9]+[\\W0-9A-Za-z]*))|(([\\W]+[^A-Za-z]*)([A-Za-z]+[^0-9]*)([0-9]+[\\W0-9A-Za-z]*))|(([\\W]+[^0-9]*)([0-9]+[^A-Za-z]*)([A-Za-z]+[\\W0-9A-Za-z]*))|(([0-9]+[^A-Za-z]*)([A-Za-z]+[^\\W]*)([\\W]+[\\W0-9A-Za-z]*))|(([0-9]+[^\\W]*)([\\W]+[^A-Za-z]*)([A-Za-z]+[\\W0-9A-Za-z]*))$/",
    isPumpable: false
  },
  {
    input:
      "/<img[\\s]+[^>]*?((alt*?[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?)|(src*?[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?))((src*?[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?>)|(alt*?[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?>)|>)/",
    isPumpable: false
  },
  {
    input: "/<title>+(.*?)<\\/title>/",
    isPumpable: false
  },
  {
    input:
      "/<meta[\\s]+[^>]*?name[\\s]?=[\\s\\\"\\']+(.*?)[\\s\\\"\\']+content[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?>/",
    isPumpable: false
  },
  {
    input:
      "/^(([0]?[1-9]|1[0-2])\\/([0-2]?[0-9]|3[0-1])\\/[1-2]\\d{3})? ?((([0-1]?\\d)|(2[0-3])):[0-5]\\d)?(:[0-5]\\d)? ?(AM|am|PM|pm)?$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}$|^[1-4]{1}[0-9]{1}$|^50$/",
    isPumpable: false
  },
  {
    input: "/((\\0[0-9])|(\\1[0-9])|(\\2[0-3])):([0-5][0-9])/",
    wasParseError: "{ParsingData.InvalidBackreference(12)}"
  },
  {
    input:
      "/\\[(?<GroupName>.*)\\](?<GroupContent>[^\\[]+)       --------        [\\s]*(?<Key>.+)[\\s]*=[\\s]*(?<Value>[^\\r]+)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input:
      "/^([a-z-[dfioquwz]]|[A-Z-[DFIOQUWZ]])\\d([a-z-[dfioqu]]|[A-Z-[DFIOQU]])(\\s)?\\d([a-z-[dfioqu]]|[A-Z-[DFIOQU]])\\d$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: '/^\\\\([^\\\\]+\\\\)*[^\\/:*?"<>|]?$/',
    isPumpable: false
  },
  {
    input:
      "/^[_a-z0-9-]+(\\.[_a-z0-9-]+)*@[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*(\\.[a-z0-9]+([a-z0-9-]*[a-z0-9]+)*)*\\.([a-z]{2}|xn\\-{2}[a-z0-9]{4,18}|arpa|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a.a@0",
    pumpable: ".ya0",
    suffix: ""
  },
  {
    input: "/^([0-9a-zA-Z]+[-._+&])*[0-9a-zA-Z_-]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input: "/1?[ \\.\\-\\+]?[(]?([0-9]{3})?[)]?[ \\.\\-\\+]?[0-9]{3}[ \\.\\-\\+]?[0-9]{4}/",
    isPumpable: false
  },
  {
    input: "/\\b[P|p]*(OST|ost)*\\.*\\s*[O|o|0]*(ffice|FFICE)*\\.*\\s*[B|b][O|o|0][X|x]\\b/",
    isPumpable: false
  },
  {
    input:
      "/^(900[0-9][0-9]|902[0-9][0-9]|9030[1-5]|9040[1-5]|9050[1-6]|9060[1-6]|90608|90631|90638|90639|90640|90650|90660|90670|90680|9070[1-4]|90706|90710|90712|90713|90715|90716|90717|90723|9073[1-3]|9074[4-6]|90747|90755|9080[2-8]|90810|9081[3-5]|90822|9083[1-2]|90840|90846|910[0-4][0-9]|91101|9110[3-8]|9112[5-6]|9120[1-8]|91214|913[0-6][0-9]|91372|91381|91384|9140[1-3|5-6]|91411|91423|91436|9150[1-2|4|6]|91510|91523|9160[1-2|4-8]|91702|91706|91711|9172[2-4]|9173[1-3]|9174[0-1|4-6|8]|9175[0|4-6]|9176[5-8]|9177[0|3|5-6]|9178[0-1|3]|91789|92621|93510|93523|9353[2|4-6]|93543|93544|9355[0-3]|93563|93591)(-[0-9]{4})?$/",
    isPumpable: false
  },
  {
    input: "/(\\+91(-)?|91(-)?|0(-)?)?(9)[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/([0-9]{6}|[0-9]{3}\\s[0-9]{3})/",
    isPumpable: false
  },
  {
    input: "/^(0)44[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}2[\\s]{0,1}[1-9]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^[1-9][0-9]{0,6}(|.[0-9]{1,2}|,[0-9]{1,2})?/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[:*:]/",
    isPumpable: false
  },
  {
    input:
      "/((?!(This|It|He|She|[MTWFS][a-z]+day|[JF][a-z]+ary|March|April|May|June|July|August|[SOND][a-z]+ber))(?:[A-Z]+\\.\\s?)*(?:(?:[a-zA-Z]+-?)?[A-Z][a-zA-Z]+)(?:(\\b\\s?((?:[a-zA-Z]+-?)?[A-Z][a-zA-Z]+|[A-Z]+\\.|on|of|the|von|der|van|de|bin|and))*(?:\\s*(?:[a-zA-Z]+-?)?[A-Z][a-zA-Z]+))?)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/(([a-zA-Z0-9\\-]*\\.{1,}){1,}[a-zA-Z0-9]*)/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^1000([.][0]{1,3})?$|^\\d{1,3}$|^\\d{1,3}([.]\\d{1,3})$|^([.]\\d{1,3})$/",
    isPumpable: false
  },
  {
    input: "/^(\\-)?1000([.][0]{1,3})?$|^(\\-)?\\d{1,3}$|^(\\-)?\\d{1,3}([.]\\d{1,3})$|^(\\-)?([.]\\d{1,3})$/",
    isPumpable: false
  },
  {
    input:
      "/^\\$?\\-?([1-9]{1}[0-9]{0,2}(\\,\\d{3})*(\\.\\d{0,2})?|[1-9]{1}\\d{0,}(\\.\\d{0,2})?|0(\\.\\d{0,2})?|(\\.\\d{1,2}))$|^\\-?\\$?([1-9]{1}\\d{0,2}(\\,\\d{3})*(\\.\\d{0,2})?|[1-9]{1}\\d{0,}(\\.\\d{0,2})?|0(\\.\\d{0,2})?|(\\.\\d{1,2}))$|^\\(\\$?([1-9]{1}\\d{0,2}(\\,\\d{3})*(\\.\\d{0,2})?|[1-9]{1}\\d{0,}(\\.\\d{0,2})?|0(\\.\\d{0,2})?|(\\.\\d{1,2}))\\)$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-z]{1,6}[ ']){0,3}([ÉÈÊËÜÛÎÔÄÏÖÄÅÇA-Z]{1}[éèëêüûçîôâïöäåa-z]{2,}[- ']){0,3}[A-Z]{1}[éèëêüûçîôâïöäåa-z]{2,}$/",
    wasParseError: "{ParsingData.NonAsciiInput(24, 195)}"
  },
  {
    input: "/^[1]?[-\\.\\s]?(\\(\\d{3}\\)|\\d{3}){1}[-\\.\\s]?\\d{3}[-\\.\\s]?\\d{4}(\\s+|\\s*[-\\.x]{1}\\d{1,6})?$/",
    isPumpable: false
  },
  {
    input: "/^(([$])?((([0-9]{1,3},)+[0-9]{3})|[0-9]+)(\\.[0-9]{2})?)$/",
    isPumpable: false
  },
  {
    input: "/^*[]!#/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(?=^[!@#$%\\^&*()_\\-+=\\[{\\]};:<>|\\.\\/?a-zA-Z\\d]{7,}$)(?=([!@#$%\\^&*()_\\-+=\\[{\\]};:<>|\\.\\/?a-zA-Z\\d]*\\W+){1,})[!@#$%\\^&*()_\\-+=\\[{\\]};:<>|\\.\\/?a-zA-Z\\d]*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/([0]{1}[6]{1}[-\\s]*[1-9]{1}[\\s]*([0-9]{1}[\\s]*){7})|([0]{1}[1-9]{1}[0-9]{1}[0-9]{1}[-\\s]*[1-9]{1}[\\s]*([0-9]{1}[\\s]*){5})|([0]{1}[1-9]{1}[0-9]{1}[-\\s]*[1-9]{1}[\\s]*([0-9]{1}[\\s]*){6})/",
    isPumpable: false
  },
  {
    input: "/^[0-9]*[1-9]+$|^[1-9]+[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/\\/rapidshare\\.com\\/files\\/(\\d+)\\/([^\\'^\\\"^\\s^>^<^\\\\^\\/]+)//",
    isPumpable: false
  },
  {
    input: "/^\\+[0-9]{1,3}\\.[0-9]+\\.[0-9]+$/",
    isPumpable: false
  },
  {
    input: "/\".*?\"|\".*$|'.*?'|'.*$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-z0-9+\\-.]+):([\\/]{0,2}([a-z0-9\\-._~%!\\$&'\\(\\)\\*+,;=:]+@)?([\\[\\]a-z0-9\\-._~%!\\$&'\\(\\)\\*+,;=:]+(:[0-9]+)?))([a-z0-9\\-._~%!\\$&'\\(\\)\\*+,;=:@\\/]*)(\\?[\\?\\/a-z0-9\\-._~%!\\$&'\\(\\)\\*+,;=:@]+)?(\\#[a-z0-9\\-._~%!\\$&'\\(\\)\\*+,;=:@\\/\\?]+)?/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]([a-zA-Z0-9])*([\\.][a-zA-Z]([a-zA-Z0-9])*)*$/",
    isPumpable: false
  },
  {
    input: "/(^\\-?[0-9]*\\.?[0-9]+$)/",
    isPumpable: false
  },
  {
    input: "/[^A-Za-z0-9 ]/",
    isPumpable: false
  },
  {
    input: "/(?=([\\W]*[\\w][\\W]*\\b))\\s(?=\\d\\.|\\d\\b)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^([A-Z|a-z|&]{3}\\d{2}((0[1-9]|1[012])(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])(29|30)|(0[13578]|1[02])31)|([02468][048]|[13579][26])0229)(\\w{2})([A|a|0-9]{1})$|^([A-Z|a-z]{4}\\d{2}((0[1-9]|1[012])(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])(29|30)|(0[13578]|1[02])31)|([02468][048]|[13579][26])0229)((\\w{2})([A|a|0-9]{1})){0,3}$/",
    isPumpable: false
  },
  {
    input: "/^([A-ZÑ\\x26]{3,4}([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|3[0-1])[A-Z|\\d]{3})$/",
    wasParseError: "{ParsingData.NonAsciiInput(6, 195)}"
  },
  {
    input: "/([(]?\\d{3}[)]?(-| |.)?\\d{3}(-| |.)?\\d{4})/",
    isPumpable: false
  },
  {
    input: "/^[89]\\d{7}$/",
    isPumpable: false
  },
  {
    input:
      '/^((\\\\\\\\[a-zA-Z0-9-]+\\\\[a-zA-Z0-9`~!@#$%^&(){}\'._-]+([ ]+[a-zA-Z0-9`~!@#$%^&(){}\'._-]+)*)|([a-zA-Z]:))(\\\\[^ \\\\/:*?""<>|]+([ ]+[^ \\\\/:*?""<>|]+)*)*\\\\?$/',
    isPumpable: false
  },
  {
    input: '/^[^ \\\\/:*?""<>|]+([ ]+[^ \\\\/:*?""<>|]+)*$/',
    isPumpable: false
  },
  {
    input: "/^[\\w\\s]+$/",
    isPumpable: false
  },
  {
    input: "/^[[A-Z]\\s]$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/^(?:(?:0?[13578]|1[02])|(?:0?[469]|11)(?!\\/31)|(?:0?2)(?:(?!\\/3[01]|\\/29\\/(?:(?:0[^48]|[13579][^26]|[2468][^048])00|(?:\\d{2}(?:0[^48]|[13579][^26]|[2468][^048]))))))\\/(?:0?[1-9]|[12][0-9]|3[01])\\/\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(38)}"
  },
  {
    input: "/^(\\d{5}-\\d{4}|\\d{5})$/",
    isPumpable: false
  },
  {
    input: "/^(([0-9]{2,4})([-\\s\\/]{0,1})([0-9]{4,8}))?$/",
    isPumpable: false
  },
  {
    input: "/^3[234689][0-9]$/",
    isPumpable: false
  },
  {
    input:
      "/^[0-9]{4}-(((0[13578]|(10|12))-(0[1-9]|[1-2][0-9]|3[0-1]))|(02-(0[1-9]|[1-2][0-9]))|((0[469]|11)-(0[1-9]|[1-2][0-9]|30)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((h|H)(t|T))(t|T)(p|P)((s|S)?)\\:\\/\\/)?((www|WWW)+\\.)+(([0-9]{1,3}){3}[0-9]{1,3}\\.|([\\w!~*'()-]+\\.)*([\\w^-][\\w-]{0,61})?[\\w]\\.[a-z]{2,6})(:[0-9]{1,4})?((\\/*)|(\\/+[\\w!~*'().;?:@&=+$,%#-]+)+\\/*)$/",
    isPumpable: false
  },
  {
    input: "/(?!^[0-9 ]*$)(?!^[a-zA-Z ]*$)^([a-zA-Z0-9 ]{6,15})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^((http|HTTP|https|HTTPS|ftp|FTP?)\\:\\/\\/)?((www|WWW)+\\.)+(([0-9]{1,3}){3}[0-9]{1,3}\\.|([\\w!~*'()-]+\\.)*([\\w^-][\\w-]{0,61})?[\\w]\\.[a-z]{2,6})(:[0-9]{1,4})?((\\/*)|(\\/+[\\w!~*'().;?:@&=+$,%#-]+)+\\/*)$/",
    isPumpable: false
  },
  {
    input: "/^1[34][0-9][0-9]\\/((1[0-2])|([1-9]))\\/(([12][0-9])|(3[01])|[1-9])$/",
    isPumpable: false
  },
  {
    input: "/[^!~\\/><\\|\\/#%():;{}`_-]/",
    isPumpable: false
  },
  {
    input: "/(mailto\\:|(news|(ht|f)tp(s?))\\:\\/\\/)(([^[:space:]]+)|([^[:space:]]+)( #([^#]+)#)?)/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/^\\s*(?<Last>[-A-Za-z ]+)[.](?<First>[-A-Za-z ]+)(?:[.](?<Middle>[-A-Za-z ]+))?(?:[.](?<Ordinal>[IVX]+))?(?:[.](?<Number>\\d{10}))\\s*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/^([1-9]{0,1})([0-9]{1})((\\.[0-9]{0,1})([0-9]{1})|(\\,[0-9]{0,1})([0-9]{1}))?$/",
    isPumpable: false
  },
  {
    input: "/^([012346789][0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/jquery\\-(\\d|\\.)*\\.min\\.js/",
    isPumpable: false
  },
  {
    input: "/(\\*\\*)(.+)(\\*\\*)/",
    isPumpable: false
  },
  {
    input: "/(\\/\\/)(.+)(\\/\\/)/",
    isPumpable: false
  },
  {
    input: "/(\\_\\_)(.+)(\\_\\_)/",
    isPumpable: false
  },
  {
    input: "/([A-Z]:\\\\[^/:\\*\\?<>\\|]+\\.\\w{2,6})|(\\\\{2}[^/:\\*\\?<>\\|]+\\.\\w{2,6})/",
    isPumpable: false
  },
  {
    input: "/^\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*/",
    isPumpable: false
  },
  {
    input: "/^([987]{1})(\\d{1})(\\d{8})/",
    isPumpable: false
  },
  {
    input: '/^<a\\s+href\\s*=\\s*"http:\\/\\/([^"]*)"([^>]*)>(.*?(?=<\\/a>))<\\/a>$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(47)}"
  },
  {
    input: "/[1-2][0|9][0-9]{2}[0-1][0-9][0-3][0-9][-][0-9]{4}/",
    isPumpable: false
  },
  {
    input:
      "/<a\\s+(?:(?:\\w+\\s*=\\s*)(?:\\w+|\"[^\"]*\"|'[^']*'))*?\\s*href\\s*=\\s*(?<url>\\w+|\"[^\"]*\"|'[^']*')(?:(?:\\s+\\w+\\s*=\\s*)(?:\\w+|\"[^\"]*\"|'[^']*'))*?>[^<]+</a>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(64, 60)}"
  },
  {
    input:
      "/<a\\s+(?:(?:\\w+\\s*=\\s*)(?:\\w+|\"[^\"]*\"|'[^']*'))*?\\s*href\\s*=\\s*(?<url>\\w+|\"[^\"]*\"|'[^']*')(?:(?:\\s+\\w+\\s*=\\s*)(?:\\w+|\"[^\"]*\"|'[^']*'))*?>.+?</a>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(64, 60)}"
  },
  {
    input: "/^([a-zA-Z][a-zA-Z0-9]{1,100})$/",
    isPumpable: false
  },
  {
    input: "/^(?:(?:((?![0-9_])[a-zA-Z0-9_]+)\\.?)+)(?<!\\.)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(8)}"
  },
  {
    input: "/^[2-9]{2}[0-9]{8}$/",
    isPumpable: false
  },
  {
    input: "/^[^ ,0]*$/",
    isPumpable: false
  },
  {
    input: "/^[^0-9]*(?:(\\d)[^0-9]*){10}$/",
    isPumpable: false
  },
  {
    input: "/^((4(\\d{12}|\\d{15}))|(5\\d{15})|(6011\\d{12})|(3(4|7)\\d{13}))$/",
    isPumpable: false
  },
  {
    input: "/^(?!000)\\d{3,4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^100(\\.0{0,2}?)?$|^\\d{0,2}(\\.\\d{0,2})?$/",
    isPumpable: false
  },
  {
    input: "/^([\\u20AC]?[1-9]\\d*\\.\\d{3}(?:,\\d{2})?|[\\u20AC]?[1-9]\\d*(?:,\\d{2})?|[\\u20AC]?[1-9]\\d*)$/",
    wasParseError: "{ParsingData.UnsupportedEscape(4, 117)}"
  },
  {
    input: "/^([0-5]?\\d?\\d?\\d?\\d|6[0-4]\\d\\d\\d|65[0-4]\\d\\d|655[0-2]\\d|6553[0-5])$/",
    isPumpable: false
  },
  {
    input: "/^(?<national>\\+?(?:86)?)(?<separator>\\s?-?)(?<phone>(?<vender>13[0-4])(?<area>\\d{4})(?<id>\\d{4}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/\\/\\*.*(\\R.+)+\\*\\//",
    wasParseError: "{ParsingData.UnsupportedEscape(6, 82)}"
  },
  {
    input: "/\\/\\*.*((\\r\\n).+)+\\*\\//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "*\\x0d\\x0a!",
    pumpable: "\\x0d\\x0a+\\x0d\\x0a+",
    suffix: ""
  },
  {
    input: "/^([a-zA-Z1-9]*)\\.(((a|A)(s|S)(p|P)(x|X))|((h|H)(T|t)(m|M)(l|L))|((h|H)(t|T)(M|m))|((a|A)(s|S)(p|P)))/",
    isPumpable: false
  },
  {
    input:
      "/(((ht|f)tp(s?):\\/\\/)(www\\.[^ \\[\\]\\(\\)\\n\\r\\t]+)|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})\\/)([^ \\[\\]\\(\\),;\"\\'<>\\n\\r\\t]+)([^\\. \\[\\]\\(\\),;\"\\'<>\\n\\r\\t])|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})/",
    isPumpable: false
  },
  {
    input: "/^(((0|((\\+)?91(\\-)?))|((\\((\\+)?91\\)(\\-)?)))?[7-9]\\d{9})?$/",
    isPumpable: false
  },
  {
    input: "/^\\$?(([1-9],)?([0-9]{3},){0,3}[0-9]{3}|[0-9]{0,16})(\\.[0-9]{0,3})?$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[\\d])(?=.*[A-Z])(?=.*[a-z])[\\w\\d!@#$%_]{6,40}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/s\\/\\b(\\w+)\\b\\/ucfirst($1)\\/ge/",
    isPumpable: false
  },
  {
    input:
      "/\\s*([a-z\\. ]+)\\s*\\n\\s*([a-z0-9\\. #]+)\\s*\\n\\s*([a-z \\.]+)\\s*,\\s*([a-z \\.]+)\\s*\\n?(?:\\s*(\\d{1,15}(?:-\\d{1,4})?)\\s*\\n)?(?:\\s*(\\+?(?:1\\s*[-\\/\\.]?)?(?:\\((?:\\d{3})\\)|(?:\\d{3}))\\s*[-\\/\\.]?\\s*(?:\\d{3})\\s*[-\\/\\.]?\\s*(?:\\d{4})(?:(?:[ \\t]*[xX]|[eE][xX][tT])\\.?[ \\t]*(?:\\d+))*))?/",
    isPumpable: false
  },
  {
    input:
      "/^((?:[A-Z](?:('|(?:[a-z]{1,3}))[A-Z])?[a-z]+)|(?:[A-Z]\\.))(?:([ -])((?:[A-Z](?:('|(?:[a-z]{1,3}))[A-Z])?[a-z]+)|(?:[A-Z]\\.)))?$/",
    isPumpable: false
  },
  {
    input: "/(REM [\\d\\D]*?[\\r\\n])|(?<SL>\\'[\\d\\D]*?[\\r\\n])/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(23, 60)}"
  },
  {
    input:
      "/(\\/\\*[\\d\\D]*?\\*\\/)|(\\/\\*(\\s*|.*?)*\\*\\/)|(\\/\\/.*)|(\\/\\\\*[\\\\d\\\\D]*?\\\\*/)|([\\r\\n ]*//[^\\r\\n]*)+/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "/*",
    pumpable: "+",
    suffix: ""
  },
  {
    input: "/^([0-1]?[0-9]{1}|2[0-3]{1}):([0-5]{1}[0-9]{1})$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}?(\\d{7}))$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0[13578]|10|12)([-.\\/])(0[1-9]|[12][0-9]|3[01])([-.\\/])(\\d{4}))|((0[469]|1­1)([-.\\/])([0][1-9]|[12][0-9]|30)([-.\\/])(\\d{4}))|((2)([-.\\/])(0[1-9]|1[0-9]|2­[0-8])([-.\\/])(\\d{4}))|((2)(\\.|-|\\/)(29)([-.\\/])([02468][048]00))|((2)([-.\\/])­(29)([-.\\/])([13579][26]00))|((2)([-.\\/])(29)([-.\\/])([0-9][0-9][0][48]))|((2)­([-.\\/])(29)([-.\\/])([0-9][0-9][2468][048]))|((2)([-.\\/])(29)([-.\\/])([0-9][0-9­][13579][26]))))$/",
    wasParseError: "{ParsingData.NonAsciiInput(77, 194)}"
  },
  {
    input: "/\\d+(\\/\\d+)?/",
    isPumpable: false
  },
  {
    input: "/<[^>]+>/",
    isPumpable: false
  },
  {
    input:
      "/^((((0?[13578]|1[02])\\/([0-2]?[1-9]|20|3[0-1]))|((0?[469]|11)\\/([0-2]?[1-9]|20|30))|(0?2\\/([0-1]?[1-9]|2[0-8])))\\/((19|20)?\\d{2}))|(0?2\\/29\\/((19|20)?(04|08|12|16|20|24|28|32|36|40|44|48|52|56|60|64|68|72|76|80|84|88|92|96)|2000))$/",
    isPumpable: false
  },
  {
    input:
      "/^((([a-z0-9])+([\\w.-]{1})?)+([^\\W_]{1}))+@((([a-z0-9])+([\\w-]{1})?)+([^\\W_]{1}))+\\.[a-z]{2,3}(\\.[a-z]{2,4})?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a00",
    suffix: ""
  },
  {
    input: "/(\\/^[A-Z][a-z]*(([\\'\\,\\.\\-]?[A-Z])?[a-z]*)((\\s)?((Jr.(\\.))|I|II|III]))?$\\/,/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/((A[FGIKLMNPRSUZ]S?X?|DAL?L?A?E?S?|DE|DE[LNRST]L?A?E?H?I?O?S?|DI[AE]?|DOS?|DU|EIT?N?E?|ELS?|EN|ETT?|HAI?|HE[NT]|HIN?A?I?N?R?|HOI|IL|IM|ISA|KA|KE|LAS|LES?|LH?IS?|LOS?|LO?U|MA?C|N[AIY]|O[IP]|SI|T[AEO]N?R?|U[MN][AEOS]?|VAN|VE[LR]|VO[MN]|Y[ENR]|ZU[MR]?) )?((LAS?|LOS?|DEN?R?|ZU) )?[A-Z0\\/'\\.-]+( |$)(SR|JR|II+V?|VI+|[1-9][STRDH]+)?/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[a-z].*[a-z])(?=.*[A-Z].*[A-Z])(?=.*\\d.*\\d)(?=.*\\W.*\\W)[a-zA-Z0-9\\S]{9,}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$/",
    isPumpable: false
  },
  {
    input: "/^(LV-)[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/(?<=select).*(?]from)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(15, 93)}"
  },
  {
    input: "/<table>(<tr>((<td>([A-Za-z0-9])*<\\/td>)+)<\\/tr>)*<\\/table>/",
    isPumpable: false
  },
  {
    input:
      "/^(958([0-9])+([0-9])+([0-9])+([0-9])+([0-9])+([0-9])+)|(958-([0-9])+([0-9])+([0-9])+([0-9])+([0-9])+([0-9])+)$/",
    isPumpable: false
  },
  {
    input:
      "/(\\s)*(int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*(\\s)*(\\()(\\s)*((int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*((\\s)*[,](\\s)*(int|void|float|char|double|string)((\\s)|(\\*))*(\\&?)(\\s)+([a-z])([a-z0-9])*)*)?(\\s)*(\\))(\\s)*;/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "int & a (int a",
    pumpable: " ,int\\x09\\x09a",
    suffix: ""
  },
  {
    input: "/^(?:(?:1\\d{0,2}|[3-9]\\d?|2(?:[0-5]{1,2}|\\d)?|0)\\.){3}(?:1\\d{0,2}|[3-9]\\d?|2(?:[0-5]{1,2}|\\d)?|0)$/",
    isPumpable: false
  },
  {
    input: "/(private|public|protected)\\s\\w(.)*\\((.)*\\)[^;]/",
    isPumpable: false
  },
  {
    input: "/^(([0-9])|([0-1][0-9])|([2][0-3])):?([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]{1}[0-9]{3}[,]?)*([1-9]{1}[0-9]{3})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z].*|[1-9].*|[:.\\/].*)\\.(((a|A)(s|S)(p|P)(x|X)))$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]{2}[9]{3}|[A-Z]{3}[9]{2}|[A-Z]{4}[9]{1}|[A-Z]{5})[0-9]{6}([A-Z]{1}[9]{1}|[A-Z]{2})[A-Z0-9]{3}[0-9]{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^[0][5][0]-\\d{7}|[0][5][2]-\\d{7}|[0][5][4]-\\d{7}|[0][5][7]-\\d{7}|[0][7][7]-\\d{7}|[0][2]-\\d{7}|[0][3]-\\d{7}|[0][4]-\\d{7}|[0][8]-\\d{7}|[0][9]-\\d{7}|[0][5][0]\\d{7}|[0][5][2]\\d{7}|[0][5][4]\\d{7}|[0][5][7]\\d{7}|[0][7][7]\\d{7}|[0][2]\\d{7}|[0][3]\\d{7}|[0][4]\\d{7}|[0][8]\\d{7}|[0][9]\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/(^\\d{5}-\\d{3}|^\\d{2}.\\d{3}-\\d{3}|\\d{8})/",
    isPumpable: false
  },
  {
    input:
      "/^(ac|AC|al|AL|am|AM|ap|AP|ba|BA|ce|CE|df|DF|es|ES|go|GO|ma|MA|mg|MG|ms|MS|mt|MT|pa|PA|pb|PB|pe|PE|pi|PI|pr|PR|rj|RJ|rn|RN|ro|RO|rr|RR|rs|RS|sc|SC|se|SE|sp|SP|to|TO)$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\040]+$/",
    isPumpable: false
  },
  {
    input: "/([\\(]?(?<AreaCode>[0-9]{3})[\\)]?)?[ \\.\\-]?(?<Exchange>[0-9]{3})[ \\.\\-](?<Number>[0-9]{4})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input:
      "/\\/class\\s+([a-z0-9_]+)(?:\\s+extends\\s+[a-z0-9_]+)?(?:\\s+implements\\s+(?:[a-z0-9_]+\\s*,*\\s*)+)?\\s*\\{\\/Usi/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "class a extends a implements 0",
    pumpable: "0\\x09",
    suffix: ""
  },
  {
    input: "/(^[0-9]*[1-9]+[0-9]*\\.[0-9]*$)|(^[0-9]*\\.[0-9]*[1-9]+[0-9]*$)|(^[0-9]*[1-9]+[0-9]*$)/",
    isPumpable: false
  },
  {
    input: '/(".+"\\s)?<?[a-z\\._0-9]+[^\\._]@([a-z0-9]+\\.)+[a-z0-9]{2,6}>?;?/',
    isPumpable: false
  },
  {
    input: "/[\\+]?[\\s]?(\\d(\\-|\\s)?)?(\\(\\d{3}\\)\\s?|\\d{3}\\-?)\\d{3}(-|\\s-\\s)?\\d{4}(\\s(ex|ext)\\s?\\d+)?/",
    isPumpable: false
  },
  {
    input: "/([^\\w]+)|([^A-Za-z])|(\\b[^aeiouy]+\\b)|(\\b(\\w{2})\\b)/",
    isPumpable: false
  },
  {
    input: "/^\\+(?:[0-9] ?){6,14}[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$/",
    isPumpable: false
  },
  {
    input: "/\\/\\*[^\\/]+\\//",
    isPumpable: false
  },
  {
    input: "/(a|A)/",
    isPumpable: false
  },
  {
    input: "/^(\\w+([_.]{1}\\w+)*@\\w+([_.]{1}\\w+)*\\.[A-Za-z]{2,3}[;]?)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "0__@0.Aa__.AA",
    suffix: "!"
  },
  {
    input: "/(((s*)(ftp)(s*)|(http)(s*)|mailto|news|file|webcal):(\\S*))|((www.)(\\S*))/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{10}GBR[0-9]{7}[U,M,F]{1}[0-9]{9}$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}[9]{3}|[A-Z]{3}[9]{2}|[A-Z]{4}[9]{1}|[A-Z]{5})[0-9]{6}([A-Z]{1}[9]{1}|[A-Z]{2})[A-Z0,9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z0-9<]{9}[0-9]{1}[A-Z]{3}[0-9]{7}[A-Z]{1}[0-9]{7}[A-Z0-9<]{14}[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/(((0[123456789]|10|11|12)(([1][9][0-9][0-9])|([2][0-9][0-9][0-9]))))/",
    isPumpable: false
  },
  {
    input: "/(?!^0*\\.0*$)^\\d{1,10}(\\.\\d{1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      '/^((?:(?:[a-zA-Z]:)|\\\\)\\\\)?((?:\\.\\.?\\\\)|(?:[^\\0-\\31<>:"/\\\\|?*]+(?<![ .])\\\\))*([^\\0-\\31<>:"/\\\\|?*]+(?<![ .]))?$/',
    wasParseError: "{ParsingData.UnsupportedEscape(48, 51)}"
  },
  {
    input:
      "/(\\A|\\s)(((>[:;=+])|[>:;=+])[,*]?[-~+o]?(\\)+|\\(+|\\}+|\\{+|\\]+|\\[+|\\|+|\\\\+|/+|>+|<+|D+|[@#!OoPpXxZS$03])|>?[xX8][-~+o]?(\\)+|\\(+|\\}+|\\{+|\\]+|\\[+|\\|+|\\\\+|/+|>+|<+|D+))(\\Z|\\s)/",
    isPumpable: false
  },
  {
    input:
      "/(\\A|\\s)((\\)+|\\(+|\\}+|\\{+|\\]+|\\[+|\\|+|\\\\+|/+|>+|<+|D+|[@#!OoXxZS$0])[-~+o]?[,*]?((<[:;=+])|[<:;=+])|(\\)+|\\(+|\\}+|\\{+|\\]+|\\[+|\\|+|\\\\+|/+|>+|<+|D+)[-~+o]?[xX8]<?)(\\Z|\\s)/",
    isPumpable: false
  },
  {
    input:
      "/(\\A|\\s)[({\\[]*([\\^\\*\\-@#$%<>XxVvOo0ZzTt+'¬](_+|\\.)[\\^\\*\\-@#$%<>XxVvOo0ZzTt+'¬]|\\._\\.|[\\^\\*@#$%<>XxVOo0ZTt']\\-[\\^\\*@#$%<>XxVOo0ZTt']|>>|><|<<|o[O0]|[O0]o)[)}\\]]*[;.?]*['\"]?(\\Z|\\s)/",
    wasParseError: "{ParsingData.NonAsciiInput(41, 194)}"
  },
  {
    input: "/<blockquote>(?:\\s*([^<]+)<br>\\s*)+<\\/blockquote>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<blockquote> \\x00<br>",
    pumpable: "\\x09\\x09<br>",
    suffix: ""
  },
  {
    input: "/^([-]?[0-9])$|^([-]?[1][0-2])$/",
    isPumpable: false
  },
  {
    input: "/^([-]?[0-9]?(\\.[0-9]{0,2})?)$|^([-]?([1][0-1])(\\.[0-9]{0,2})?)$|^([-]?([1][0-3](\\.[0]{0,2})))$/",
    isPumpable: false
  },
  {
    input: "/(?<=<(\\S|\\s)*)((?<=(href=('|\")+))|(?<=(href=))[^('|\")])([^'>\"\\s)]*)(?=('|\"|[\\S])?)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?<=<[\\/?]?)\\w+(?::\\w+)?/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: '/@"([^"]|["]{2})*"|".*?(?<=[^\\\\]|[\\\\]{2})"/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(22)}"
  },
  {
    input: "/^([a-z]{2,3}(\\.[a-zA-Z][a-zA-Z_$0-9]*)*)\\.([A-Z][a-zA-Z_$0-9]*)$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z][a-zA-Z_$0-9]*(\\.[a-zA-Z][a-zA-Z_$0-9]*)*)\\.)?([a-zA-Z][a-zA-Z_$0-9]*)$/",
    isPumpable: false
  },
  {
    input: "/^(\\+?36)?[ -]?(\\d{1,2}|(\\(\\d{1,2}\\)))\\/?([ -]?\\d){6,7}$/",
    isPumpable: false
  },
  {
    input:
      "/^[A-Z]{2}-[0-9]{2}-[0-9]{2}|[0-9]{2}-[0-9]{2}-[A-Z]{2}|[0-9]{2}-[A-Z]{2}-[0-9]{2}|[A-Z]{2}-[0-9]{2}-[A-Z]{2}|[A-Z]{2}-[A-Z]{2}-[0-9]{2}|}|[0-9]{2}-[A-Z]{2}-[A-Z]{2}|[0-9]{2}-[A-Z]{3}-[0-9]{1}|[0-9]{1}-[A-Z]{3}-[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^\\d* \\d*\\/{1}\\d*$|^\\d*$/",
    isPumpable: false
  },
  {
    input: "/(a|b|c).(a.b)*.b+.c/",
    isPumpable: false
  },
  {
    input: "/[-+]?((\\.[0-9]+|[0-9]+\\.[0-9]+)([eE][-+][0-9]+)?|[0-9]+)/",
    isPumpable: false
  },
  {
    input: "/^([0-1]?[0-9]|[2][0-3]):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^[+-]?\\d+(\\.\\d{1,4})? *%?$/",
    isPumpable: false
  },
  {
    input: "/(^0[78][2347][0-9]{7})/",
    isPumpable: false
  },
  {
    input: "/(^(?!000)\\d{3}) ([- ]?) ((?!00)\\d{2}) ([- ]?) ((?!0000)\\d{4})/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/(^(?!00)\\d{2}) ([- ]?) ((?!0000000)\\d{7})/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input:
      "/^([2][0]\\d{2}\\/([0]\\d|[1][0-2])\\/([0-2]\\d|[3][0-1]))$|^([2][0]\\d{2}\\/([0]\\d|[1][0-2])\\/([0-2]\\d|[3][0-1])\\s([0-1]\\d|[2][0-3])\\:[0-5]\\d\\:[0-5]\\d)$/",
    isPumpable: false
  },
  {
    input: '/target[ ]*[=]([ ]*)(["]|[\'])*([_])*([A-Za-z0-9])+(["])*/',
    isPumpable: false
  },
  {
    input:
      "/^((((H|h)(T|t)|(F|f))(T|t)(P|p)((S|s)?))\\:\\/\\/)?(www.|[a-zA-Z0-9].)[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,6}(\\:[0-9]{1,5})*(\\/($|[a-zA-Z0-9\\.\\,\\;\\?\\'\\\\\\+&%\\$#\\=~_\\-]+))*$/",
    isPumpable: false
  },
  {
    input: "/^(((ht|f)tp(s?))\\:\\/\\/).*$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]\\d{3}\\s?(?i)(?!(S[ADS]))([A-Z&&[^FIOQUY]]{2})$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^\\d*((\\.\\d+)?)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: ".0",
    suffix: "!"
  },
  {
    input:
      "/(\\[(\\w+)\\s*(([\\w]*)=('|\")?([a-zA-Z0-9|:|\\/|=|-|.|\\?|&]*)(\\5)?)*\\])([a-zA-Z0-9|:|\\/|=|-|.|\\?|&|\\s]+)(\\[\\/\\2\\])/",
    wasParseError: "{ParsingData.InvalidBackreference(57)}"
  },
  {
    input: "/[a-zA-Z0-9_\\\\-]+@([a-zA-Z0-9_\\\\-]+\\\\.)+(com)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a@a\\{",
    pumpable: "d\\\\\\\\d",
    suffix: ""
  },
  {
    input: "/^[\\-]{0,1}[0-9]{1,}(([\\.\\,]{0,1}[0-9]{1,})|([0-9]{0,}))$/",
    isPumpable: false
  },
  {
    input: "/(\\b)(\\w+(\\b|\\n|\\s)){3}/",
    isPumpable: false
  },
  {
    input: "/\\/^[-+]?[1-9](\\d*|((\\d{1,2})?,(\\d{3},)*(\\d{3})))?([eE][-+]\\d+)?$\\//",
    isPumpable: false
  },
  {
    input: "/\\/^[-+]?((\\d*|((\\d{1,3})?,(\\d{3},)*(\\d{3})))?)(\\.\\d*)?([eE][-+]\\d+)?$\\//",
    isPumpable: false
  },
  {
    input:
      "/((^(10|12|0?[13578])(3[01]|[12][0-9]|0?[1-9])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(11|0?[469])(30|[12][0-9]|0?[1-9])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(0?2)(2[0-8]|1[0-9]|0?[1-9])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(0?2)(29)([2468][048]00)$)|(^(0?2)(29)([3579][26]00)$)|(^(0?2)(29)([1][89][0][48])$)|(^(0?2)(29)([2-9][0-9][0][48])$)|(^(0?2)(29)([1][89][2468][048])$)|(^(0?2)(29)([2-9][0-9][2468][048])$)|(^(0?2)(29)([1][89][13579][26])$)|(^(0?2)(29)([2-9][0-9][13579][26])$))/",
    isPumpable: false
  },
  {
    input: "/^\\${1}[a-z]{1}[a-z\\d]{0,6}$/",
    isPumpable: false
  },
  {
    input:
      "/(((ht|f)tp(s?):\\/\\/)|(www\\.[^ \\[\\]\\(\\)\\n\\r\\t]+)|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})\\/)([^ \\[\\]\\(\\),;\"'<>\\n\\r\\t]+)([^\\. \\[\\]\\(\\),;\"'<>\\n\\r\\t])|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z]+)[0-9]*\\.*[a-zA-Z0-9]+$|^[a-zA-Z]+[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9._%-]+@[a-zA-Z0-9._%-]+\\.[a-zA-Z]{2,4}\\s*$/",
    isPumpable: false
  },
  {
    input:
      '/^([A-Za-z0-9\\!\\#\\$\\%\\&\\\'\\*\\+\\-\\/\\=\\?\\^\\_\\`\\{\\}\\|\\~]+|"([\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|\\\\[\\x0-\\x7F])*")(\\.([A-Za-z0-9\\!\\#\\$\\%\\&\\\'\\*\\+\\-\\/\\=\\?\\^\\_\\`\\{\\}\\|\\~]+|"([\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|\\\\[\\x0-\\x7F])*"))*@([A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?)*|(1[0-9]{0,2}|2([0-4][0-9]?|5[0-4]?|[6-9])?|[3-9][0-9]?)(\\.(0|1[0-9]{0,2}|2([0-4][0-9]?|5[0-5]?|[6-9])?|[3-9][0-9]?)){2}\\.(1[0-9]{0,2}|2([0-4][0-9]?|5[0-4]?|[6-9])?|[3-9][0-9]?))$/',
    wasParseError: "{ParsingData.UnsupportedEscape(110, 120)}"
  },
  {
    input: "/^([0-9]*\\,?[0-9]+|[0-9]+\\,?[0-9]*)?$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9])+\\\\{1}([a-zA-Z0-9])+$/",
    isPumpable: false
  },
  {
    input: "/^(\\()?(787|939)(\\)|-)?([0-9]{3})(-)?([0-9]{4}|[0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/(\\w+),\\s+(\\w+)\\s+ (\\((\\w+)\\)\\s+)? (\\w+),\\s+(\\w+)[^\\d]+ (\\d+)\\s+(\\w+)/",
    isPumpable: false
  },
  {
    input: "/(\\w+),[^(]+\\((\\w+)\\)\\s+(\\d+)\\s+(\\w+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)/",
    isPumpable: false
  },
  {
    input: "/(\\w+),[^(]+\\((\\w+)\\)\\s+(\\w+)\\s+(\\d+)\\/(\\d+)\\s+(\\d+)?/",
    isPumpable: false
  },
  {
    input:
      "/^((([a-zA-Z]:)|(\\\\{2}\\w+)|(\\\\{2}(?:(?:25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)(?(?=\\.?\\d)\\.)){4}))(\\\\(\\w[\\w ]*)))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(72, 40)}"
  },
  {
    input: "/^\\w+.*$/",
    isPumpable: false
  },
  {
    input: "/([.])([a-z,1-9]{3,4})(\\/)/",
    isPumpable: false
  },
  {
    input: "/(?<!})\\n/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?<key>[^\\s]+(\\s\\w)*)(?=([\\s]*:[\\s]*))\\2(?<=\\2)(?<value>\\b[^,:]+\\b)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(\\d*)'*-*(\\d*)\\/*(\\d*)\"/",
    isPumpable: false
  },
  {
    input: "/^[01]?[- .]?\\(?(?!\\d[1]{2})[2-9]\\d{2}\\)?[- .]?(?!\\d[1]{2})\\d{3}[- .]?\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(15)}"
  },
  {
    input:
      "/^((?:2[0-5]{2}|1\\d{2}|[1-9]\\d|[1-9])\\.(?:(?:2[0-5]{2}|1\\d{2}|[1-9]\\d|\\d)\\.){2}(?:2[0-5]{2}|1\\d{2}|[1-9]\\d|\\d)):(\\d|[1-9]\\d|[1-9]\\d{2,3}|[1-5]\\d{4}|6[0-4]\\d{3}|654\\d{2}|655[0-2]\\d|6553[0-5])$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z][a-zA-Z0-9_\\.\\-]+@([a-zA-Z0-9-]{2,}\\.)+([a-zA-Z]{2,4}|[a-zA-Z]{2}\\.[a-zA-Z]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/^((http|https|ftp):\\/\\/(www\\.)?|www\\.)[a-zA-Z0-9\\_\\-]+\\.([a-zA-Z]{2,4}|[a-zA-Z]{2}\\.[a-zA-Z]{2})(\\/[a-zA-Z0-9\\-\\._\\?\\&=,'\\+%\\$#~]*)*$/",
    isPumpable: false
  },
  {
    input: "/^(([0-9]{3})[-]?)*[0-9]{6,7}$/",
    isPumpable: false
  },
  {
    input: "/[\\+]?[1]?[-. ]?(\\(\\d{3}\\)|\\d{3})(|[-. ])?\\d{3}(|[-. ])\\d{4}|\\d{3}(|[-. ])\\d{4}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[1-9][0-9][0-9][0-9]$/",
    isPumpable: false
  },
  {
    input: "/^([Vv]+(erdade(iro)?)?|[Ff]+(als[eo])?|[Tt]+(rue)?|0|[\\+\\-]?1)$/",
    isPumpable: false
  },
  {
    input: "/(02\\d\\s?\\d{4}\\s?\\d{4})|(01\\d{2}\\s?\\d{3}\\s?\\d{4})|(01\\d{3}\\s?\\d{5,6})|(01\\d{4}\\s?\\d{4,5})/",
    isPumpable: false
  },
  {
    input: "/(077|078|079)\\s?\\d{2}\\s?\\d{6}/",
    isPumpable: false
  },
  {
    input:
      "/\\/^([a-z0-9])(([\\-.]|[_]+)?([a-z0-9]+))*(@)([a-z0-9])((([-]+)?([a-z0-9]+))?)*((.[a-z]{2,3})?(.[a-z]{2,6}))$\\/i/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input: "/^((\\d{8})|(\\d{10})|(\\d{11})|(\\d{6}-\\d{5}))?$/",
    isPumpable: false
  },
  {
    input: "/[\\x01-\\x08,\\x0A-\\x1F,\\x7F,\\x81,\\x8D,\\x8F,\\x90,\\x9D]/",
    wasParseError: "{ParsingData.NonAsciiInput(26, 129)}"
  },
  {
    input: "/^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input: "/^07([\\d]{3})[(\\D\\s)]?[\\d]{3}[(\\D\\s)]?[\\d]{3}$/",
    isPumpable: false
  },
  {
    input: "/\\<img ((src|height|width|border)=:q:Wh*)*\\/\\>/",
    isPumpable: false
  },
  {
    input: "/^([0-1](?:\\.\\d)|[0-1](?:\\,\\d)|(2\\.0)|(2\\,0))$/",
    isPumpable: false
  },
  {
    input: "/^(5[1-5]\\d{2})\\d{12}|(4\\d{3})(\\d{12}|\\d{9})$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9])|(0[1-9])|(1[0-2]))\\/(([0-9])|([0-2][0-9])|(3[0-1]))\\/(([0-9][0-9])|([1-2][0,9][0-9][0-9]))$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^(([01]?\\d?\\d|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d?\\d|2[0-4]\\d|25[0-5])\\/(\\d{1}|[0-2]{1}\\d{1}|3[0-2])$\\//",
    isPumpable: false
  },
  {
    input: "/^\\D?(\\d{3})\\D?\\D?(\\d{3})\\D?(\\d{4})$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\w\\d\\-\\.]+)@{1}(([\\w\\d\\-]{1,67})|([\\w\\d\\-]+\\.[\\w\\d\\-]{1,67}))\\.(([a-zA-Z\\d]{2,4})(\\.[a-zA-Z\\d]{2})?)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{6}[0-9LMNPQRSTUV]{2}[A-Za-z]{1}[0-9LMNPQRSTUV]{2}[A-Za-z]{1}[0-9LMNPQRSTUV]{3}[A-Za-z]{1}$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]0?$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-z]:((\\\\([-*\\.*\\w+\\s+\\d+]+)|(\\w+)\\\\)+)(\\w+.zip)|(\\w+.ZIP))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\\\x09",
    pumpable: "a\\\\\\x0900zip\\",
    suffix: ""
  },
  {
    input:
      "/^((\\(44\\))( )?|(\\(\\+44\\))( )?|(\\+44)( )?|(44)( )?)?((0)|(\\(0\\)))?( )?(((1[0-9]{3})|(7[1-9]{1}[0-9]{2})|(20)( )?[7-8]{1})( )?([0-9]{3}[ -]?[0-9]{3})|(2[0-9]{2}( )?[0-9]{3}[ -]?[0-9]{4}))$/",
    isPumpable: false
  },
  {
    input:
      "/(((0[1-9]|[12][0-9]|3[01])([-.\\/])(0[13578]|10|12)([-.\\/])(\\d{4}))|(([0][1-9]|[12][0-9]|30)([-.\\/])(0[469]|11)([-.\\/])(\\d{4}))|((0[1-9]|1[0-9]|2[0-8])([-.\\/])(02)([-.\\/])(\\d{4}))|((29)(\\.|-|\\/)(02)([-.\\/])([02468][048]00))|((29)([-.\\/])(02)([-.\\/])([13579][26]00))|((29)([-.\\/])(02)([-.\\/])([0-9][0-9][0][48]))|((29)([-.\\/])(02)([-.\\/])([0-9][0-9][2468][048]))|((29)([-.\\/])(02)([-.\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input: "/^[0-9]$|[1-9]+[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^-?[0-9]{0,2}(\\.[0-9]{1,2})?$|^-?(100)(\\.[0]{1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\w-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([\\w-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$/",
    isPumpable: false
  },
  {
    input: "/\\/^[1-9][0-9][0-9][0-9][0-9][0-9]$\\//",
    isPumpable: false
  },
  {
    input: "/\\/^[0-9]\\d{2,4}-\\d{6,8}$\\//",
    isPumpable: false
  },
  {
    input: "/^(([1-9]{1}(\\d+)?)(\\.\\d+)?)|([0]\\.(\\d+)?([1-9]{1})(\\d+)?)$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?(\\d?\\d?\\d?,?)?(\\d{3}\\,?)*(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/[^\\r\\n]|(?:\\r(?!\\n))|(?:(?<!\\r)\\n)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(13)}"
  },
  {
    input: "/^(?=(.*[a-zA-Z].*){2,})(?=.*\\d.*)(?=.*\\W.*)[a-zA-Z0-9\\S]{8,15}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d.*)(?=.*\\W.*)[a-zA-Z0-9\\S]{8,15}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: '/\\s*[;,]\\s*(?!(?<=(?:^|[;,])\\s*"(?:[^"]|""|\\\\")*[;,]\\s*)(?:[^"]|""|\\\\")*"\\s*(?:[;,]|$))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(10)}"
  },
  {
    input: "/^[0-9]{2,3}-? ?[0-9]{6,7}$/",
    isPumpable: false
  },
  {
    input: "/urn:[a-z0-9]{1}[a-z0-9\\-]{1,31}:[a-z0-9_,:=@;!'%\\/#\\(\\)\\+\\-\\.\\$\\*\\?]+/",
    isPumpable: false
  },
  {
    input: "/^\\d{3,3}\\.\\d{0,2}$|^E\\d{3,3}\\.\\d{0,2}$/",
    isPumpable: false
  },
  {
    input: "/\\/iP(?:[ao]d|hone)\\//",
    isPumpable: false
  },
  {
    input: "/^[A-Z]-\\d{3}(?>\\d|-[A-Z])$|^[A-Z]{2,3}-\\d{3}$|^\\d{3}-[A-Z]{3}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(12)}"
  },
  {
    input:
      "/^(?>[A-Z]{2}|\\d\\d)-(?>[A-Z]{2}|\\d\\d)-(?<!\\d\\d-\\d\\d-)\\d\\d$|^(?>[A-Z]{2}|\\d\\d)-(?>[A-Z]{2}|\\d\\d)-(?<![A-Z]{2}-[A-Z]{2}-)[A-Z]{2}$|^\\d\\d-[A-Z]{3}-\\d$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[0-3]{1}(?(?<=3)[01]{1}|\\d)([-.\\/]{1})[01]{1}(?(?<=1)[0-2]{1}|\\d)\\1(\\d{2}|\\d{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(11, 40)}"
  },
  {
    input: "/^(?:[^@<>;:,.()\\s\\[\\]\\\\]+(?:\\.(?!@))?)+@(?:[\\w\\-]+(?:\\.(?!\\.))?)+\\.[A-Za-z]{2,6}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(30)}"
  },
  {
    input: "/^([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])$/",
    isPumpable: false
  },
  {
    input: '/^([a-zA-Z]\\:) (\\\\{1}| ((\\\\{1}) [^\\\\] ([^/:*?<>"|]*(?<![ ])))+)$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(50)}"
  },
  {
    input: '/^([a-zA-Z]\\:)(\\\\{1}|((\\\\{1})[^\\\\/:*?<>"|]([^\\\\/:*?<>"|]*(?![ ])))+)$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(56)}"
  },
  {
    input: "/^+41 [0-9]{2}[ ][0-9]{3}[ ][0-9]{2}[ ][0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^([0]?[1-9]|[1][0-2])[.\\/-]([0]?[1-9]|[1|2][0-9]|[3][0|1])[.\\/-]([0-9]{4}|[0-9]{2})$/",
    isPumpable: false
  },
  {
    input: "/^([0]?[1-9]|[1|2][0-9]|[3][0|1])[.\\/-]([0]?[1-9]|[1][0-2])[.\\/-]([0-9]{4}|[0-9]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/^((http|https|ftp|ftps)+(:\\/\\/))?(www\\.)?(([a-z0-9\\.-]{2,})\\.(ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|fx|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|aero|asia|cat|coop|edu|gov|jobs|mil|mobi|museum|tel|travel|pro|post|biz|com|info|int|name|net|org|pro|arpa)|((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])))(:([1-9][0-9]?[0-9]?[0-9]?|[1-5][0-9][0-9][0-9][0-9]|6[0-4][0-9][0-9][0-9]|65[0-4][0-9][0-9]|655[0-2][0-9]|6553[0-5]|))?(((\\/(([a-zA-Z0-9_\\-\\%\\~\\+\\&\\;]{1,})+)*)*)|\\/$)?(\\.(php|html|htm|zip$|arj$|rar$|sit$|pdf$|gif$|jpg$|jpeg$|jpe$|tif$|tiff$))?(\\?([a-zA-Z0-9_\\-]+\\=[a-z-A-Z0-9_\\-\\%\\~\\+]+)?(\\&([a-zA-Z0-9_\\-]+\\=[a-z-A-Z0-9_\\-\\%\\~\\+]+))*)?(\\=\\?([a-zA-Z0-9_\\-])*)?(((\\+([a-zA-Z0-9_])*)?(\\-([a-zA-Z0-9_])*)?)*)?(\\#([a-z-A-Z0-9_\\-\\%\\~\\+\\&\\;]*$))?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/[_\\w-]+(?:\\.[_\\w-]+)*@(?:[\\w-]+\\.)+(?:[\\w-]{2,4})(?![\\w]+)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(49)}"
  },
  {
    input: "/http:\\/\\/www.datadoctor.biz/",
    isPumpable: false
  },
  {
    input:
      "/^((\\+){1}[1-9]{1}[0-9]{0,1}[0-9]{0,1}(\\s){1}[\\(]{1}[1-9]{1}[0-9]{1,5}[\\)]{1}[\\s]{1})[1-9]{1}[0-9]{4,9}$/",
    isPumpable: false
  },
  {
    input: "/^(27|0)[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/<h([1-6])>([^<]*)<\\/h([1-6])>/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{0,2})-([0-9]{0,2})-([0-9]{0,4})$/",
    isPumpable: false
  },
  {
    input: "/(?<Protocol>\\w+):\\/\\/(?<Domain>[\\w@][\\w.:\\-@]+)\\/(?<Container>[\\w= ,@-]+)*/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[^iIoOqQ'-]{10,17}$/",
    isPumpable: false
  },
  {
    input: '/^(?<Code>([^"\']|"[^"]*")*)\'(?<Comment>.*)$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^((\\+)?[1-9]{1,2})?([-\\s\\.])?((\\(\\d{1,4}\\))|\\d{1,4})(([-\\s\\.])?[0-9]{1,12}){1,2}$/",
    isPumpable: false
  },
  {
    input: "/^(?!000)(?!666)(?!9)\\d{3}[- ]?(?!00)\\d{2}[- ]?(?!0000)\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/function[\\s]+[\\S]+[\\s]*([\\s]*)[\\s]*{[\\s]*([\\S]|[\\s])*[\\s]*}/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(35)}"
  },
  {
    input: "/^ *(1[0-2]|[1-9]):[0-5][0-9] *(a|p|A|P)(m|M) *$/",
    isPumpable: false
  },
  {
    input: "/(?=^.{1,254}$)(^(?:(?!\\d+\\.|-)[a-zA-Z0-9_\\-]{1,63}(?<!-)\\.?)+(?:[a-zA-Z]{2,})$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^([a-zA-Z0-9]+([\\.+_-][a-zA-Z0-9]+)*)@(([a-zA-Z0-9]+((\\.|[-]{1,2})[a-zA-Z0-9]+)*)\\.[a-zA-Z]{2,6})$/",
    isPumpable: false
  },
  {
    input: "/^[0]*?(?<Percentage>[1-9][0-9]?|100)%?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input:
      '/^(([a-zA-Z]:|\\\\)\\\\)?(((\\.)|(\\.\\.)|([^\\\\/:\\*\\?"\\|<>\\. ](([^\\\\/:\\*\\?"\\|<>\\. ])|([^\\\\/:\\*\\?"\\|<>]*[^\\\\/:\\*\\?"\\|<>\\. ]))?))\\\\)*[^\\\\/:\\*\\?"\\|<>\\. ](([^\\\\/:\\*\\?"\\|<>\\. ])|([^\\\\/:\\*\\?"\\|<>]*[^\\\\/:\\*\\?"\\|<>\\. ]))?$/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "{\\x00\\",
    suffix: ""
  },
  {
    input: "/\\A(([a-zA-Z]{1,2}\\d{1,2})|([a-zA-Z]{2}\\d[a-zA-Z]{1}))\\x20{0,1}\\d[a-zA-Z]{2}\\Z/",
    isPumpable: false
  },
  {
    input:
      "/(^13((\\ )?\\d){4}$)|(^1[38]00((\\ )?\\d){6}$)|(^(((\\(0[23478]\\))|(0[23478]))(\\ )?)?\\d((\\ )?\\d){7}$)/",
    isPumpable: false
  },
  {
    input:
      "/(^\\(\\)$|^\\(((\\([0-9]+,(\\((\\([0-9]+,[0-9]+,[0-9]+\\),)*(\\([0-9]+,[0-9]+,[0-9]+\\)){1}\\))+\\),)*(\\([0-9]+,(\\((\\([0-9]+,[0-9]+,[0-9]+\\),)*(\\([0-9]+,[0-9]+,[0-9]+\\)){1}\\))+\\)){1}\\)))$/",
    isPumpable: false
  },
  {
    input: "/^[D-d][K-k]-[1-9]{1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[D-d][K-k]( |-)[1-9]{1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[S-s]( |-)?[1-9]{1}[0-9]{2}( |-)?[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^(?=[a-zA-Z])(?=.*[0-9])(?=.*[#\\$_])(?=.*[A-Z])(?=.*[a-z])(?!.*[^a-zA-Z0-9#\\$_])(?!.*\\s).{8,12}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^((0[1-9])|(1[0-2]))[\\/\\.\\-]*((0[8-9])|(1[1-9]))$/",
    isPumpable: false
  },
  {
    input: "/^(^N[BLSTU]$)|(^[AMN]B$)|(^[BQ]C$)|(^ON$)|(^PE$)|(^SK$)$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-zA-Z])(?!.*\\s).{6,12}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^([\\w][\\w\\-_\\u0020]{4,18}[\\w])$/",
    wasParseError: "{ParsingData.UnsupportedEscape(13, 117)}"
  },
  {
    input: "/^(?:m|M|male|Male|f|F|female|Female)$/",
    isPumpable: false
  },
  {
    input: "/^\\(\\d{3}\\)\\s?|\\d{3}(\\.|-|\\s)?)\\d{3}(\\.|-|\\s)?\\d{4}$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[a-zA-Z]\\:\\\\.*|^\\\\\\\\.*/",
    isPumpable: false
  },
  {
    input:
      "/^[NS]([0-8][0-9](\\.[0-5]\\d){2}|90(\\.00){2})\\040[EW]((0\\d\\d|1[0-7]\\d)(\\.[0-5]\\d){2}|180(\\.00){2})$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,15}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/(?<FirstName>[A-Z]\\.?\\w*\\-?[A-Z]?\\w*)\\s?(?<MiddleName>[A-Z]\\w*|[A-Z]?\\.?)\\s?(?<LastName>[A-Z]\\w*\\-?[A-Z]?\\w*)(?:,\\s|)(?<Suffix>Jr\\.|Sr\\.|IV|III|II|)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(?<FirstName>[A-Z]\\.?\\w*\\-?[A-Z]?\\w*)\\s?(?<MiddleName>[A-Z]\\w+|[A-Z]?\\.?)\\s(?<LastName>[A-Z]?\\w{0,3}[A-Z]\\w+\\-?[A-Z]?\\w*)(?:,\\s|)(?<Suffix>Jr\\.|Sr\\.|IV|III|II|)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(?<FirstName>[A-Z]\\.?\\w*\\-?[A-Z]?\\w*)\\s?(?<MiddleName>[A-Z]\\w+|[A-Z]?\\.?)\\s(?<LastName>(?:[A-Z]\\w{1,3}|St\\.\\s)?[A-Z]\\w+\\-?[A-Z]?\\w*)(?:,\\s|)(?<Suffix>Jr\\.|Sr\\.|IV|III|II|)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(?<LastName>[A-Z]\\w+\\-?[A-Z]?\\w*),\\s(?<Suffix>Jr\\.|Sr\\.|IV|III|II)?,?\\s?(?<FirstName>[A-Z]\\w*\\-?[A-Z]?\\w*\\.?)\\s?(?<MiddleName>[A-Z]?\\w*\\.?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[^<>`~!\\/@\\#},.?\"-$%:;)(_ ^{&*=|'+]+$/",
    isPumpable: false
  },
  {
    input: "/^\\d$|^[1][0]$/",
    isPumpable: false
  },
  {
    input:
      "/^(AT ?U[0-9]{7}|BE ?[0-9]{10}|BG ?[0-9]{9,10}|CY ?[0-9]{8}[A-Z]{1}|CZ ?[0-9]{8,10}|DE ?[0-9]{9}|DK ?[0-9]{8}|EE ?[0-9]{9}|EL ?[0-9]{9}|ES ?[0-9A-Z]{9}|FI ?[0-9]{8}|FR ?[0-9A-Z]{11}|HU ?[0-9]{8}|IE ?[0-9A-Z]{8}|IT ?[0-9]{11}|LT ?([0-9]{9}|[0-9]{12})|LU ?[0-9]{8}|LV ?[0-9]{11}|MT ?[0-9]{8}|NL ?[0-9B]{12}|PL ?[0-9]{10}|PT ?[0-9]{9}|RO ?[0-9]{2,10}|SE ?[0-9]{12}|SI ?[0-9]{8}|SK ?[0-9]{10})$/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\\,?\\s+((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\\,?\\s+((?:[A-Za-z]+\\x20*)+)\\,\\s+(A[LKSZRAP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD]|T[NX]|UT|V[AIT]|W[AIVY])\\s+(\\d+(?:-\\d+)?)\\s*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0 aS.  V",
    pumpable: "VV",
    suffix: ""
  },
  {
    input:
      "/(^\\$(\\d{1,3},?(\\d{3},?)*\\d{3}(\\.\\d{1,3})?|\\d{1,3}(\\.\\d{2})?)$|^\\d{1,2}(\\.\\d{1,2})? *%$|^100%$)/",
    isPumpable: false
  },
  {
    input: "/^\\d+(?:\\.\\d{0,2})?$/",
    isPumpable: false
  },
  {
    input: "/^([0-1]?[0-9]|[2][0-3])[:|.]([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^\\d+\\/?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^(\\d?)*(\\.\\d{1}|\\.\\d{2})?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "0",
    suffix: "!"
  },
  {
    input: "/[^<>\\/?&{};#]+/",
    isPumpable: false
  },
  {
    input: "/^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/^(?-i:[A-Z]{1}[a-z]+(?<fnh>[-]{1})?(?(fnh)[A-Z]{1}[a-z]+)\\s[A-Z]{1}(?<apos>[']{1})?(?(apos)[A-Z]{1})[a-z]+(?<lnh>[-]{1})?(?(lnh)[A-Z]{1}[a-z]+))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(22, 60)}"
  },
  {
    input: "/^([a-zA-z\\s]{2,})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-z\\s]{4,32})$/",
    isPumpable: false
  },
  {
    input:
      "/(?<protocol>http(s)?|ftp):\\/\\/(?<server>([A-Za-z0-9-]+\\.)*(?<basedomain>[A-Za-z0-9-]+\\.[A-Za-z0-9]+))+((\\/?)(?<path>(?<dir>[A-Za-z0-9\\._\\-]+)(\\/){0,1}[A-Za-z0-9.-\\/]*)){0,1}/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\\.){3}([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])$/",
    isPumpable: false
  },
  {
    input: '/^<a[^>]*(http://[^"]*)[^>]*>([ 0-9a-zA-Z]+)</a>$/',
    isPumpable: false
  },
  {
    input: "/^[^\\x00-\\x1f\\x21-\\x26\\x28-\\x2d\\x2f-\\x40\\x5b-\\x60\\x7b-\\xff]+$/",
    wasParseError: "{ParsingData.NonAsciiInput(48, 255)}"
  },
  {
    input: "/^(\\d{1,})$|^(\\d{1,}\\.)$|^(\\d{0,}?\\.\\d{1,})$|^([+-]\\d{1,}(\\.)?)$|^([+-](\\d{1,})?\\.\\d{1,})$/",
    isPumpable: false
  },
  {
    input:
      "/^((?:4\\d{3})|(?:5[1-5]\\d{2})|(?:6011)|(?:3[68]\\d{2})|(?:30[012345]\\d))[ -]?(\\d{4})[ -]?(\\d{4})[ -]?(\\d{4}|3[4,7]\\d{13})$/",
    isPumpable: false
  },
  {
    input: "/([^,0-9]\\D*)([0-9]*|\\d*\\,\\d*)$/",
    isPumpable: false
  },
  {
    input: "/(^\\-|\\+)?([1-9]{1}[0-9]{0,2}(\\,\\d{3})*|[1-9]{1}\\d{0,})$|^0?$/",
    isPumpable: false
  },
  {
    input: "/^((([0-9]|([0-1][0-9])|(2[0-3]))[hH:][0-5][0-9])|(([0-9]|(1[0-9])|(2[0-3]))[hH]))$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9@*#]{8,15})$/",
    isPumpable: false
  },
  {
    input:
      "/(([+]?34) ?)?(6(([0-9]{8})|([0-9]{2} [0-9]{6})|([0-9]{2} [0-9]{3} [0-9]{3}))|9(([0-9]{8})|([0-9]{2} [0-9]{6})|([1-9] [0-9]{7})|([0-9]{2} [0-9]{3} [0-9]{3})|([0-9]{2} [0-9]{2} [0-9]{2} [0-9]{2})))/",
    isPumpable: false
  },
  {
    input: "/(0?[1-9]|[1-9][0-9])[0-9]{6}(-| )?[trwagmyfpdxbnjzsqvhlcke]/",
    isPumpable: false
  },
  {
    input: "/<a[\\s]+[^>]*?href[\\s]?=[\\s\\\"\\']+(.*?)[\\\"\\']+.*?>([^<]+|.*?)?<\\/a>/",
    isPumpable: false
  },
  {
    input: "/^.+\\@.+\\..+$/",
    isPumpable: false
  },
  {
    input:
      "/(((ht|f)tp(s?):\\/\\/)|(([\\w]{1,})\\.[^ \\[\\]\\(\\)\\n\\r\\t]+)|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})\\/)([^ \\[\\]\\(\\),;\"'<>\\n\\r\\t]+)([^\\. \\[\\]\\(\\),;\"'<>\\n\\r\\t])|(([012]?[0-9]{1,2}\\.){3}[012]?[0-9]{1,2})/",
    isPumpable: false
  },
  {
    input: "/^(NAME)(\\s?)<?(\\w*)(\\s*)([0-9]*)>?$/",
    isPumpable: false
  },
  {
    input: "/(^[0-9]{0,10}$)/",
    isPumpable: false
  },
  {
    input:
      "/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-2]) ([0-1][0-9]|2[0-4]):([0-4][0-9]|5[0-9]):([0-4][0-9]|5[0-9])$/",
    isPumpable: false
  },
  {
    input: "/(?<=>)[A-Z]{2}[\\d|\\w]{9}\\d{1}(?=(<))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      '/<img\\s((width|height|alt|align|style)="[^"]*"\\s)*src="(\\/?[a-z0-9_-]\\/?)+\\.(png|jpg|jpeg|gif)"(\\s(width|height|alt|align|style)="[^"]*")*\\s*\\/>/',
    isPumpable: true,
    isVulnerable: true,
    prefix: '<img src="0',
    pumpable: "0/-",
    suffix: ""
  },
  {
    input: "/(\\d{6}[-\\s]?\\d{12})|(\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4})/",
    isPumpable: false
  },
  {
    input:
      "/^([0]\\d|[1][0-2])\\/([0-2]\\d|[3][0-1])\\/([2][01]|[1][6-9])\\d{2}(\\s([0]\\d|[1][0-2])(\\:[0-5]\\d){1,2})*\\s*([aApP][mM]{0,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((0?[1-9]|[12]\\d|3[01])[-\\/]([0]?[13578]|1[02]))|((0?[1-9]|[12]\\d|30)[-\\/]([0]?[469]|11))|(([01]?\\d|2[0-8])[-\\/]0?2))[-\\/]((20|19)?\\d{2}|\\d{1,2}))|(29[-\\/]0?2[-\\/]((19)|(20))?([13579][26]|[24680][048])))$/",
    isPumpable: false
  },
  {
    input: "/(?s)(?i)^(?!^.*(dont match me).*$).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(9)}"
  },
  {
    input:
      "/^((((([13578])|(1[0-2]))[\\-\\/\\s]?(([1-9])|([1-2][0-9])|(3[01])))|((([469])|(11))[\\-\\/\\s]?(([1-9])|([1-2][0-9])|(30)))|(2[\\-\\/\\s]?(([1-9])|([1-2][0-9]))))[\\-\\/\\s]?\\d{4})(\\s((([1-9])|(1[02]))\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])\\s))([AM|PM|am|pm]{2,2})))?$/",
    isPumpable: false
  },
  {
    input: "/^[a-z]+[0-9]*[a-z]+$/",
    isPumpable: false
  },
  {
    input: "/([0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\\w]*[0-9a-zA-Z]\\.)+[a-zA-Z]{2,9})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "00",
    suffix: ""
  },
  {
    input: "/(?<Sedol>[B-Db-dF-Hf-hJ-Nj-nP-Tp-tV-Xv-xYyZz\\d]{6}\\d)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/[AaEeIiOoUuYy]/",
    isPumpable: false
  },
  {
    input: "/((\\s)*(?<Key>([^\\=^\\s^\\n]+))[\\s^\\n]*\\=(\\s)*(?<Value>([^\\n^\\s]+(\\n){0,1})))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input: "/^((\\d{2,4})\\/)?((\\d{6,8})|(\\d{2})-(\\d{2})-(\\d{2,4})|(\\d{3,4})-(\\d{3,4}))$/",
    isPumpable: false
  },
  {
    input: "/^(([1..9])|(0[1..9])|(1\\d)|(2\\d)|(3[0..1])).((\\d)|(0\\d)|(1[0..2])).(\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^100$|^\\d{0,2}(\\.\\d{1,2})? *%?$/",
    isPumpable: false
  },
  {
    input: "/(?<=(\\A|,))(?<val>(\\w|\\W){1})(?=(,|\\Z))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(13, 60)}"
  },
  {
    input: "/<([^\\s>]*)(\\s[^<]*)>/",
    isPumpable: false
  },
  {
    input: "/<([^<>\\s]*)(\\s[^<>]*)?>/",
    isPumpable: false
  },
  {
    input:
      "/\\A([A-Za-z0-9'~`!@#$%&^_+=\\(\\){},\\-\\[\\]\\;])+?([ A-Za-z0-9'~`!@#$%&^_+=\\(\\){},\\-\\[\\];]|([.]))*?(?(3)(([ A-Za-z0-9'~`!@#$%&^_+=\\(\\){},\\-\\[\\]\\;]*?)([A-Za-z0-9'~`!@#$%&^_+=\\(\\){},\\-\\[\\];])+\\z)|(\\z))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(96, 40)}"
  },
  {
    input:
      "/^(?:(?<1>[(])?(?<AreaCode>[2-9]\\d{2})(?(1)[)][ ]?|[- \\/.]?))?(?<Prefix>[1-9]\\d{2})[- .]?(?<Suffix>\\d{4})(?:(?:[ ]+|[xX]|Ext\\.?[ ]?){1,2}(?<Ext>\\d{1,5}))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input:
      "/^((([A-PR-UWYZ])([0-9][0-9A-HJKS-UW]?))|(([A-PR-UWYZ][A-HK-Y])([0-9][0-9ABEHMNPRV-Y]?))\\s{0,2}(([0-9])([ABD-HJLNP-UW-Z])([ABD-HJLNP-UW-Z])))|(((GI)(R))\\s{0,2}((0)(A)(A)))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1}[\\w\\sa-zA-Z\\d_]*[^\\s]$/",
    isPumpable: false
  },
  {
    input: "/(?!^0*$)(?!^0*\\.0*$)^\\d{1,5}(\\.\\d{1,3})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/<[^\\/bp][^><]*>|<p[a-z][^><]*>|<b[^r][^><]*>|<br[a-z][^><]*>|<\\/[^bp]+>|<\\/p[a-z]+>|<\\/b[^r]+>|<\\/br[a-z]+>/",
    isPumpable: false
  },
  {
    input:
      "/((^(10|12|0?[13578])([\\/])(3[01]|[12][0-9]|0?[1-9])([\\/])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(11|0?[469])([\\/])(30|[12][0-9]|0?[1-9])([\\/])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(0?2)([\\/])(2[0-8]|1[0-9]|0?[1-9])([\\/])((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(0?2)([\\/])(29)([\\/])([2468][048]00)$)|(^(0?2)([\\/])(29)([\\/])([3579][26]00)$)|(^(0?2)([\\/])(29)([\\/])([1][89][0][48])$)|(^(0?2)([\\/])(29)([\\/])([2-9][0-9][0][48])$)|(^(0?2)([\\/])(29)([\\/])([1][89][2468][048])$)|(^(0?2)([\\/])(29)([\\/])([2-9][0-9][2468][048])$)|(^(0?2)([\\/])(29)([\\/])([1][89][13579][26])$)|(^(0?2)([\\/])(29)([\\/])([2-9][0-9][13579][26])$))/",
    isPumpable: false
  },
  {
    input: "/(\\d+)([,|.\\d])*\\d/",
    isPumpable: false
  },
  {
    input: "/^[3|4|5|6]([0-9]{15}$|[0-9]{12}$|[0-9]{13}$|[0-9]{14}$)/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z0-9](([_\\.\\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\\.\\-]?[a-zA-Z0-9]+)*)\\.([A-Za-z]{2,})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input:
      "/(\\s*\\(?0\\d{4}\\)?(\\s*|-)\\d{3}(\\s*|-)\\d{3}\\s*)|(\\s*\\(?0\\d{3}\\)?(\\s*|-)\\d{3}(\\s*|-)\\d{4}\\s*)|(\\s*(7|8)(\\d{7}|\\d{3}(\\-|\\s{1})\\d{4})\\s*)/",
    isPumpable: false
  },
  {
    input:
      "/^((http|https|ftp):\\/\\/)?((.*?):(.*?)@)?([a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])((\\.[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])*)(:([0-9]{1,5}))?((\\/.*?)(\\?(.*?))?(\\#(.*))?)?$/",
    isPumpable: false
  },
  {
    input:
      "/^(([A-Z]{1,2}[ ]?[0-9]{1,4})|([A-Z]{3}[ ]?[0-9]{1,3})|([0-9]{1,3}[ ]?[A-Z]{3})|([0-9]{1,4}[ ]?[A-Z]{1,2})|([A-Z]{3}[ ]?[0-9]{1,3}[ ]?[A-Z])|([A-Z][ ]?[0-9]{1,3}[ ]?[A-Z]{3})|([A-Z]{2}[ ]?[0-9]{2}[ ]?[A-Z]{3})|([A-Z]{3}[ ]?[0-9]{4}))$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{3}\\s{0,1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[0-3][0-9][0-1]\\d{3}-\\d{4}?/",
    isPumpable: false
  },
  {
    input:
      "/(^|\\s)(00[1-9]|0[1-9]0|0[1-9][1-9]|[1-6]\\d{2}|7[0-6]\\d|77[0-2])(-?|[\\. ])([1-9]0|0[1-9]|[1-9][1-9])\\3(\\d{3}[1-9]|[1-9]\\d{3}|\\d[1-9]\\d{2}|\\d{2}[1-9]\\d)($|\\s|[;:,!\\.\\?])/",
    isPumpable: false
  },
  {
    input: "/\\[\\w+\\]\\s+((.*=.*\\s+)*|[^\\[])/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/^((https?|ftp)\\:\\/\\/((\\[?(\\d{1,3}\\.){3}\\d{1,3}\\]?)|(([-a-zA-Z0-9]+\\.)+[a-zA-Z]{2,4}))(\\:\\d+)?(\\/[-a-zA-Z0-9._?,'+&%$#=~\\\\]+)*/?)$/",
    isPumpable: false
  },
  {
    input: "/[^abc]/",
    isPumpable: false
  },
  {
    input: "/^[+]?((\\d*[1-9]+\\d*\\.?\\d*)|(\\d*\\.\\d*[1-9]+\\d*))$/",
    isPumpable: false
  },
  {
    input: "/(^(?!0{5})(\\d{5})(?!-?0{4})(-?\\d{4})?$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/^(\\[a-zA-Z '\\]+)$/",
    isPumpable: false
  },
  {
    input: "/\\s*((a|b|c)\\s+(?!.*\\2.*))*(a|b|c)\\s*/",
    wasParseError: "{ParsingData.InvalidBackreference(19)}"
  },
  {
    input: "/^[ 1(]{0,3}?([02-9][0-9]{2})\\D{0,2}([0-9]{3})\\D?([0-9]{4})($|\\D+.+$)/",
    isPumpable: false
  },
  {
    input: "/^[0-9\\s\\(\\)\\+\\-]+$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+((\\s|\\-|\\')[a-zA-Z]+)?$/",
    isPumpable: false
  },
  {
    input: "/^(([0-9]{5})*-([0-9]{4}))|([0-9]{5})$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:(?:0?[13578]|1[02])(\\/|-)31)|(?:(?:0?[1,3-9]|1[0-2])(\\/|-)(?:29|30)))(\\/|-)(?:[1-9]\\d\\d\\d|\\d[1-9]\\d\\d|\\d\\d[1-9]\\d|\\d\\d\\d[1-9])$|^(?:(?:0?[1-9]|1[0-2])(\\/|-)(?:0?[1-9]|1\\d|2[0-8]))(\\/|-)(?:[1-9]\\d\\d\\d|\\d[1-9]\\d\\d|\\d\\d[1-9]\\d|\\d\\d\\d[1-9])$|^(0?2(\\/|-)29)(\\/|-)(?:(?:0[48]00|[13579][26]00|[2468][048]00)|(?:\\d\\d)?(?:0[48]|[2468][048]|[13579][26]))$/",
    isPumpable: false
  },
  {
    input: "/\\d{10,12}@[a-zA-Z].[a-zA-Z].*/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{4}\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1}[0-9]{1}[a-zA-Z]{1}[- ]{0,1}[0-9]{1}[a-zA-Z]{1}[0-9]{1}/",
    isPumpable: false
  },
  {
    input:
      "/^\\D{0,2}[0]{0,3}[1]{0,1}\\D{0,2}([2-9])(\\d{2})\\D{0,2}(\\d{3})\\D{0,2}(\\d{3})\\D{0,2}(\\d{1})\\D{0,2}$/",
    isPumpable: false
  },
  {
    input: '/href[\\s]*=[\\s]*"[^\\n"]*"/',
    isPumpable: false
  },
  {
    input: "/(INSERT INTO\\s+)(\\w+)(\\s+\\()([\\w+,?\\s*]+)(\\)\\s+VALUES\\s+\\()(['?\\w+'?,?\\s*]+)(\\))/",
    isPumpable: false
  },
  {
    input: "/(INSERT INTO\\s+)(\\w+)(\\s+\\()([\\w+,?\\s*]+)(\\)\\s+VALUES\\s+)((\\(['?\\w+'?,?\\s*]+\\)\\,?;?\\s*)+)/",
    isPumpable: false
  },
  {
    input: "/(UPDATE\\s+)(\\w+)\\s+(SET)\\s+([\\w+\\s*=\\s*\\w+,?\\s*]+)\\s+(WHERE.+)/",
    isPumpable: false
  },
  {
    input:
      "/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\,*\\s\\s*\\d{4}$|^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\\,*\\s\\d{4}$|^(January|February|March|April|May|June|July|August|September|October|November|December)\\,*\\s\\d{4}$|^(january|february|march|april|may|june|july|august|september|october|november|december)\\,*\\s\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/src=(?:\\\"|\\')?(?<imgSrc>[^>]*[^\\/].(?:jpg|bmp|gif|png))(?:\\\"|\\')?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(16, 60)}"
  },
  {
    input:
      "/^(((((0[1-9])|(1\\d)|(2[0-8]))-((0[1-9])|(1[0-2])))|((31-((0[13578])|(1[02])))|((29|30)-((0[1,3-9])|(1[0-2])))))-((20[0-9][0-9]))|(29-02-20(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input:
      "/^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b)\\.){3}(\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b))|(([0-9A-Fa-f]{1,4}:){0,5}:((\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b)\\.){3}(\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b))|(::([0-9A-Fa-f]{1,4}:){0,5}((\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b)\\.){3}(\\b((25[0-5])|(1\\d{2})|(2[0-4]\\d)|(\\d{1,2}))\\b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$/",
    isPumpable: false
  },
  {
    input: "/([0-9a-z_-]+[\\.][0-9a-z_-]{1,3})$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9]{1}\\d{0,2},(\\d{3},)*\\d{3})|([1-9]{1}\\d{0,}))$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{1}[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/^(\\+27|27|0)[0-9]{2}( |-)?[0-9]{3}( |-)?[0-9]{4}( |-)?(x[0-9]+)?(ext[0-9]+)?/",
    isPumpable: false
  },
  {
    input:
      "/^(?<From>(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER|[ ]|,|\\/|[0-9])+)(-|–|:|TO)?(?<To>(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER|[ ]|,|\\/|[0-9]|PRESENT)+)+(:)*/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/(?<Telephone>([0-9]|[ ]|[-]|[\\(]|[\\)]|ext.|[,])+)([ ]|[:]|\\t|[-])*(?<Where>Home|Office|Work|Away|Fax|FAX|Phone)|(?<Where>Home|Office|Work|Away|Fax|FAX|Phone|Daytime|Evening)([ ]|[:]|\\t|[-])*(?<Telephone>([0-9]|[ ]|[-]|[\\(]|[\\)]|ext.|[,])+)|(?<Telephone>([(]([0-9]){3}[)]([ ])?([0-9]){3}([ ]|-)([0-9]){4}))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(?<http>(http:[\\/][\\/]|www.)([a-z]|[A-Z]|[0-9]|[\\/.]|[~])*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(?<email>(?![ ])(\\w|[.])*@(\\w|[.])*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: '/[\\s0-9a-zA-Z\\;\\"\\,\\<\\>\\\\?\\+\\=\\)\\(\\\\*\\&\\%\\\\$\\#\\.]*/',
    isPumpable: false
  },
  {
    input:
      "/^((f|ht)tp(s)?)\\:\\/\\/([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,6}((\\/|\\?)[a-zA-Z0-9\\.\\?=\\/#%&\\+-]+|\\/|)$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^\\s*-?(\\d{0,7}|10[0-5]\\d{0,5}|106[0-6]\\d{0,4}|1067[0-4]\\d{0,3}|10675[0-1]\\d{0,2}|((\\d{0,7}|10[0-5]\\d{0,5}|106[0-6]\\d{0,4}|1067[0-4]\\d{0,3}|10675[0-1]\\d{0,2})\\.)?([0-1]?[0-9]|2[0-3]):[0-5]?[0-9](:[0-5]?[0-9](\\.\\d{1,7})?)?)\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/^[\\s]*(?:(Public|Private)[\\s]+(?:[_][\\s]*[\\n\\r]+)?)?(Function|Sub)[\\s]+(?:[_][\\s]*[\\n\\r]+)?([a-zA-Z][\\w]{0,254})(?:[\\s\\n\\r_]*\\((?:[\\s\\n\\r_]*([a-zA-Z][\\w]{0,254})[,]?[\\s]*)*\\))?/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "Public _\\x0dFunction _\\x0da(",
    pumpable: "A\\x09A",
    suffix: ""
  },
  {
    input: "/\\b(?([A-Z])[^DFIOQUWZ])\\d(?([A-Z])[^DFIOQU])\\d(?([A-Z])[^DFIOQUWZ])\\d\\b/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 40)}"
  },
  {
    input: "/^(N[BLSTU]|[AMN]B|[BQ]C|ON|PE|SK)$/",
    isPumpable: false
  },
  {
    input:
      "/(?:@[A-Z]\\w*\\s+)*(?:(?:public|private|protected)\\s+)?(?:(?:(?:abstract|final|native|transient|static|synchronized)\\s+)*(?:<(?:\\?|[A-Z]\\w*)(?:\\s+(?:extends|super)\\s+[A-Z]\\w*)?(?:(?:,\\s*(?:\\?|[A-Z]\\w*))(?:\\s+(?:extends|super)\\s+[A-Z]\\w*)?)*>\\s+)?(?:(?:(?:[A-Z]\\w*(?:<[A-Z]\\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\\[\\]))*)|void)+)\\s+(([a-zA-Z]\\w*)\\s*\\(\\s*(((?:[A-Z]\\w*(?:<(?:\\?|[A-Z]\\w*)(?:\\s+(?:extends|super)\\s+[A-Z]\\w*)?(?:(?:,\\s*(?:\\?|[A-Z]\\w*))(?:\\s+(?:extends|super)\\s+[A-Z]\\w*)?)*>)?|int|float|double|char|boolean|byte|long|short)(?:(?:\\[\\])|\\.\\.\\.)?\\s+[a-z]\\w*)(?:,\\s*((?:[A-Z]\\w*(?:<[A-Z]\\w*>)?|int|float|double|char|byte|long|short|boolean)(?:(?:\\[\\])|\\.\\.\\.)?\\s+[a-z]\\w*))*)?\\s*\\))/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "AA",
    suffix: ""
  },
  {
    input: "/((\\d{2})|(\\d))\\/((\\d{2})|(\\d))\\/((\\d{4})|(\\d{2}))/",
    isPumpable: false
  },
  {
    input: "/^(([0]?[1-9]|1[0-2])(:)([0-5][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^[+][0-9]\\d{2}-\\d{3}-\\d{4}$/",
    isPumpable: false
  },
  {
    input: '/"((\\\\")|[^"(\\\\")])+"/',
    isPumpable: false
  },
  {
    input:
      "/^((((0?[13578])|(1[02]))[\\/|\\-]?((0?[1-9]|[0-2][0-9])|(3[01])))|(((0?[469])|(11))[\\/|\\-]?((0?[1-9]|[0-2][0-9])|(30)))|(0?[2][\\/\\-]?(0?[1-9]|[0-2][0-9])))[\\/\\-]?\\d{2,4}$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z Á-Úá-ú][^1234567890]+$/",
    wasParseError: "{ParsingData.NonAsciiInput(8, 195)}"
  },
  {
    input: "/^((l((ll)|(b)|(bb)|(bbb)))|(bb*))$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]([0-9])?)(\\.(([0])?|([1-9])?|[1]([0-1])?)?)?$/",
    isPumpable: false
  },
  {
    input: "/\\b[A-Z0-9]{5}\\d{1}[01567]\\d{1}([0][1-9]|[12][0-9]|[3][0-1])\\d{1}[A-Z0-9]{3}[A-Z]{2}\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b([Jj](([Aa][Nn][Uu][Aa][Rr][Yy]|[Aa][Nn])|([Uu][Nn][Ee]|[Uu][Nn])|([Uu][Ll][Yy]|[Uu][Ll])))\\b|\\b((([Ss][Ee][Pp][Tt]|[Nn][Oo][Vv]|[Dd][Ee][Cc])[Ee][Mm])|[Oo][Cc][Tt][Oo])[Bb][Ee][Rr]|([Ss][Ee][Pp]|[Nn][Oo][Vv]|[Dd][Ee][Cc]|[Oo][Cc][Tt])\\b|\\b([Mm][Aa]([Yy]|([Rr][Cc][Hh]|[Rr])))\\b|\\b[Aa](([Pp][Rr][Ii][Ll]|[Pp][Rr])|([Uu][Gg][Uu][Ss][Tt]|[Uu][Gg]))\\b|\\b[Ff]([Ee][Bb][Rr][Uu][Aa][Rr][Yy]|[Ee][Bb])\\b/",
    isPumpable: false
  },
  {
    input: "/^[9]9\\d{10}|^[5]\\d{10}/",
    isPumpable: false
  },
  {
    input: "/^([01][012]|0[1-9])\\/([0-2][0-9]|[3][0-1])\\/([0-9][0-9][0-9][0-9])$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^(application|audio|example|image|message|model|multipart|text|video)\\/[a-zA-Z0-9]+([+.-][a-zA-z0-9]+)*$\\//",
    isPumpable: false
  },
  {
    input: "/(pwd|password)\\s*=\\s*(?<pwd>('(([^'])|(''))+'|[^';]+))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(23, 60)}"
  },
  {
    input: "/^((\\d{1,2})?([.][\\d]{1,2})?){1}[%]{1}$/",
    isPumpable: false
  },
  {
    input: "/^((0?[1-9]|1[012])(:[0-5]\\d){1,2}(\\ [AaPp][Mm]))$/",
    isPumpable: false
  },
  {
    input: "/(([2-9]{1})([0-9]{2})([0-9]{3})([0-9]{4}))$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{1,2}[0-9]{1,2}|[A-Z]{3}|[A-Z]{1,2}[0-9][A-Z])( |-)[0-9][A-Z]{2}/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{1}( |-)?[1-9]{1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^(F-)?((2[A|B])|[0-9]{2})[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^(V-|I-)?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}[0-9]{3} ?[A-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]{2}|[0-9][1-9]|[1-9][0-9])[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/((^([\\d]{1,3})(,{1}([\\d]{3}))*)|(^[\\d]*))((\\.{1}[\\d]{2})?$)/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?:04|06|09|11)\\/(?:(?:[012][0-9])|30))|(?:(?:(?:0[135789])|(?:1[02]))\\/(?:(?:[012][0-9])|30|31))|(?:02\\/(?:[012][0-9])))\\/(?:19|20|21)[0-9][0-9]/",
    isPumpable: false
  },
  {
    input: "/\\w?<\\s?\\/?[^\\s>]+(\\s+[^\"'=]+(=(\"[^\"]*\")|('[^\\']*')|([^\\s\"'>]*))?)*\\s*\\/?>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a<0",
    pumpable: "\\x09\\x090",
    suffix: ""
  },
  {
    input: "/(?<=^|[\\s ]+)[^\\!\\@\\%\\$\\s ]*([\\!\\@\\%\\$][^\\!\\@\\%\\$\\s ]*){2,}(?=[\\s ]+|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?n)^-?(\\d{1,8}(\\.\\d{1,2})?|\\d{0,8}(\\.\\d{1,2}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      "/(?'DateLiteral'\\#\\s*(?'DateOrTime'(?'DateValue'((?'Month'(0?[1-9])|1[0-2])(?'Sep'[-\\/])(?'Day'0?[1-9]|[12]\\d|3[01])\\k'Sep'(?'Year'\\d{1,4})\\s+(?'HourValue'(0?[1-9])|1[0-9]|2[0-4])[:](?'MinuteValue'0?[1-9]|[1-5]\\d|60)[:](?'SecondValue':0?[1-9]|[1-5]\\d|60)?\\s*(?'AMPM'[AP]M)?)|((?'Month'(0?[1-9])|1[0-2])(?'Sep'[-\\/])(?'Day'0?[1-9]|[12]\\d|3[01])\\k'Sep'(?'Year'\\d{4}))|((?'HourValue'(0?[1-9])|1[0-9]|2[0-4])[:](?'MinuteValue'0?[1-9]|[1-5]\\d|60)[:](?'SecondValue':0?[1-9]|[1-5]\\d|60)?\\s*(?'AMPM'[AP]M)?)))\\s*\\#)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 39)}"
  },
  {
    input: "/^ISBN\\s(?=[-0-9xX ]{13}$)(?:[0-9]+[- ]){3}[0-9]*[xX0-9]$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(7)}"
  },
  {
    input: "/(?s)\\/\\*.*\\*\\//",
    isPumpable: false
  },
  {
    input: "/(\\d{4,6})/",
    isPumpable: false
  },
  {
    input: "/^(\\d+|[a-zA-Z]+)$/",
    isPumpable: false
  },
  {
    input: "/.*?$(?<!\\.aspx)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: '/"([^"](?:\\\\.|[^\\\\"]*)*)"/',
    isPumpable: true,
    isVulnerable: true,
    prefix: '"!',
    pumpable: "!",
    suffix: ""
  },
  {
    input: "/(\\w[-._\\w]*\\w@\\w[-._\\w]*\\w\\.\\w{2,3})/",
    isPumpable: false
  },
  {
    input: '/^([a-zA-Z]\\:)(\\\\[^\\\\/:*?<>"|]*(?<![ ]))*(\\.[a-zA-Z]{2,6})$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(30)}"
  },
  {
    input: "/(\\b\\w+\\b)\\s+\\1/",
    isPumpable: false
  },
  {
    input:
      "/(?'openingTag'<)\\s*?(?'tagName'\\w+)(\\s*?(?>(?!=[\\/\\?]?>)(?'attribName'\\w+)(?:\\s*(?'attribSign'=)\\s*)(?'attribValue'(?:\\'[^\\']*\\'|\\\"[^\\\"]*\\\"|[^ >]+))))\\s*?(?'closeTag'[\\/\\?]?>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 39)}"
  },
  {
    input:
      "/(?n)^((?'allowDay'Sun|Mon|Fri)|(Sat(?'allowDay'ur(?=d))?)|(((T(ue?|h(ur?)?))|(Wed(ne(?=sd))?))((?<=(e|r))(?'allowDay's))?))((?(allowDay)day)|\\.)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input: "/^(100(?:\\.0{1,2})?|0*?\\.\\d{1,2}|\\d{1,2}(?:\\.\\d{1,2})?)%$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]\\d{2}(\\.\\d){0,1}$/",
    isPumpable: false
  },
  {
    input:
      "/^((NO)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{3}|(NO)[0-9A-Z]{15}|(BE)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}|(BE)[0-9A-Z]{16}|(DK|FO|FI|GL|NL)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{2}|(DK|FO|FI|GL|NL)[0-9A-Z]{18}|(MK|SI)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{3}|(MK|SI)[0-9A-Z]{19}|(BA|EE|KZ|LT|LU|AT)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}|(BA|EE|KZ|LT|LU|AT)[0-9A-Z]{20}|(HR|LI|LV|CH)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{1}|(HR|LI|LV|CH)[0-9A-Z]{21}|(BG|DE|IE|ME|RS|GB)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{2}|(BG|DE|IE|ME|RS|GB)[0-9A-Z]{22}|(GI|IL)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{3}|(GI|IL)[0-9A-Z]{23}|(AD|CZ|SA|RO|SK|ES|SE|TN)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}|(AD|CZ|SA|RO|SK|ES|SE|TN)[0-9A-Z]{24}|(PT)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{1}|(PT)[0-9A-Z]{25}|(IS|TR)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{2}|(IS|TR)[0-9A-Z]{26}|(FR|GR|IT|MC|SM)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{3}|(FR|GR|IT|MC|SM)[0-9A-Z]{27}|(AL|CY|HU|LB|PL)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}|(AL|CY|HU|LB|PL)[0-9A-Z]{28}|(MU)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{2}|(MU)[0-9A-Z]{30}|(MT)[0-9A-Z]{2}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{4}[ ][0-9A-Z]{3}|(MT)[0-9A-Z]{31})$/",
    isPumpable: false
  },
  {
    input: "/^(?<BeforeLastCapital>([^\\s]*))(?<LastCapital>[A-Z])(?<AfterLastCapital>([^A-Z])*)$   #Last Capital/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?:(?:(?:(?:[1-2][0-9]{3}) *(?:[\\/\\-\\., ]) *(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:[12][0-9]|3[01]|0?[1-9]))|(?:(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:[12][0-9]|3[01]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:[12][0-9]|3[01]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:(?i:(?:j(?:an(?:uary)?|u(?:ne?|ly?)))|a(?:pr(?:il)?|ug(?:ust)?)|ma(?:y|r(?:ch)?)|(?:nov|dec)(?:ember)?|feb(?:ruary)?|sep(?:tember)?|oct(?:ober)?)) *(?:[\\/\\-\\., ]) *(?:(?:[12][0-9]|3[01]|0?[1-9])|(?:(?i:[23]?1st|2?2nd|2?3rd|[4-9]th|1[0-9]th|20th|2[4-9]th|30th))) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:(?:[12][0-9]|3[01]|0?[1-9])|(?:(?i:[23]?1st|2?2nd|2?3rd|[4-9]th|1[0-9]th|20th|2[4-9]th|30th))) *(?:[\\/\\-\\., ]) *(?:(?i:(?:j(?:an(?:uary)?|u(?:ne?|ly?)))|a(?:pr(?:il)?|ug(?:ust)?)|ma(?:y|r(?:ch)?)|(?:nov|dec)(?:ember)?|feb(?:ruary)?|sep(?:tember)?|oct(?:ober)?)) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3}))))|(?:(?:(?:(?:[1-2][0-9]{3}) *(?:[\\/\\-\\., ]) *(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:[12][0-9]|3[01]|0?[1-9]))|(?:(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:[12][0-9]|3[01]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:[12][0-9]|3[01]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:1[0-2]|0?[1-9]) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:(?i:(?:j(?:an(?:uary)?|u(?:ne?|ly?)))|a(?:pr(?:il)?|ug(?:ust)?)|ma(?:y|r(?:ch)?)|(?:nov|dec)(?:ember)?|feb(?:ruary)?|sep(?:tember)?|oct(?:ober)?)) *(?:[\\/\\-\\., ]) *(?:(?:[12][0-9]|3[01]|0?[1-9])|(?:(?i:[23]?1st|2?2nd|2?3rd|[4-9]th|1[0-9]th|20th|2[4-9]th|30th))) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))|(?:(?:(?:[12][0-9]|3[01]|0?[1-9])|(?:(?i:[23]?1st|2?2nd|2?3rd|[4-9]th|1[0-9]th|20th|2[4-9]th|30th))) *(?:[\\/\\-\\., ]) *(?:(?i:(?:j(?:an(?:uary)?|u(?:ne?|ly?)))|a(?:pr(?:il)?|ug(?:ust)?)|ma(?:y|r(?:ch)?)|(?:nov|dec)(?:ember)?|feb(?:ruary)?|sep(?:tember)?|oct(?:ober)?)) *(?:[\\/\\-\\., ]) *(?:(?:[0-9]{1,2})|(?:[1-2][0-9]{3})))) *(?:(?:(?:1[0-2]|0?[1-9])(?: *(?:\\:) *(?:[1-5][0-9]|0?[0-9]))?(?: *(?:\\:) *(?:[1-5][0-9]|0?[0-9]))? *(?:(?i:[ap]m)))|(?:(?:2[0-3]|[01]?[0-9])(?: *(?:\\:) *(?:[1-5][0-9]|0?[0-9]))(?: *(?:\\:) *(?:[1-5][0-9]|0?[0-9]))?))))$/",
    isPumpable: false
  },
  {
    input:
      "/(?i:(?:j(?:an(?:uary)?|u(?:ne?|ly?)))|a(?:pr(?:il)?|ug(?:ust)?)|ma(?:y|r(?:ch)?)|(?:nov|dec)(?:ember)?|feb(?:ruary)?|sep(?:tember)?|oct(?:ober)?)/",
    isPumpable: false
  },
  {
    input: "/(?i:t(?:ue(?:sday)?|hu(?:rsday)?))|s(?:un(?:day)?|at(?:urday)?)|(?:wed(?:nesday)?|(?:mon|fri)(?:day)?)/",
    isPumpable: false
  },
  {
    input: "/^(?i)([À-ÿa-z\\-]{2,})\\x20([À-ÿa-z\\-']{2,})(?-i)/",
    wasParseError: "{ParsingData.NonAsciiInput(7, 195)}"
  },
  {
    input: "/^([0-1][0-9]|[2][0-3]|[0-9]):([0-5][0-9])(?::([0-5][0-9]))?$/",
    isPumpable: false
  },
  {
    input: "/^([0-2]\\d|3[0-1]|[1-9])\\/(0\\d|1[0-2]|[1-9])\\/(\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^(^[0-9]*(^[0-9]*[\\.][0-9]+){0,1}$)/",
    isPumpable: false
  },
  {
    input: '/(\'.*$|Rem((\\t| ).*$|$)|"(.|"")*?")/',
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^([1-9]|[1-9]\\d|100)$/",
    isPumpable: false
  },
  {
    input: "/^(X(-|\\.)?0?\\d{7}(-|\\.)?[A-Z]|[A-Z](-|\\.)?\\d{7}(-|\\.)?[0-9A-Z]|\\d{8}(-|\\.)?[A-Z])$/",
    isPumpable: false
  },
  {
    input: "/(^(?:\\w\\:)?(?:\\/|\\\\\\\\){1}[^\\/|\\\\]*(?:/|\\\\){1})/",
    isPumpable: false
  },
  {
    input: "/(.*[\\\\\\\\/]|^)(.*?)(?:[\\.]|$)([^\\.\\s]*$)/",
    isPumpable: false
  },
  {
    input: "/^(.){0,20}$/",
    isPumpable: false
  },
  {
    input: "/\\s(type|name|value)=(?:(\\w+)|(?:\"(.*?)\")|(?:\\'(.*)\\'))/",
    isPumpable: false
  },
  {
    input: '/^[^\\\\\\./:\\*\\?\\"<>\\|]{1}[^\\\\/:\\*\\?\\"<>\\|]{0,254}$/',
    isPumpable: false
  },
  {
    input:
      "/^((((0031)|(\\+31))(\\-)?6(\\-)?[0-9]{8})|(06(\\-)?[0-9]{8})|(((0031)|(\\+31))(\\-)?[1-9]{1}(([0-9](\\-)?[0-9]{7})|([0-9]{2}(\\-)?[0-9]{6})))|([0]{1}[1-9]{1}(([0-9](\\-)?[0-9]{7})|([0-9]{2}(\\-)?[0-9]{6}))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|[12]\\d|3[01])[\\s\\.\\-\\/](0[13578]|1[02])[\\s\\.\\-\\/]((19|[2-9]\\d)\\d{2}))|((0[1-9]|[12]\\d|30)[\\s\\.\\-\\/](0[13456789]|1[012])[\\s\\.\\-\\/]((19|[2-9]\\d)\\d{2}))|((0[1-9]|1\\d|2[0-8])[\\s\\.\\-\\/]02[\\s\\.\\-\\/]((19|[2-9]\\d)\\d{2}))|(29[\\s\\.\\-\\/]02[\\s\\.\\-\\/]((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))$/",
    isPumpable: false
  },
  {
    input: "/^(AT){0,1}[U]{0,1}[0-9]{8}$/",
    isPumpable: false
  },
  {
    input: "/^(BG){0,1}([0-9]{9}|[0-9]{10})$/",
    isPumpable: false
  },
  {
    input: "/^(-?)(,?)(\\d{1,3}(\\.\\d{3})*|(\\d+))(\\,\\d{2})?$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}[0-9]{3}\\s?[a-zA-Z]{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-1][0-9]|2[0-3]){1}:([0-5][0-9]){1}:([0-5][0-9]){1},([0-9][0-9][0-9]){1} --> ([0-1][0-9]|2[0-3]){1}:([0-5][0-9]){1}:([0-5][0-9]){1},([0-9][0-9][0-9]){1}(.*)$/",
    isPumpable: false
  },
  {
    input: "/^\\{([1-9]{1}|[1-9]{1}[0-9]{1,}){1}\\}\\{([1-9]{1}|[1-9]{1}[0-9]{1,}){1}\\}(.*)$/",
    isPumpable: false
  },
  {
    input:
      "/^(A(D|E|F|G|I|L|M|N|O|R|S|T|Q|U|W|X|Z)|B(A|B|D|E|F|G|H|I|J|L|M|N|O|R|S|T|V|W|Y|Z)|C(A|C|D|F|G|H|I|K|L|M|N|O|R|U|V|X|Y|Z)|D(E|J|K|M|O|Z)|E(C|E|G|H|R|S|T)|F(I|J|K|M|O|R)|G(A|B|D|E|F|G|H|I|L|M|N|P|Q|R|S|T|U|W|Y)|H(K|M|N|R|T|U)|I(D|E|Q|L|M|N|O|R|S|T)|J(E|M|O|P)|K(E|G|H|I|M|N|P|R|W|Y|Z)|L(A|B|C|I|K|R|S|T|U|V|Y)|M(A|C|D|E|F|G|H|K|L|M|N|O|Q|P|R|S|T|U|V|W|X|Y|Z)|N(A|C|E|F|G|I|L|O|P|R|U|Z)|OM|P(A|E|F|G|H|K|L|M|N|R|S|T|W|Y)|QA|R(E|O|S|U|W)|S(A|B|C|D|E|G|H|I|J|K|L|M|N|O|R|T|V|Y|Z)|T(C|D|F|G|H|J|K|L|M|N|O|R|T|V|W|Z)|U(A|G|M|S|Y|Z)|V(A|C|E|G|I|N|U)|W(F|S)|Y(E|T)|Z(A|M|W))$/",
    isPumpable: false
  },
  {
    input:
      "/^(A(BW|FG|GO|IA|L(A|B)|N(D|T)|R(E|G|M)|SM|T(A|F|G)|U(S|T)|ZE)|B(DI|E(L|N)|FA|G(D|R)|H(R|S)|IH|L(M|R|Z)|MU|OL|R(A|B|N)|TN|VT|WA)|C(A(F|N)|CK|H(E|L|N)|IV|MR|O(D|G|K|L|M)|PV|RI|UB|XR|Y(M|P)|ZE)|D(EU|JI|MA|NK|OM|ZA)|E(CU|GY|RI|S(H|P|T)|TH)|F(IN|JI|LK|R(A|O)|SM)|G(AB|BR|EO|GY|HA|I(B|N)|LP|MB|NQ|NB|R(C|D|L)|TM|U(F|M|Y))|H(KG|MD|ND|RV|TI|UN)|I(DN|MN|ND|OT|R(L|N|Q)|S(L|R)|TA)|J(AM|EY|OR|PN)|K(AZ|EN|GZ|HM|IR|NA|OR|WT)|L(AO|B(N|R|Y)|CA|IE|KA|SO|TU|UX|VA)|M(A(C|F|R)|CO|D(A|G|V)|EX|HL|KD|L(I|T)|MR|N(E|G|P)|OZ|RT|SR|TQ|US|WI|Y(S|T))|N(AM|CL|ER|FK|GA|I(C|U)|LD|OR|PL|RU|ZL)|OMN|P(A(K|N)|CN|ER|HL|LW|NG|OL|R(I|K|T|Y)|SE|YF)|QAT|R(EU|OU|US|WA)|S(AU|DN|EN|G(P|S)|HN|JM|L(B|E|V)|MR|OM|PM|RB|TP|UR|V(K|N)|W(E|Z)|Y(C|R))|T(C(A|D)|GO|HA|JK|K(L|M)|LS|ON|TO|U(N|R|V)|WN|ZA)|U(EN|GA|KR|MI|RY|SA|ZB)|V(AT|CT|GB|IR|NM|UT)|W(LF|SM)|YEM|Z(AF|MB|WE))$/",
    isPumpable: false
  },
  {
    input:
      "/^(0(0(4|8)|1(0|2|6)|2(0|4|8)|3(1|2|6)|4(0|4|8)|5(0|1|2|6)|6(0|4|8)|7(0|2|4|6)|8(4|6)|9(0|2|6))|1(0(0|4|8)|1(2|6)|2(0|4)|3(2|6)|4(0|4|8)|5(2|6)|6(2|6)|7(0|4|5|8)|8(0|4|8)|9(1|2|6))|2(0(3|4|8)|1(2|4|8)|2(2|6)|3(1|2|3|4|8|9)|4(2|4|8)|5(0|4|8)|6(0|2|6|8)|7(0|5|6)|88|9(2|6))|3(0(0|4|8)|1(2|6)|2(0|4|8)|3(2|4|6)|4(0|4|8)|5(2|6)|6(0|4|8)|7(2|6)|8(0|4|8|9)|92)|4(0(0|4|8)|1(0|4|7|8)|2(2|6|8)|3(0|4|8)|4(0|2|6)|5(0|4|8)|6(2|6)|7(0|4|8)|8(0|4)|9(2|6|8|9))|5(0(0|4|8)|1(2|6)|2(0|4|8)|3(0|3)|4(0|8)|5(4|8)|6(2|6)|7(0|4|8)|8(0|1|3|4|5|6)|9(1|8))|6(0(0|4|8)|1(2|6)|2(0|4|6)|3(0|4|8)|4(2|3|6)|5(2|4|9)|6(0|2|3|6)|7(0|4|8)|8(2|6|8)|9(0|4))|7(0(2|3|4|5|6)|1(0|6)|24|3(2|6)|4(0|4|8)|5(2|6)|6(0|4|8)|7(2|6)|8(0|4|8)|9(2|5|6|8))|8(0(0|4|7)|26|3(1|2|3|4)|40|5(0|8)|6(0|2)|76|8(2|7)|94))$/",
    isPumpable: false
  },
  {
    input: "/^<\\!\\-\\-(.*)+(\\/){0,1}\\-\\->$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<!--",
    pumpable: "0",
    suffix: ""
  },
  {
    input:
      "/^([1-9]{1}|[1-9]{1}[0-9]{1,3}|[1-5]{1}[0-9]{4}|6[0-4]{1}[0-9]{3}|65[0-4]{1}[0-9]{2}|655[0-2]{1}[0-9]{1}|6553[0-6]{1})$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\#]{0,1}([a-fA-F0-9]{6}|[a-fA-F0-9]{3})|rgb\\(([0-9]{1},|[1-9]{1}[0-9]{1},|[1]{1}[0-9]{2},|[2]{1}[0-4]{1}[0-9]{1},|25[0-5]{1},){2}([0-9]{1}|[1-9]{1}[0-9]{1}|[1]{1}[0-9]{2}|[2]{1}[0-4]{1}[0-9]{1}|25[0-5]{1}){1}\\)|rgb\\(([0-9]{1}%,|[1-9]{1}[0-9]{1}%,|100%,){2}([0-9]{1}%|[1-9]{1}[0-9]{1}%|100%){1}\\))$/",
    isPumpable: false
  },
  {
    input:
      "/^(0|(([1-9]{1}|[1-9]{1}[0-9]{1}|[1-9]{1}[0-9]{2}){1}(\\ [0-9]{3}){0,})),(([0-9]{2})|\\-\\-)([\\ ]{1})(€|EUR|EURO){1}$/",
    wasParseError: "{ParsingData.NonAsciiInput(98, 226)}"
  },
  {
    input:
      "/^(big5|euc(kr|jpms)|binary|greek|tis620|hebrew|ascii|swe7|koi8(r|u)|(u|keyb)cs2|(dec|hp|utf|geostd|armscii)8|gb(k|2312)|cp(8(5(0|2)|66)|932|125(0|1|6|7))|latin(1|2|5|7)|(u|s)jis|mac(ce|roman))$/",
    isPumpable: false
  },
  {
    input:
      "/^((ucs2|utf8)\\_(bin|(general|unicode|roman|slovak|czech|icelandic|(latv|pers)ian|(dan|pol|span|swed|turk)ish|spanish2|(esto|lithua|roma|slove)nian\\_ci)))|((mac(ce|roman)|cp(8(5(0|2)|66)|1256)|armscii8|geostd8|ascii|keybcs2|greek|hebrew|koi8(r|u))\\_(bin|general\\_ci))|((dec8|swe7)\\_(bin|swedish\\_ci))|((hp8|latin5)\\_(bin|english\\_ci))|((big5|gb(2312|k))\\_(bin|chinese\\_ci))|((cp932|eucjpms|(s|u)jis)\\_(bin|japanese\\_ci))|(euckr\\_(bin|korean\\_ci))|(tis620\\_(bin|thai\\_ci))|(latin1\\_(bin|(((dan|span|swed)ish|german(1|2))\\_ci)|general\\_(ci|cs)))|(cp1250\\_(bin|czech\\_cs|general\\_ci))|(latin2\\_(bin|czech\\_cs|(general|hungarian|croatian)\\_ci))|(cp1257\\_(bin|(general|lithuanian)\\_ci))|(latin7\\_(bin|general\\_(c(i|s))|estonian\\_cs))|(cp1251\\_(bin|(general|bulgarian|ukrainian)\\_ci|general\\_cs))$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z]{2})([0-9]{6}))$/",
    isPumpable: false
  },
  {
    input: "/^(([0-9]{5})|([0-9]{3}[ ]{0,1}[0-9]{2}))$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-9]{2})(01|02|03|04|05|06|07|08|09|10|11|12|51|52|53|54|55|56|57|58|59|60|61|62)(([0]{1}[1-9]{1})|([1-2]{1}[0-9]{1})|([3]{1}[0-1]{1}))\\/([0-9]{3,4})$/",
    isPumpable: false
  },
  {
    input: "/^([0-7]{3})$/",
    isPumpable: false
  },
  {
    input: "/^([0]{0,1}[0-7]{3})$/",
    isPumpable: false
  },
  {
    input: "/^((\\-|d|l|p|s){1}(\\-|r|w|x){9})$/",
    isPumpable: false
  },
  {
    input:
      "/^(((([\\*]{1}){1})|((\\*\\/){0,1}(([0-9]{1}){1}|(([1-5]{1}){1}([0-9]{1}){1}){1}))) ((([\\*]{1}){1})|((\\*\\/){0,1}(([0-9]{1}){1}|(([1]{1}){1}([0-9]{1}){1}){1}|([2]{1}){1}([0-3]{1}){1}))) ((([\\*]{1}){1})|((\\*\\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))) ((([\\*]{1}){1})|((\\*\\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))|(jan|feb|mar|apr|may|jun|jul|aug|sep|okt|nov|dec)) ((([\\*]{1}){1})|((\\*\\/){0,1}(([0-7]{1}){1}))|(sun|mon|tue|wed|thu|fri|sat)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(B(A|B|C|J|L|N|R|S|Y)|CA|D(K|S|T)|G(A|L)|H(C|E)|IL|K(A|I|E|K|M|N|S)|L(E|C|M|V)|M(A|I|L|T|Y)|N(I|O|M|R|Z)|P(B|D|E|O|K|N|P|T|U|V)|R(A|K|S|V)|S(A|B|C|E|I|K|L|O|N|P|V)|T(A|C|N|O|R|S|T|V)|V(K|T)|Z(A|C|H|I|M|V))([ ]{0,1})([0-9]{3})([A-Z]{2})$/",
    isPumpable: false
  },
  {
    input: "/^([a-hA-H]{1}[1-8]{1})$/",
    isPumpable: false
  },
  {
    input:
      "/^(([0]{0,1})([1-9]{1})([0-9]{2})){1}([\\ ]{0,1})((([0-9]{3})([\\ ]{0,1})([0-9]{3}))|(([0-9]{2})([\\ ]{0,1})([0-9]{2})([\\ ]{0,1})([0-9]{2})))$/",
    isPumpable: false
  },
  {
    input:
      '/(?<attributeName>\\w+?)=(\\"+(?<attributeValue>[\\w\\.\\s\\:\\;\\/\\\\@\\-\\=\\&\\?]*)\\"+|(?<attributeValue>[\\w\\.\\:\\;\\/\\\\@\\-\\=\\&\\?]*)?)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^\\s*(((\\d*\\.?\\d*[0-9]+\\d*)|([0-9]+\\d*\\.\\d*) )\\s*[xX]\\s*){2}((\\d*\\.?\\d*[0-9]+\\d*)|([0-9]+\\d*\\.\\d*))\\s*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]+$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-z])([a-z0-9]{8,25})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^(((\\d|([a-f]|[A-F])){2}:){5}(\\d|([a-f]|[A-F])){2})$|^(((\\d|([a-f]|[A-F])){2}-){5}(\\d|([a-f]|[A-F])){2})$|^$/",
    isPumpable: false
  },
  {
    input: "/^((0?[1-9])|((1)[0-1]))?((\\.[0-9]{0,2})?|0(\\.[0-9]{0,2}))$/",
    isPumpable: false
  },
  {
    input: "/\\b((?:0[1-46-9]\\d{3})|(?:[1-357-9]\\d{4})|(?:[4][0-24-9]\\d{3})|(?:[6][013-9]\\d{3}))\\b/",
    isPumpable: false
  },
  {
    input: "/^([A-Z\\d]{3})[A-Z]{2}\\d{2}([A-Z\\d]{1})([X\\d]{1})([A-Z\\d]{3})\\d{5}$/",
    isPumpable: false
  },
  {
    input: "/(?!^[0-9]*$)(?!^[a-zA-Z]*$)^([a-zA-Z0-9]{8,10})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/\\w+[\\w-\\.]*\\@\\w+((-\\w+)|(\\w*))\\.[a-z]{2,3}$|^([0-9a-zA-Z'\\.]{3,40})\\*|([0-9a-zA-Z'\\.]+)@([0-9a-zA-Z']+)\\.([0-9a-zA-Z']+)$|([0-9a-zA-Z'\\.]+)@([0-9a-zA-Z']+)\\*+$|^$/",
    isPumpable: false
  },
  {
    input: "/([*,1-9]:[1-9]){1}(,([*,1-9]:[1-9]){0,}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[+-]?[0-9]*\\.?([0-9]?)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/background-image.[^<]*?;/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\s.\\-_']+$/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?<scheme>[a-zA-Z]+):\\/\\/)?(?<domain>(?:[0-9a-zA-Z\\-_]+(?:[.][0-9a-zA-Z\\-_]+)*))(?::(?<port>[0-9]+))?(?<path>(?:\\/[0-9a-zA-Z\\-_.]+)+)(?:[?](?<query>.+))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input: "/<(\\/{0,1})img(.*?)(\\/{0,1})\\>/",
    isPumpable: false
  },
  {
    input: "/[A-Z0-9]{5}\\d[0156]\\d([0][1-9]|[12]\\d|3[01])\\d[A-Z0-9]{3}[A-Z]{2}/",
    isPumpable: false
  },
  {
    input:
      "/^(\\+[1-9]\\d+) ([1-9]\\d+) ([1-9]\\d+)(\\-\\d+){0,1}$|^(0\\d+) ([1-9]\\d+)(\\-\\d+){0,1}$|^([1-9]\\d+)(\\-\\d+){0,1}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1,3}\\[([0-9]{1,3})\\]/",
    isPumpable: false
  },
  {
    input: "/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9._-]+)/",
    isPumpable: false
  },
  {
    input: "/.*-[0-9]{1,10}.*/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}(-\\d{3})?$/",
    isPumpable: false
  },
  {
    input: "/^[A-ZÄÖÜ]{1,3}\\-[ ]{0,1}[A-Z]{0,2}[0-9]{1,4}[H]{0,1}/",
    wasParseError: "{ParsingData.NonAsciiInput(5, 195)}"
  },
  {
    input: "/^[1-9]+\\d*\\.\\d{2}$/",
    isPumpable: false
  },
  {
    input: "/(\\s+|)((\\(\\d{3}\\) +)|(\\d{3}-)|(\\d{3} +))?\\d{3}(-| +)\\d{4}( +x\\d{1,4})?(\\s+|)/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\.([A-Za-z0-9]{2,5}($|\\b\\?))/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:Data Source)|(?:Server))=([\\w\\.]+?);\\s*?(?:(?:Initial Catalog)|(?:Database))=(\\w+?);\\s*?(?:(?:User Id)|(?:Uid))=(\\w+?);\\s*?(?:(?:Password)|(?:Pwd))=(\\w*?);.*/",
    isPumpable: false
  },
  {
    input:
      "/Server=([\\w\\.]+?);\\s*?(?:Port=(\\d+?);\\s*?)?Database=(\\w+?);\\s*?(?:(?:User)|(?:Uid))=(\\w+?);\\s*?(?:(?:Password)|(?:Pwd))=(\\w*?);.*/",
    isPumpable: false
  },
  {
    input: "/^(\\d{0,4}(?:\\.\\d{0,2})?|[-]\\d{0,2}(?:\\.\\d{0,2})?)[%]{0,1}$/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)\\,?\\s+((?:(?:\\d+(?:\\x20+\\w+\\.?)+(?:(?:\\x20+STREET|ST|DRIVE|DR|AVENUE|AVE|ROAD|RD|LOOP|COURT|CT|CIRCLE|LANE|LN|BOULEVARD|BLVD)\\.?)?)|(?:(?:P\\.\\x20?O\\.|P\\x20?O)\\x20*Box\\x20+\\d+)|(?:General\\x20+Delivery)|(?:C[\\\\\\\\/]O\\x20+(?:\\w+\\x20*)+))\\,?\\x20*(?:(?:(?:APT|BLDG|DEPT|FL|HNGR|LOT|PIER|RM|S(?:LIP|PC|T(?:E|OP))|TRLR|UNIT|\\x23)\\.?\\x20*(?:[a-zA-Z0-9\\-]+))|(?:BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR))?)?\\,?\\s+((?:[A-Za-z]+\\x20*)+)\\,\\s+(A[BLKSZRAP]|BC|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADLN]|K[SY]|LA|M[ABDEHINOPST]|N[BCDEHJLMSTUVY]|O[HKRN]|P[AERW]|QC|RI|S[CDK]|T[NX]|UT|V[AIT]|W[AIVY]|YT)\\s+((\\d{5}-\\d{4})|(\\d{5})|([AaBbCcEeGgHhJjKkLlMmNnPpRrSsTtVvXxYy]\\d[A-Za-z]\\s?\\d[A-Za-z]\\d))\\s*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0 aS.  V",
    pumpable: "VV",
    suffix: ""
  },
  {
    input: "/\\b[1-9]{1}[0-9]{1,5}-\\d{2}-\\d\\b/",
    isPumpable: false
  },
  {
    input:
      "/^(([0-2]\\d|[3][0-1])\\/([0]\\d|[1][0-2])\\/[2][0]\\d{2})$|^(([0-2]\\d|[3][0-1])\\/([0]\\d|[1][0-2])\\/[2][0]\\d{2}\\s00\\:00\\:00)$/",
    isPumpable: false
  },
  {
    input: "/^[-\\w\\s\"'=/!@#%&,;:`~\\.\\$\\^\\{\\[\\(\\|\\)\\]\\}\\*\\+\\?\\\\]*$/",
    isPumpable: false
  },
  {
    input:
      "/^(GB)?(\\ )?[0-9]\\d{2}(\\ )?[0-9]\\d{3}(\\ )?(0[0-9]|[1-8][0-9]|9[0-6])(\\ )?([0-9]\\d{2})?|(GB)?(\\ )?GD(\\ )?([0-4][0-9][0-9])|(GB)?(\\ )?HA(\\ )?([5-9][0-9][0-9])$/",
    isPumpable: false
  },
  {
    input:
      "/^((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*);|(0|[1-9]+[0-9]*);)*?((0|[1-9]+[0-9]*)-(0|[1-9]+[0-9]*)|(0|[1-9]+[0-9]*)){1}$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "11;",
    suffix: ""
  },
  {
    input:
      "/^(((?!\\(800\\))(?!\\(888\\))(?!\\(877\\))(?!\\(866\\))(?!\\(900\\))\\(\\d{3}\\) ?)|(?!800)(?!888)(?!877)(?!866)(?!900)(\\d{3}-))?\\d{3}-\\d{4}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input: "/^\\W{0,5}[Rr]e:\\W[a-zA-Z0-9]{1,10},\\W[a-z]{1,10}\\W[a-z]{1,10}\\W[a-z]{1,10}/",
    isPumpable: false
  },
  {
    input: "/^\\d*\\.?((25)|(50)|(5)|(75)|(0)|(00))?$/",
    isPumpable: false
  },
  {
    input: "/(0?[1-9]|[12][0-9]|3[01])[.](0?[1-9]|1[012])[.]\\d{4}/",
    isPumpable: false
  },
  {
    input:
      "/^(([^,\\n]+),([^,\\n]+),([^@]+)@([^\\.]+)\\.([^,\\n]+)\\n)+([^,\\n]+),([^,\\n]+),([^@]+)@([^\\.]+)\\.([^,\\n]+)\\n?$/",
    isPumpable: false
  },
  {
    input: "/^(3276[0-7]|327[0-5]\\d|32[0-6]\\d{2}|3[01]\\d{3}|[12]\\d{4}|[1-9]\\d{3}|[1-9]\\d{2}|[1-9]\\d|\\d)$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]\\d*\\.?[0]*$/",
    isPumpable: false
  },
  {
    input:
      "/href=[\\\"\\'](http:\\/\\/|\\.\\/|\\/)?\\w+(\\.\\w+)*(\\/\\w+(\\.\\w+)?)*(\\/|\\?\\w*=\\w*(&\\w*=\\w*)*)?[\\\"\\']/",
    isPumpable: false
  },
  {
    input:
      "/(?<O>(?<d>[BEGLMNS]|A[BL]|B[ABDHLNRST]|C[ABFHMORTVW]|D[ADEGHLNTY]|E[HNX]|F[KY]|G[LUY]|H[ADGPRSUX]|I[GMPV]|JE|K[ATWY]|L[ADELNSU]|M[EKL]|N[EGNPRW]|O[LX]|P[AEHLOR]|R[GHM]|S[AEGKL-PRSTWY]|T[ADFNQRSW]|UB|W[ADFNRSV]|YO|ZE)(?<a>\\d\\d?)|(?<d>E)(?<a>\\dW)|(?<d>EC)(?<a>\\d[AMNPRVY0])|(?<d>N)(?<a>\\dP)|(?<d>NW)(?<a>\\dW)|(?<d>SE)(?<a>\\dP)|(?<d>SW)(?<a>\\d[AEHPVWXY])|(?<d>W)(?<a>1[0-4A-DFGHJKSTUW])|(?<d>W)(?<a>[2-9])|(?<d>WC)(?<a>[12][ABEHNRVX]))\\ (?<I>(?<s>\\d)(?<u>[ABD-HJLNP-UW-Z]{2}))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^(3[0-1]|2[0-9]|1[0-9]|0[1-9])[\\/](Jan|JAN|Feb|FEB|Mar|MAR|Apr|APR|May|MAY|Jun|JUN|Jul|JUL|Aug|AUG|Sep|SEP|Oct|OCT|Nov|NOV|Dec|DEC)[\\/]\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(?=^.{8,15}$)((?!.*\\s)(?=.*[A-Z])(?=.*[a-z])(?=(.*\\d){1,}))((?!.*[\",;&|'])|(?=(.*\\W){1,}))(?!.*[\",;&|'])^.*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(CREATE|ALTER) +(PROCEDURE|PROC|FUNCTION|VIEW) *(\\[(.*)\\]|(.*))/",
    isPumpable: false
  },
  {
    input: "/^([^:])+\\\\.([^:])+$/",
    isPumpable: false
  },
  {
    input: '/"[^"]+"/',
    isPumpable: false
  },
  {
    input:
      "/^(00[1-9]|0[1-9][0-9]|[1-7][0-9][0-9]|7[0-7][0-2]|77[0-2])(\\d{6})(A|B([1-9]?|[ADGHJKLNPQRTWY])|C([1-9]|[A-Z])|D([1-9]?|[ACDGHJKLMNPQRSTVWXYZ])|E([1-9]?|[ABCDFGHJKM])|F([1-8])|J([1-4])|K([1-9]|[ABCDEFGHJLM])|T([ABCDEFGHJKLMNPQRSTUVWXYZ2]?)|M|W([1-9]?|[BCFGJRT]))$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[A-Z])(?=.*[a-z])(?=.*[\\d])(?=.*[-\\]\\\\`~!@#$%^&*()_=+}{[|'\";:><,.?/ ]).{8,50}$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/(?<local1300>^1300[ |\\-]{0,1}\\d{3}[ |\\-]{0,1}\\d{3}$)|(?<tollcall>^1900|1902[ |\\-]{0,1}\\d{3}[ |\\-]{0,1}\\d{3}$)|(?<freecall>^1800[ |\\-]{0,1}\\d{3}[ |\\-]{0,1}\\d{3}$)|(?<standard>^\\({0,1}0[2|3|7|8]{1}\\){0,1}[ \\-]{0,1}\\d{4}[ |\\-]{0,1}\\d{4}$)|(?<international>^\\+61[ |\\-]{0,1}[2|3|7|8]{1}[ |\\-]{0,1}[0-9]{4}[ |\\-]{0,1}[0-9]{4}$)|(?<local13>^13\\d{4}$)|(?<mobile>^04\\d{2,3}\\d{6}$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^ *(([\\.\\-\\+\\w]{2,}[a-z0-9])@([\\.\\-\\w]+[a-z0-9])\\.([a-z]{2,3})) *(; *(([\\.\\-\\+\\w]{2,}[a-z0-9])@([\\.\\-\\w]+[a-z0-9])\\.([a-z]{2,3})) *)* *$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0[1-9]|[1-2][0-9]|3[0-1])[.\\/-](0[13578]|10|12))|((0[1-9]|[1-2][0-9])[.\\/-](02))|(((0[1-9])|([1-2][0-9])|(30))[.\\/-](0[469]|11)))[.\\/-]((19\\d{2})|(2[012]\\d{2})))$/",
    isPumpable: false
  },
  {
    input: "/^(s-|S-){0,1}[0-9]{3}\\s?[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{1}$|^[1-6]{1}[0-3]{1}$|^64$|\\-[1-9]{1}$|^\\-[1-6]{1}[0-3]{1}$|^\\-64$/",
    isPumpable: false
  },
  {
    input:
      "/([0-9]* {0,2}[A-Z]{1}\\w+[,.;:]? {0,4}[xvilcXVILC\\d]+[.,;:]( {0,2}[\\d-,]{1,7})+)([,.;:] {0,4}[xvilcXVILC]*[.,;:]( {0,2}[\\d-,]{1,7})+)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^((?:\\+27|27)|0)(=72|82|73|83|74|84)(\\d{7})$/",
    isPumpable: false
  },
  {
    input:
      "/^[A-Z0-9a-z'&()\\/]{0,1}[A-Z0-9a-z'&()\\/]{0,1}(([A-Z0-9a-z'&()\\/_-])|(\\\\s)){0,47}[A-Z0-9a-z'&()/]{1}$/",
    isPumpable: false
  },
  {
    input: "/(\\d+(-\\d+)*)+(,\\d+(-\\d+)*)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/([A-Zäöü0-9\\/][^a-z\\:\\,\\(\\)]*[A-Zäöü0-9])($|[\\.\\:\\,\\;\\)\\-\\ \\+]|s\\b)/",
    wasParseError: "{ParsingData.NonAsciiInput(5, 195)}"
  },
  {
    input: "/^04[0-9]{8}/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1,3}'(\\d{3}')*\\d{3}(\\.\\d{1,3})?|\\d{1,3}(\\.\\d{3})?)$/",
    isPumpable: false
  },
  {
    input:
      "/^((0?[1-9]|[12][1-9]|3[01])\\.(0?[13578]|1[02])\\.20[0-9]{2}|(0?[1-9]|[12][1-9]|30)\\.(0?[13456789]|1[012])\\.20[0-9]{2}|(0?[1-9]|1[1-9]|2[0-8])\\.(0?[123456789]|1[012])\\.20[0-9]{2}|(0?[1-9]|[12][1-9])\\.(0?[123456789]|1[012])\\.20(00|04|08|12|16|20|24|28|32|36|40|44|48|52|56|60|64|68|72|76|80|84|88|92|96))$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w ]*.*))+\\.(txt|TXT)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\0",
    pumpable: "\\0\\0",
    suffix: ""
  },
  {
    input: "/^[0-9]{6}/",
    isPumpable: false
  },
  {
    input: "/\\xA9/",
    wasParseError: "{ParsingData.NonAsciiInput(0, 169)}"
  },
  {
    input: "/\\u2122/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/\\u00AE/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/\\u00A3/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/\\u20AC/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/\\u00A5/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/\\u221E/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 117)}"
  },
  {
    input: "/^(([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w ]*.*))+\\.(jpg|JPG)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\0",
    pumpable: "\\0\\0",
    suffix: ""
  },
  {
    input: "/(?<=<\\w+ )(\\w+-*\\w*=[^>]+\\s?)(?=>)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[\\u0410-\\u042F\\u0430-\\u044F]+/",
    wasParseError: "{ParsingData.UnsupportedEscape(2, 117)}"
  },
  {
    input:
      "/^\\(?(?:(?:0(?:0|11)\\)?[\\s-]?\\(?|\\+)44\\)?[\\s-]?\\(?(?:0\\)?[\\s-]?\\(?)?|0)(?:\\d{2}\\)?[\\s-]?\\d{4}[\\s-]?\\d{4}|\\d{3}\\)?[\\s-]?\\d{3}[\\s-]?\\d{3,4}|\\d{4}\\)?[\\s-]?(?:\\d{5}|\\d{3}[\\s-]?\\d{3})|\\d{5}\\)?[\\s-]?\\d{4,5}|8(?:00[\\s-]?11[\\s-]?11|45[\\s-]?46[\\s-]?4\\d))(?:(?:[\\s-]?(?:x|ext\\.?\\s?|\\#)\\d+)?)$/",
    isPumpable: false
  },
  {
    input:
      "/^\\(?(?:(?:0(?:0|11)\\)?[\\s-]?\\(?|\\+)(44)\\)?[\\s-]?\\(?(?:0\\)?[\\s-]?\\(?)?|0)([1-9]\\d{1,4}\\)?[\\s\\d-]+)(?:((?:x|ext\\.?\\s?|\\#)\\d+)?)$/",
    isPumpable: false
  },
  {
    input:
      "/^((1[1-9]|2[03489]|3[0347]|5[56]|7[04-9]|8[047]|9[018])\\d{8}|(1[2-9]\\d|[58]00)\\d{6}|8(001111|45464\\d))$/",
    isPumpable: false
  },
  {
    input:
      "/^(2(?:0[01378]|3[0189]|4[017]|8[0-46-9]|9[012])\\d{7}|1(?:(?:1(?:3[0-48]|[46][0-4]|5[012789]|7[0-49]|8[01349])|21[0-7]|31[0-8]|[459]1\\d|61[0-46-9]))\\d{6}|1(?:2(?:0[024-9]|2[3-9]|3[3-79]|4[1-689]|[58][02-9]|6[0-4789]|7[013-9]|9\\d)|3(?:0\\d|[25][02-9]|3[02-579]|[468][0-46-9]|7[1235679]|9[24578])|4(?:0[03-9]|2[02-5789]|[37]\\d|4[02-69]|5[0-8]|[69][0-79]|8[0-5789])|5(?:0[1235-9]|2[024-9]|3[0145689]|4[02-9]|5[03-9]|6\\d|7[0-35-9]|8[0-468]|9[0-5789])|6(?:0[034689]|2[0-689]|[38][013-9]|4[1-467]|5[0-69]|6[13-9]|7[0-8]|9[0124578])|7(?:0[0246-9]|2\\d|3[023678]|4[03-9]|5[0-46-9]|6[013-9]|7[0-35-9]|8[024-9]|9[02-9])|8(?:0[35-9]|2[1-5789]|3[02-578]|4[0-578]|5[124-9]|6[2-69]|7\\d|8[02-9]|9[02569])|9(?:0[02-589]|2[02-689]|3[1-5789]|4[2-9]|5[0-579]|6[234789]|7[0124578]|8\\d|9[2-57]))\\d{6}|1(?:2(?:0(?:46[1-4]|87[2-9])|545[1-79]|76(?:2\\d|3[1-8]|6[1-6])|9(?:7(?:2[0-4]|3[2-5])|8(?:2[2-8]|7[0-4789]|8[345])))|3(?:638[2-5]|647[23]|8(?:47[04-9]|64[015789]))|4(?:044[1-7]|20(?:2[23]|8\\d)|6(?:0(?:30|5[2-57]|6[1-8]|7[2-8])|140)|8(?:052|87[123]))|5(?:24(?:3[2-79]|6\\d)|276\\d|6(?:26[06-9]|686))|6(?:06(?:4\\d|7[4-79])|295[567]|35[34]\\d|47(?:24|61)|59(?:5[08]|6[67]|74)|955[0-4])|7(?:26(?:6[13-9]|7[0-7])|442\\d|50(?:2[0-3]|[3-68]2|76))|8(?:27[56]\\d|37(?:5[2-5]|8[239])|84(?:3[2-58]))|9(?:0(?:0(?:6[1-8]|85)|52\\d)|3583|4(?:66[1-8]|9(?:2[01]|81))|63(?:23|3[1-4])|9561))\\d{3}|176888[234678]\\d{2}|16977[23]\\d{3})|7(?:[1-4]\\d\\d|5(?:0[0-8]|[13-9]\\d|2[0-35-9])|624|7(?:0[1-9]|[1-7]\\d|8[02-9]|9[0-689])|8(?:[014-9]\\d|[23][0-8])|9(?:[04-9]\\d|1[02-9]|2[0-35-9]|3[0-689]))\\d{6}|76(?:0[012]|2[356]|4[0134]|5[49]|6[0-369]|77|81|9[39])\\d{6}|80(?:0(?:1111|\\d{6,7})|8\\d{7})|500\\d{6}|87[123]|9(?:[01]\\d|8[0-3]))\\d{7}|8(?:4(?:5464\\d|[2-5]\\d{7})|70\\d{7})|70\\d{8}|56\\d{8}|3[0347]|55)\\d{8}$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[a-zA-Z0-9._-]+$/",
    isPumpable: false
  },
  {
    input:
      "/^([Aa][LKSZRAEPlkszraep]|[Cc][AOTaot]|[Dd][ECec]|[Ff][LMlm]|[Gg][AUau]|HI|hi|[Ii][ADLNadln]|[Kk][SYsy]|LA|la|[Mm][ADEHINOPSTadehinopst]|[Nn][CDEHJMVYcdehjmvy]|[Oo][HKRhkr]|[Pp][ARWarw]|RI|ri|[Ss][CDcd]|[Tt][NXnx]|UT|ut|[Vv][AITait]|[Ww][AIVYaivy])$/",
    isPumpable: false
  },
  {
    input:
      "/^((31(?! (FEB|APR|JUN|SEP|NOV)))|((30|29)(?! FEB))|(29(?= FEB (((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])-(JAN|FEB|MAR|MAY|APR|JUL|JUN|AUG|OCT|SEP|NOV|DEC)-((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^((31(?! (FEB|APR|JUN|SEP|NOV)))|(30|29)|(0[1-9])|1\\d|2[0-8]) (JAN|FEB|MAR|MAY|APR|JUL|JUN|AUG|OCT|SEP|NOV|DEC)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^((31(?! (FEB|APR|JUN|SEP|NOV)))|((30|29)(?! FEB))|(29(?= FEB (((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8]) (JAN|FEB|MAR|MAY|APR|JUL|JUN|AUG|OCT|SEP|NOV|DEC) ((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^(\\+?)(\\d{2,4})(\\s?)(\\-?)((\\(0\\))?)(\\s?)(\\d{2})(\\s?)(\\-?)(\\d{3})(\\s?)(\\-?)(\\d{2})(\\s?)(\\-?)(\\d{2})/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*\\(?(020[7,8]{1}\\)?[ ]?[1-9]{1}[0-9{2}[ ]?[0-9]{4})|(0[1-8]{1}[0-9]{3}\\)?[ ]?[1-9]{1}[0-9]{2}[ ]?[0-9]{3})\\s*$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/\\$(\\d*)??,??(\\d*)??,??(\\d*)\\.(\\d*)/",
    isPumpable: false
  },
  {
    input:
      "/^((([\\(]?[2-9]{1}[0-9]{2}[\\)]?)|([2-9]{1}[0-9]{2}\\.?)){1}[ ]?[2-9]{1}[0-9]{2}[\\-\\.]{1}[0-9]{4})([ ]?[xX]{1}[ ]?[0-9]{3,4})?$/",
    isPumpable: false
  },
  {
    input: "/[( ]?\\d{1,3}[ )]?[ -]?\\d{3}[ -]?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/[+ ]?\\s?\\d{1,3}[- ]?\\d{1,3}[- ]?\\d{4}[- ]?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\([+]?[ ]?\\d{1,3}[)][ ]?[(][+]?[ ]?\\d{1,3}[)][- ]?\\d{4}[- ]?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/[+]?[ ]?\\d{1,3}[ ]?\\d{1,3}[- ]?\\d{4}[- ]?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/^(?!.*(.)\\1{3})((?=.*[\\d])(?=.*[A-Za-z])|(?=.*[^\\w\\d\\s])(?=.*[A-Za-z])).{8,20}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(([\\w][\\w\\-\\.]*)\\.)?([\\w][\\w\\-]+)(\\.([\\w][\\w\\.]*))?$/",
    isPumpable: false
  },
  {
    input: "/^[{|\\(]?[0-9a-fA-F]{8}[-]?([0-9a-fA-F]{4}[-]?){3}[0-9a-fA-F]{12}[\\)|}]?$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:[\\+]?(?<CountryCode>[\\d]{1,3}(?:[ ]+|[\\-.])))?[(]?(?<AreaCode>[\\d]{3})[\\-\\/)]?(?:[ ]+)?)?(?<Number>[a-zA-Z2-9][a-zA-Z0-9 \\-.]{6,})(?:(?:[ ]+|[xX]|(i:ext[\\.]?)){1,2}(?<Ext>[\\d]{1,5}))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(14, 60)}"
  },
  {
    input: "/(?<=<TAGNAME.*>).*(?=<\\/TAGNAME>)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/([\\d]{4}[ |-]?){2}([\\d]{11}[ |-]?)([\\d]{2})/",
    isPumpable: false
  },
  {
    input:
      "/^(((0)[13578]|(10)|(12))(\\/)((0[1-9])|([12][0-9])|((3)[01]))(\\/)(\\d{4}))|(((0)[469]|(11))(\\/)((0[1-9])|([12][0-9])|(30))(\\/)(\\d{4}))|((02)(\\/)((0[1-9])|((1)[0-9])|((2)[0-8]))(\\/)(\\d{4}))|((02)(\\/)((0[1-9])|((1)[0-9])|((2)[0-9]))(\\/)((\\d{2})(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input: "/^[ABCEGHJKLMNPRSTVXYabceghjklmnprstvxy]{1}\\d{1}[A-Za-z]{1}\\d{1}[A-Za-z]{1}\\d{1}$/",
    isPumpable: false
  },
  {
    input: "/^([0][1-9]|[1][0-2]):[0-5][0-9] {1}(AM|PM|am|pm)$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]{1}[0-9]{0,7})+((,[1-9]{1}[0-9]{0,7}){0,1})+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "1",
    pumpable: ",1",
    suffix: "!"
  },
  {
    input: "/(^\\d{1,9})+(,\\d{1,9})*$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((0[1-9])|(1\\d)|(2[0-8]))[\\/.-]((0[1-9])|(1[0-2])))|((31[\\/.-]((0[13578])|(1[02])))|((29|30)[\\/.-]((0[1,3-9])|(1[0-2])))))[\\/.-]((000[^0])&([0-9][0-9][0-9][0-9]))|(29[\\/.-]02[\\/.-](([0-9][0-9](([02468][48])|([2468][048])|([13579][26])))|((([02468][48])|([2468][048])|([13579][26]))00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((0[1-9])|(1\\d)|(2[0-8]))\\/((0[1-9])|(1[0-2])))|((31\\/((0[13578])|(1[02])))|((29|30)\\/((0[1,3-9])|(1[0-2])))))\\/((000[1-9])|(00[1-9][0-9])|(0[1-9][0-9][0-9])|([1-9][0-9][0-9][0-9]))|(29\\/02\\/(([0-9][0-9](([02468][48])|([2468][048])|([13579][26])))|((([02468][48])|([2468][048])|([13579][26]))00))))$/",
    isPumpable: false
  },
  {
    input: "/[a-z0-9][a-z0-9_\\.-]{0,}[a-z0-9]\\.[a-z0-9][a-z0-9_\\.-]{0,}[a-z0-9][\\.][cn]{2,4}/",
    isPumpable: false
  },
  {
    input:
      "/^(\\d{4}((-)?(0[1-9]|1[0-2])((-)?(0[1-9]|[1-2][0-9]|3[0-1])(T(24:00(:00(\\.[0]+)?)?|(([0-1][0-9]|2[0-3])(:)[0-5][0-9])((:)[0-5][0-9](\\.[\\d]+)?)?)((\\+|-)(14:00|(0[0-9]|1[0-3])(:)[0-5][0-9])|Z))?)?)?)$/",
    isPumpable: false
  },
  {
    input: "/&(?![a-z]+;|#\\d+;)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: '/<img[^>]*src=\\"?([^\\"]*)\\"?([^>]*alt=\\"?([^\\"]*)\\"?)?[^>]*>/',
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{4}[a-zA-Z]{2}[a-zA-Z0-9]{2}[XXX0-9]{0,3}/",
    isPumpable: false
  },
  {
    input:
      "/^(((((\\+)?(\\s)?(\\d{2,4}))(\\s)?((\\(0\\))?)(\\s)?|0)(\\s|\\-)?)(\\s|\\d{2})(\\s|\\-)?)?(\\d{3})(\\s|\\-)?(\\d{2})(\\s|\\-)?(\\d{2})/",
    isPumpable: false
  },
  {
    input:
      "/^((((([0-1]?\\d)|(2[0-8]))\\/((0?\\d)|(1[0-2])))|(29\\/((0?[1,3-9])|(1[0-2])))|(30\\/((0?[1,3-9])|(1[0-2])))|(31\\/((0?[13578])|(1[0-2]))))\\/((19\\d{2})|([2-9]\\d{3}))|(29\\/0?2\\/(((([2468][048])|([3579][26]))00)|(((19)|([2-9]\\d))(([2468]0)|([02468][48])|([13579][26]))))))\\s(([01]?\\d)|(2[0-3]))(:[0-5]?\\d){2}$/",
    isPumpable: false
  },
  {
    input: "/\\b(((\\S+)?)(@|mailto\\:|(news|(ht|f)tp(s?))\\:\\/\\/)\\S+)\\b/",
    isPumpable: false
  },
  {
    input:
      "/^(http|https|ftp)\\:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?\\/?([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~])*$/",
    isPumpable: false
  },
  {
    input:
      '/<[iI][mM][gG][a-zA-Z0-9\\s=".]*((src)=\\s*(?:"([^"]*)"|\'[^\']*\'))[a-zA-Z0-9\\s=".]*/*>(?:</[iI][mM][gG]>)*/',
    isPumpable: false
  },
  {
    input: "/^[+]?100(\\.0{1,2})?%?$|^[+]?\\d{1,2}(\\.\\d{1,2})?%?$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[!@#$%^&*()\\-_=+`~\\[\\]{}?|])(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).{8,20}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/(?:(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\,?[0-9]{2,3})*)(?<dec>\\.)(?<postdec>[0-9]*)?$)|(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\.?[0-9]{2,3})*)(?<dec>\\,)(?<postdec>[0-9]*)?$)|(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\'?[0-9]{2,3})*)(?<dec>\\.)(?<postdec>[0-9]*)?$)|(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\,[0-9]{2,3})*)(?<dec>\\.)(?<postdec>[0-9]*)?$)|(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\ [0-9]{2,3})*)(?<dec>\\,)(?<postdec>[0-9]*)?$)|(?:^(?<sign>[+-]?)(?<predec>[0-9]{1,3}(?:\\'?[0-9]{2,3})*)(?<dec>\\,)(?<postdec>[0-9]*)?$))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(9, 60)}"
  },
  {
    input: "/(^(?!0{5})(\\d{5})(?!-?0{4})(|-\\d{4})?$)/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[0-9]*[02468]$/",
    isPumpable: false
  },
  {
    input: "/^(\\S+\\.{1})(\\S+\\.{1})*([^\\s\\.]+\\s*)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "!.",
    pumpable: "....",
    suffix: ""
  },
  {
    input:
      "/^jdbc:db2:\\/\\/((?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:(?:(?:[A-Z|a-z])(?:[\\w|-]){0,61}(?:[\\w]?[.]))*)(?:(?:[A-Z|a-z])(?:[\\w|-]){0,61}(?:[\\w]?)))):([0-9]{1,5})\\/([0-9|A-Z|a-z|_|#|$]{1,16})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "jdbc:db2://",
    pumpable: "A0.",
    suffix: ""
  },
  {
    input: "/^(?!\\d[1]{2}|[5]{3})([2-9]\\d{2})([. -]*)\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$/",
    isPumpable: false
  },
  {
    input: "/Spaccio Moncler,Piumini Moncler,Moncler Piumino,Moncler Giubbotti,Moncler Negozio,Moncler 2011/",
    isPumpable: false
  },
  {
    input: "/((079)|(078)|(077)){1}[0-9]{7}/",
    isPumpable: false
  },
  {
    input: "/^(?=.{6,})(?=.*[0-9].*)(?=.*[a-z].*).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/<title>(.*?)<\\/title>/",
    isPumpable: false
  },
  {
    input: "/<script[\\\\.|\\\\W|\\\\w]*?</script>/",
    isPumpable: false
  },
  {
    input:
      '/([ ]?[\\\\*~`!@#\\\\%\\\\^\\\\*\\\\(\\\\)_\\\\-\\"\\"\':;\\\\,\\\\.\\\\?\\\\-\\\\+\\\\{\\\\}\\\\/\\\\& ][ ]?|\\\\b)/',
    isPumpable: false
  },
  {
    input: "/\\\\(+\\\\d{3}|\\\\d{2}|\\\\d{1}\\\\)?/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\\\s\\\\d{2}[-]\\\\w{3}-\\\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\\\[\\\\w{2}\\\\]/",
    isPumpable: false
  },
  {
    input: "/\\\\$\\\\d+[.]?\\\\d*/",
    isPumpable: false
  },
  {
    input: "/<!--[\\\\.|\\\\W|\\\\w]*?-->/",
    isPumpable: false
  },
  {
    input:
      "/(\\\\d{1}-\\\\d{2}\\\\s*)(of +)(\\\\s?\\\\d{5})|(\\\\d{1}-\\\\d{2}\\\\s*)(of +)(\\\\s?\\\\d{4})|(\\\\d{1}-\\\\d{2}\\\\s*)(of +)(\\\\s?\\\\d{3})|(\\\\d{1}-\\\\d{2}\\\\s*)(of +)(\\\\s?\\\\d{2})|(\\\\d{1}-\\\\d{2}\\\\s*)(of +)(\\\\s?\\\\d{1})/",
    isPumpable: false
  },
  {
    input: '/href\\\\s*=\\\\s*\\\\\\"((\\\\/)([\\\\w\\\\-\\\\.,@?~\\\\+#]+)*)\\\\\\/',
    wasParseError: "{ParsingData.UnsupportedEscape(50, 10)}"
  },
  {
    input: "/\\d{1,2}d \\d{1,2}h/",
    isPumpable: false
  },
  {
    input: '/^[^\\"]+$/',
    isPumpable: false
  },
  {
    input: '/\\s*("[^"]+"|[^ ,]+)/',
    isPumpable: false
  },
  {
    input:
      "/(http):\\\\/\\\\/[\\\\w\\\\-_]+(\\\\.[\\\\w\\\\-_]+)+(\\\\.[\\\\w\\\\-_]+)(\\\\/)([\\\\w\\\\-\\\\.,@?^=%&:/~\\\\+#]*[\\\\w\\\\-\\\\@?^=%&/~\\\\+#]+)(\\\\/)((\\\\d{8}-)|(\\\\d{9}-)|(\\\\d{10}-)|(\\\\d{11}-))+([\\\\w\\\\-\\\\.,@?^=%&:/~\\\\+#]*[\\\\w\\\\-\\\\@?+html^])?/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "http:\\/\\/w\\w-",
    pumpable: "\\w-\\\\-",
    suffix: ""
  },
  {
    input: "/(\\d)+\\<\\/a\\>/",
    isPumpable: false
  },
  {
    input: '/href\\s*=\\s*\\"((\\/)([i])(\\/)+([\\w\\-\\.,@?^=%&:/~\\+#]*[\\w\\-\\@?^=%&/~\\+#]+)*)\\"/',
    isPumpable: true,
    isVulnerable: true,
    prefix: 'href="/i/',
    pumpable: "/0",
    suffix: ""
  },
  {
    input:
      "/\\/^[-a-z0-9~!$%^&*_=+}{\\'?]+(\\.[-a-z0-9~!$%^&*_=+}{\\'?]+)*@([a-z0-9_][-a-z0-9_]*(\\.[-a-z0-9_]+)*\\.(aero|arpa|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|pro|travel|mobi|[a-z][a-z])|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,5})?$\\/i/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$/",
    isPumpable: false
  },
  {
    input: "/http:\\/\\/(www\\.)?([^\\.]+)\\.com/",
    isPumpable: false
  },
  {
    input: "/^(\\+97[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}1|0)50[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}[1-9]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^0[234679]{1}[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}[1-9]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^0{0,1}[1-9]{1}[0-9]{2}[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}[1-9]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^((\\+){0,1}91(\\s){0,1}(\\-){0,1}(\\s){0,1}){0,1}98(\\s){0,1}(\\-){0,1}(\\s){0,1}[1-9]{1}[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/-[0-9]*[x][0-9]*/",
    isPumpable: false
  },
  {
    input:
      "/^((11|12|13|14|15|21|22|23|31|32|33|34|35|36|37|41|42|43|44|45|46|50|51|52|53|54|61|62|63|64|65|71|81|82|91)\\d{4})((((((19|20)(([02468][048])|([13579][26]))0229))|((20[0-9][0-9])|(19[0-9][0-9]))((((0[1-9])|(1[0-2]))((0[1-9])|(1\\d)|(2[0-8])))|((((0[1,3-9])|(1[0-2]))(29|30))|(((0[13578])|(1[02]))31))))((\\d{3}(x|X))|(\\d{4})))|((((([02468][048])|([13579][26]))0229)|(\\d{2}((((0[1-9])|(1[0-2]))((0[1-9])|(1\\d)|(2[0-8])))|(((0[1,3-9])|(1[0-2]))(29|30))|(((0[13578])|(1[02]))31))))\\d{3}))$/",
    isPumpable: false
  },
  {
    input: "/^[-]?\\d{1,10}\\.?([0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input: "/^([A-Za-z]\\d[A-Za-z][-]?\\d[A-Za-z]\\d)/",
    isPumpable: false
  },
  {
    input:
      "/^(([_\\w-+!#$%&'*\\/=?^`{}|~]+(\\.[_\\w-+!#$%&'*\\/=?^`{}|~]+)*)|(\"([ _\\w-+!#$%&'*/=?^`{}|~]+(\\.[ _\\w-+!#$%&'*/=?^`{}|~]+)*)\"))@[\\w-]{1,63}(\\\\.[\\w-]{1,63})*(\\.[_\\w-]{2,6})$/",
    isPumpable: false
  },
  {
    input: "/\\d{4}\\s\\d{4}\\s\\d{4}\\s\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/((\\(\\d{3}\\)?)|(\\d{3}))([\\s-.\\/]?)(\\d{3})([\\s-.\\/]?)(\\d{4})/",
    isPumpable: false
  },
  {
    input: "/^\\s*[a-zA-Z,\\s]+\\s*$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\s.\\-]+$/",
    isPumpable: false
  },
  {
    input: "/<a[a-zA-Z0-9 =\"'.:;?]*(name=){1}[a-zA-Z0-9 =\"'.:;?]*\\s*((/>)|(>[a-zA-Z0-9 =\"'<>.:;?]*</a>))/",
    isPumpable: false
  },
  {
    input: "/<a[a-zA-Z0-9 =\"'.?_/]*(href\\s*=\\s*){1}[a-zA-Z0-9 =\"'.?_/]*\\s*((/>)|(>[a-zA-Z0-9 =\"'<>.?_/]*</a>))/",
    isPumpable: false
  },
  {
    input: "/^(1?)(-| ?)(\\()?([0-9]{3})(\\)|-| |\\)-|\\) )?([0-9]{3})(-| )?([0-9]{4}|[0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-zA-Z])(?!.*[\\W_\\x7B-\\xFF]).{6,15}$/",
    wasParseError: "{ParsingData.NonAsciiInput(32, 255)}"
  },
  {
    input:
      "/(\\/\\*[\\s\\S.]+?\\*\\/|[\\/]{2,}.*|\\/((\\\\\\\\/)|.??)*\\/[gim]{0,3}|'((\\\\\\')|.??)*'|\"((\\\\\\\")|.??)*\"|-?\\d+\\.\\d+e?-?e?\\d*|-?\\.\\d+e-?\\d+|\\w+|[\\[\\]\\(\\)\\{\\}:=;\"'\\-&!|+,.\\/*])/",
    isPumpable: true,
    isVulnerable: true,
    prefix: '"',
    pumpable: "]",
    suffix: ""
  },
  {
    input: "/(\\w+[\\.\\_\\-]*)*\\w+@[\\w]+(.)*\\w+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "0_",
    suffix: ""
  },
  {
    input:
      "/(?i)((sun(day)?|mon(day)?|tue(sday)?|wed(nesday)?|thu(rsday)?|fri(day)?|sat(urday)?),?\\s)?((jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|jun(e)?|jul(y)?|aug(ust)?|sep(tember)?|oct(ober)?|nov(ember)?|dec(ember)?)\\s)+((0?[1-9]|[1-2][0-9]|3[0-1]),?\\s)+([1-2][0-9][0-9][0-9])/",
    isPumpable: false
  },
  {
    input: "/(^(\\d+)$)|(^(\\d{1,3}[ ,\\.](\\d{3}[ ,\\.])*\\d{3}|\\d{1,3})$)/",
    isPumpable: false
  },
  {
    input: "/^[\\w0-9äÄöÖüÜß\\-_]+\\.[a-zA-Z0-9]{2,6}$/",
    wasParseError: "{ParsingData.NonAsciiInput(7, 195)}"
  },
  {
    input: "/\\/(A|B|AB|O)[+-]\\//",
    isPumpable: false
  },
  {
    input: "/(?:\\s+)|((?:\"(?:.+?)\")|(?:'(?:.+?)'))/",
    isPumpable: false
  },
  {
    input:
      "/(\\d\\d\\d\\d)-?(\\d\\d)-?(\\d\\d)T?(\\d\\d):?(\\d\\d)(?::?(\\d\\d)(\\.\\d+)*?)?(Z|[+-])(?:(\\d\\d):?(\\d\\d))?/",
    isPumpable: false
  },
  {
    input: "/((^[{])|^)[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}(?(2)[}]$|$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(87, 40)}"
  },
  {
    input:
      "/^[{][A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}[}]$|^[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*(\\W.*){4,}).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: '/(?<!and\\snot|and|not|or)\\s+(?!(and\\snot|or|-)|([^"]*"[^"]*")*[^"]*"[^"]*$)/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: '/\\"[^"]+\\"|\\([^)]+\\)|[^\\"\\s\\()]+/',
    isPumpable: false
  },
  {
    input: '/(?!\\bnot\\b|\\band\\b|\\bor\\b|\\b\\"[^"]+\\"\\b)((?<=\\s|\\-|\\(|^)[^\\"\\s\\()]+(?=\\s|\\*|\\)|$))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[^ _0-9a-zA-Z\\$\\%\\'\\-\\@\\{\\}\\~\\!\\#\\(\\)\\&\\^]/",
    isPumpable: false
  },
  {
    input: '/(?<=(?:^|\\s|,)")[^"]*?(?=")|(?<=\\s|^)(?!")[\\w\\W]+?(?=\\s|$)/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^(?=^.{8,}$)(?=.*\\d)(?=.*\\W+)(?=.*[a-z])(?=.*[A-Z])(?i-msnx:(?!.*pass|.*password|.*word|.*god|.*\\s))(?!^.*\\n).*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(57, 110)}"
  },
  {
    input: "/<\\/*?(?![^>]*?\\b(?:a|img)\\b)[^>]*?>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/<(script|style)[^>]*?>(?:.|\\n)*?<\\/\\s*\\1\\s*>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<script>",
    pumpable: "\\x0a",
    suffix: ""
  },
  {
    input: "/[a-zA-Z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u01FF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(8, 117)}"
  },
  {
    input: "/^([\\u00c0-\\u01ffa-zA-Z'\\-]+[ ]?[\\u00c0-\\u01ffa-zA-Z'\\-]*)+$/",
    wasParseError: "{ParsingData.UnsupportedEscape(4, 117)}"
  },
  {
    input: "/^[ .a-zA-Z0-9:-]{1,150}$/",
    isPumpable: false
  },
  {
    input: "/(?<=(,|;|:))\\s(?=((?:(?!<).)*>))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      '/^((?>[a-zA-Z\\d!#$%&\'*+\\-/=?^_`{|}~]+\\x20*|"((?=[\\x01-\\x7f])[^"\\\\]|\\\\[\\x01-\\x7f])*"\\x20*)*(?<angle><))?((?!\\.)(?>\\.?[a-zA-Z\\d!#$%&\'*+\\-/=?^_`{|}~]+)+|"((?=[\\x01-\\x7f])[^"\\\\]|\\\\[\\x01-\\x7f])*")@(((?!-)[a-zA-Z\\d\\-]+(?<!-)\\.)+[a-zA-Z]{2,}|\\[(((?(?<!\\[)\\.)(25[0-5]|2[0-4]\\d|[01]?\\d?\\d)){4}|[a-zA-Z\\d\\-]*[a-zA-Z\\d]:((?=[\\x01-\\x7f])[^\\\\\\[\\]]|\\\\[\\x01-\\x7f])+)\\])(?(angle)>)$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(91, 60)}"
  },
  {
    input: "/^(\\d{3}-\\d{3}-\\d{4})*$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{2}-\\d{2})*$/",
    isPumpable: false
  },
  {
    input: "/\\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\\}/",
    isPumpable: false
  },
  {
    input: "/^(([0]?[0-5][0-9]|[0-9]):([0-5][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^\\(?082|083|084|072\\)?[\\s-]?[\\d]{3}[\\s-]?[\\d]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^((AL)|(AK)|(AS)|(AZ)|(AR)|(CA)|(CO)|(CT)|(DE)|(DC)|(FM)|(FL)|(GA)|(GU)|(HI)|(ID)|(IL)|(IN)|(IA)|(KS)|(KY)|(LA)|(ME)|(MH)|(MD)|(MA)|(MI)|(MN)|(MS)|(MO)|(MT)|(NE)|(NV)|(NH)|(NJ)|(NM)|(NY)|(NC)|(ND)|(MP)|(OH)|(OK)|(OR)|(PW)|(PA)|(PR)|(RI)|(SC)|(SD)|(TN)|(TX)|(UT)|(VT)|(VI)|(VA)|(WA)|(WV)|(WI)|(WY))$/",
    isPumpable: false
  },
  {
    input: "/^([\\(]{1}[0-9]{3}[\\)]{1}[ ]{1}[0-9]{3}[\\-]{1}[0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/^100(\\.0{0,2})? *%?$|^\\d{1,2}(\\.\\d{1,2})? *%?$/",
    isPumpable: false
  },
  {
    input: "/^[+-]? *100(\\.0{0,2})? *%?$|^[+-]? *\\d{1,2}(\\.\\d{1,2})? *%?$/",
    isPumpable: false
  },
  {
    input: "/^[+-]? *(\\$)? *((\\d+)|(\\d{1,3})(\\,\\d{3})*)(\\.\\d{0,2})?$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{5})([\\-]{1}[0-9]{4})?$/",
    isPumpable: false
  },
  {
    input: "/^([4]{1})([0-9]{12,15})$/",
    isPumpable: false
  },
  {
    input: "/^([51|52|53|54|55]{2})([0-9]{14})$/",
    isPumpable: false
  },
  {
    input: "/^([34|37]{2})([0-9]{13})$/",
    isPumpable: false
  },
  {
    input: "/^([6011]{4})([0-9]{12})$/",
    isPumpable: false
  },
  {
    input: "/^([30|36|38]{2})([0-9]{12})$/",
    isPumpable: false
  },
  {
    input:
      "/(?<Date>(?<Year>\\d{4})-(?<Month>\\d{2})-(?<Day>\\d{2}))(?:T(?<Time>(?<SimpleTime>(?<Hour>\\d{2}):(?<Minute>\\d{2})(?::(?<Second>\\d{2}))?)?(?:\\.(?<FractionalSecond>\\d{1,7}))?(?<Offset>-\\d{2}\\:\\d{2})?))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^([3]{1}[0-1]{1}|[1-1]?[0-9]{1})-([0-1]?[0-2]{1}|[0-9]{1})-[0-9]{4}([\\s]+([2]{1}[0-3]{1}|[0-1]?[0-9]{1})[:]{1}([0-5]?[0-9]{1})([:]{1}([0-5]?[0-9]{1}))?)?$/",
    isPumpable: false
  },
  {
    input: "/(\\[([^\\/].*?)(=(.+?))?\\](.*?)\\[\\/\\2\\]|\\[([^\\/].*?)(=(.+?))?\\])/",
    isPumpable: false
  },
  {
    input: '/"(""|[^"])*"/',
    isPumpable: false
  },
  {
    input: '/"(\\\\.|[^"])*"/',
    isPumpable: true,
    isVulnerable: true,
    prefix: '"',
    pumpable: "\\]",
    suffix: ""
  },
  {
    input:
      "/(?n:^(?=\\d)((?<day>31(?!(.0?[2469]|11))|30(?!.0?2)|29(?(.0?2)(?=.{3,4}(19|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00))|0?[1-9]|1\\d|2[0-8])(?<sep>[\\/.-])(?<month>0?[1-9]|1[012])\\2(?<year>(19|[2-9]\\d)\\d{2})(?:(?=\\x20\\d)\\x20|$))?(?<time>([01]\\d|2[0-3])(:[0-5]\\d){1})$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      "/([a-zA-Z1-9]*)\\.(((a|A)(s|S)(p|P)(x|X))|((h|H)(T|t)(m|M)(l|L))|((h|H)(t|T)(M|m))|((a|A)(s|S)(p|P))|((t|T)(x|X)(T|x))|((m|M)(S|s)(P|p)(x|X))|((g|G)(i|I)(F|f))|((d|D)(o|O)(c|C)))/",
    isPumpable: false
  },
  {
    input: "/(?<Year>(19|20)[0-9][0-9])-(?<Month>0[1-9]|1[0-2])-(?<Day>0[1-9]|[12][0-9]|3[01])/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^([0-9]*|\\d*\\.\\d{1}?\\d*)$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((0[1-9])|(1\\d)|(2[0-8]))\\/((0[1-9])|(1[0-2])))|((31\\/((0[13578])|(1[02])))|((29|30)\\/((0[1,3-9])|(1[0-2])))))\\/((20[0-9][0-9]))|((((0[1-9])|(1\\d)|(2[0-8]))\\/((0[1-9])|(1[0-2])))|((31\\/((0[13578])|(1[02])))|((29|30)\\/((0[1,3-9])|(1[0-2])))))\\/((19[0-9][0-9]))|(29\\/02\\/20(([02468][048])|([13579][26])))|(29\\/02\\/19(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]{3,20}\\s?[A-Z]{2}[0-9]{1,3}-([A-Z]{3}|[A-Z]{1}[0-9]{2}))|([A-Z]{1,20}\\s[A-Z]{1,2}[0-9]{1,4}-[A-Z]{1,3})|([\\d,\\w,\\s]{1,20}\\s[A-Z]{3}-[0-9]{1,3})|([A-Z]{1,20}\\s?[\\d,\\w,\\s]{1,20})$/",
    isPumpable: false
  },
  {
    input: "/(\\d{5}-\\d{4}|\\d{5})/",
    isPumpable: false
  },
  {
    input:
      "/(((\\d{0,2})\\(\\d{3}\\))|(\\d{3}-))\\d{3}-\\d{4}\\s{0,}((([Ee][xX][Tt])|([Pp][Oo][Ss][Tt][Ee])):\\d{1,5}){0,1}/",
    isPumpable: false
  },
  {
    input: "/(.*)-----(BEGIN|END)([^-]*)-----(.*)/",
    isPumpable: false
  },
  {
    input: "/^\\$?([0-9]{1,3},([0-9]{3},)*[0-9]{3}|[0-9]+)(\\.[0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input:
      "/(^[Bb][Ff][Pp][Oo]\\s*[0-9]{1,4})|(^[Gg][Ii][Rr]\\s*0[Aa][Aa]$)|([Aa][Ss][Cc][Nn]|[Bb][Bb][Nn][Dd]|[Bb][Ii][Qq][Qq]|[Ff][Ii][Qq][Qq]|[Pp][Cc][Rr][Nn]|[Ss][Ii][Qq][Qq]|[Ss][Tt][Hh][Ll]|[Tt][Dd][Cc][Uu]\\s*1[Zz][Zz])|(^([Aa][BLbl]|[Bb][ABDHLNRSTabdhlnrst]?|[Cc][ABFHMORTVWabfhmortvw]|[Dd][ADEGHLNTYadeghlnty]|[Ee][CHNXchnx]?|[Ff][KYky]|[Gg][LUYluy]?|[Hh][ADGPRSUXadgprsux]|[Ii][GMPVgmpv]|[JE]|[je]|[Kk][ATWYatwy]|[Ll][ADELNSUadelnsu]?|[Mm][EKLekl]?|[Nn][EGNPRWegnprw]?|[Oo][LXlx]|[Pp][AEHLORaehlor]|[Rr][GHMghm]|[Ss][AEGK-PRSTWYaegk-prstwy]?|[Tt][ADFNQRSWadfnqrsw]|[UB]|[ub]|[Ww][A-DFGHJKMNR-Wa-dfghjkmnr-w]?|[YO]|[yo]|[ZE]|[ze])[1-9][0-9]?[ABEHMNPRVWXYabehmnprvwxy]?\\s*[0-9][ABD-HJLNP-UW-Zabd-hjlnp-uw-z]{2}$)/",
    isPumpable: false
  },
  {
    input:
      "/(^BFPO\\s*[0-9]{1,4})|(^GIR\\s*0AA$)|(ASCN|BBND|BIQQ|FIQQ|PCRN|SIQQ|STHL|TDCU\\s*1ZZ)|(^(A[BL]|B[ABDHLNRST]?|C[ABFHMORTVW]|D[ADEGHLNTY]|E[CHNX]?|F[KY]|G[LUY]?|H[ADGPRSUX]|I[GMPV]|JE|K[ATWY]|L[ADELNSU]?|M[EKL]?|N[EGNPRW]?|O[LX]|P[AEHLOR]|R[GHM|S[AEGK-PRSTWY]?|Y[ADFNQRSW|UB|W[A-DFGHJKMNR-W]?|[YO]|[ZE])[1-9][0-9]?[ABEHMNPRVWXY]?\\s*[0-9][ABD-HJLNP-UW-Z]{2}$)/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^([0][1-9]|[1-4[0-9]){2}[0-9]{3}$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^([A-Z]{2}[0-9]{3})|([A-Z]{2}[\\ ][0-9]{3})$/",
    isPumpable: false
  },
  {
    input: "/^[A][Z](.?)[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^([1][0-9]|[0-9])[1-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[1-9][0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}[\\s]|[A-Z]{2})[\\w]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[B|K|T|P][A-Z][0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{3}[-][0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[H][R][\\-][0-9]{5}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[F][O][\\s]?[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[9][7|8][1|0][0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[0-4][0-9]{2}[\\s][B][P][\\s][0-9]{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(((19|2\\d)\\d{2}\\/(((0?[13578]|1[02])\\/31)|((0?[1,3-9]|1[0-2])\\/(29|30))))|((((19|2\\d)(0[48]|[2468][048]|[13579][26])|(2[048]00)))\\/0?2\\/29)|((19|2\\d)\\d{2})\\/((0?[1-9])|(1[0-2]))\\/(0?[1-9]|1\\d|2[0-8]))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((1[6-9]|[2-9]\\d)\\d{2}\\/(((0?[13578]|1[02])\\/31)|((0?[1,3-9]|1[0-2])\\/(29|30))))|((((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))\\/0?2\\/29)|((1[6-9]|[2-9]\\d)\\d{2})\\/((0?[1-9])|(1[0-2]))\\/(0?[1-9]|1\\d|2[0-8]))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((1[6-9]|[2-9]\\d)\\d{2}([-|\\/])(((0?[13578]|1[02])([-|\\/])31)|((0?[1,3-9]|1[0-2])([-|\\/])(29|30))))|((((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))([-|\\/])0?2([-|\\/])29)|((1[6-9]|[2-9]\\d)\\d{2})([-|\\/])((0?[1-9])|(1[0-2]))([-|\\/])(0?[1-9]|1\\d|2[0-8]))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((1[6-9]|[2-9]\\d)\\d{2}([-|\\/])(((0?[13578]|1[02])([-|\\/])31)|((0?[1,3-9]|1[0-2])([-|\\/])(29|30))))|((((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))([-|\\/])0?2([-|\\/])29)|((1[6-9]|[2-9]\\d)\\d{2})([-|\\/])((0?[1-9])|(1[0-2]))([-|\\/])(0?[1-9]|1\\d|2[0-8]))(\\s)((([0]?[1-9]|1[0-2])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?(\\s)?([aApP][mM]))|(([0]?[0-9]|1[0-9]|2[0-3])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?))$/",
    isPumpable: false
  },
  {
    input:
      "/^([0]\\d|[1][0-2]\\/([0-2]\\d|[3][0-1])\\/([2][0]\\d{2})\\s([0-1]\\d|[2][0-3])\\:[0-5]\\d\\:[0-5]\\d)?\\s(AM|am|aM|Am|PM|pm|pM|Pm)/",
    isPumpable: false
  },
  {
    input: "/^\\d+(\\,\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/(at\\s)(?<fullClassName>.+)(\\.)(?<methodName>[^\\.]*)(\\()(?<parameters>[^\\)]*)(\\))((\\sin\\s)(?<fileName>.+)(:line )(?<lineNumber>[\\d]*))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input:
      "/\\/((https?|ftp)\\:\\/\\/)?([a-z0-9+!*(),;?&=\\$_.-]+(\\:[a-z0-9+!*(),;?&=\\$_.-]+)?@)?(([a-z0-9-.]*)\\.([a-z]{2,6}))|(([0-9]{1,3}\\.){3}[0-9]{1,3})(\\:[0-9]{2,5})?(\\/([a-z0-9+\\$_-]\\.?)+)*\\/?(\\?[a-z+&\\$_.-][a-z0-9;:@&%=+\\/\\$_.-]*)?(#[a-z_.-][a-z0-9+\\$_.-]*)?\\/i/",
    isPumpable: false
  },
  {
    input:
      "/^(((([1]?\\d)?\\d|2[0-4]\\d|25[0-5])\\.){3}(([1]?\\d)?\\d|2[0-4]\\d|25[0-5]))|([\\da-fA-F]{1,4}(\\:[\\da-fA-F]{1,4}){7})|(([\\da-fA-F]{1,4}:){0,5}::([\\da-fA-F]{1,4}:){0,5}[\\da-fA-F]{1,4})$/",
    isPumpable: false
  },
  {
    input: '/^(((\\\\\\\\([^\\\\/:\\*\\?"\\|<>\\. ]+))|([a-zA-Z]:\\\\))(([^\\\\/:\\*\\?"\\|<>\\. ]*)([\\\\]*))*)$/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "\\\\\\x00",
    pumpable: "\\",
    suffix: " "
  },
  {
    input: "/<[^>\\s]*\\bauthor\\b[^>]*>/",
    isPumpable: false
  },
  {
    input:
      "/^(?<assembly>[\\w\\.]+)(,\\s?Version=(?<version>\\d+\\.\\d+\\.\\d+\\.\\d+))?(,\\s?Culture=(?<culture>\\w+))?(,\\s?PublicKeyToken=(?<token>\\w+))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/[+]?[\\x20]*(?<int>\\d+)?[-\\x20]*[\\(]?(?<area>[2-9]\\d{2})[\\)\\-\\x20]*(?<pbx>[0-9]{3})[-\\x20]*(?<num>[0-9]{4})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(13, 60)}"
  },
  {
    input:
      '/(?:Provider="??(?<Provider>[^;\\n]+)"??[;\\n"]??|Data\\sSource=(?<DataSource>[^;\\n]+)[;\\n"]??|Initial\\sCatalog=(?<InitialCatalog>[^;\\n]+)[;\\n"]??|User\\sID=(?<UserID>[^;\\n]+)[;\\n"]??|Password="??(?<Password>[^;\\n]+)"??[;\\n"]??|Integrated\\sSecurity=(?<IntegratedSecurity>[^;\\n]+)[;\\n]??|Connection\\sTimeOut=(?<ConnectionTimeOut>[^;\\n]+)[;\\n"]??)+$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 60)}"
  },
  {
    input: "/^\\d{2}\\s{1}(Jan|Feb|Mar|Apr|May|Jun|Jul|Apr|Sep|Oct|Nov|Dec)\\s{1}\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(?<TAG>\\s*<(?<TAG_NAME>\\w*)\\s+(?<PARAMETERS>(?<PARAMETER>(?<PARAMETER_NAME>\\w*)(=[\"']?)(?<VALUE>[\\w\\W\\d]*?)[\"']?)+)\\s*/?>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(100([\\.\\,]0{1,2})?)|(\\d{1,2}[\\.\\,]\\d{1,2})|(\\d{0,2})$/",
    isPumpable: false
  },
  {
    input: "/^[-]?P(?!$)(?:\\d+Y)?(?:\\d+M)?(?:\\d+D)?(?:T(?!$)(?:\\d+H)?(?:\\d+M)?(?:\\d+(?:\\.\\d+)?S)?)?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(6)}"
  },
  {
    input: "/^([1-9]|1[0-2]|0[1-9]){1}(:[0-5][0-9][ ][aApP][mM]){1}$/",
    isPumpable: false
  },
  {
    input: "/(\\/\\*(\\s*|.*?)*\\*\\/)|(\\/\\/.*)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "/*",
    pumpable: "+",
    suffix: ""
  },
  {
    input: "/(\\+?1[- .]?)?[.\\(]?[\\d^01]\\d{2}\\)?[- .]?\\d{3}[- .]?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/^(20|23|27|30|33)-[0-9]{8}-[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,3}$/",
    isPumpable: false
  },
  {
    input:
      '/\\d{1,3}[.]\\d{1,3}[.]\\d{1,3}[.]\\d{1,3}\\s.\\s.\\s\\[\\d{2}\\/\\D{3}\\/\\d{4}:\\d{1,2}:\\d{1,2}:\\d{1,2}\\s.\\d{4}\\]\\s\\"\\S*\\s\\S*\\s\\S*\\"\\s\\d{1,3}\\s\\S*\\s\\".*\\"\\s\\".*\\"/',
    isPumpable: false
  },
  {
    input:
      "/\\(?\\s*(?<area>\\d{3})\\s*[\\)\\.\\-]?\\s*(?<first>\\d{3})\\s*[\\-\\.]?\\s*(?<second>\\d{4})\\D*(?<ext>\\d*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input: "/^([1-9]|1[0-2]):[0-5]\\d ?(a|A|p|P)(m|M)$/",
    isPumpable: false
  },
  {
    input: "/[\\w*|\\W*]*<[[\\w*|\\W*]*|\\/[\\w*|\\W*]]>[\\w*|\\W*]*/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/^((0[1-9]|1[0-9]|2[0-4])[0-59]\\\\d{7}(00[1-9]|[0-9][1-9][0-9]|[1-9][0-9][0-9]))|((0[1-9]|1[0-9]|2[0-4])6\\\\d{6}(000[1-9]|[0-9][0-9][1-9][0-9]|[0-9][1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/[\\x80-\\xFF]/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 255)}"
  },
  {
    input:
      "/(((^[BEGLMNS][1-9]\\d?)|(^W[2-9])|(^(A[BL]|B[ABDHLNRST]|C[ABFHMORTVW]|D[ADEGHLNTY]|E[HNX]|F[KY]|G[LUY]|H[ADGPRSUX]|I[GMPV]|JE|K[ATWY]|L[ADELNSU]|M[EKL]|N[EGNPRW]|O[LX]|P[AEHLOR]|R[GHM]|S[AEGKL-PRSTWY]|T[ADFNQRSW]|UB|W[ADFNRSV]|YO|ZE)\\d\\d?)|(^W1[A-HJKSTUW0-9])|(((^WC[1-2])|(^EC[1-4])|(^SW1))[ABEHMNPRVWXY]))(\\s*)?([0-9][ABD-HJLNP-UW-Z]{2}))$|(^GIR\\s?0AA$)/",
    isPumpable: false
  },
  {
    input:
      "/(((^[BEGLMNS][1-9]\\d?) | (^W[2-9] ) | ( ^( A[BL] | B[ABDHLNRST] | C[ABFHMORTVW] | D[ADEGHLNTY] | E[HNX] | F[KY] | G[LUY] | H[ADGPRSUX] | I[GMPV] | JE | K[ATWY] | L[ADELNSU] | M[EKL] | N[EGNPRW] | O[LX] | P[AEHLOR] | R[GHM] | S[AEGKL-PRSTWY] | T[ADFNQRSW] | UB | W[ADFNRSV] | YO | ZE ) \\d\\d?) | (^W1[A-HJKSTUW0-9]) | ((  (^WC[1-2])  |  (^EC[1-4]) | (^SW1)  ) [ABEHMNPRVWXY] ) ) (\\s*)?  ([0-9][ABD-HJLNP-UW-Z]{2})) | (^GIR\\s?0AA)/",
    isPumpable: false
  },
  {
    input: "/((v|[\\\\/])\\W*[i1]\\W*[a@]\\W*g\\W*r\\W*[a@]|v\\W*[i1]\\W*[c]\\W*[o0]\\W*d\\W*[i1]\\W*n)/",
    isPumpable: false
  },
  {
    input: "/^(([A-Z])([a-zA-Z0-9]+)?)(\\:)(\\d+)$/",
    isPumpable: false
  },
  {
    input: "/^\\d+\\*\\d+\\*\\d+$/",
    isPumpable: false
  },
  {
    input: "/<a.+?href\\=(?<link>.+?)(?=[>\\s]).*?>(?<lnkText>.+?)<\\/a>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(13, 60)}"
  },
  {
    input: "/<style.*?>(?<StyledText>.*)<\\s*?\\/\\s*?style.*?>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(12, 60)}"
  },
  {
    input: "/(?<Time>^(?:0?[1-9]:[0-5]|1(?=[012])\\d:[0-5])\\d(?:[ap]m)?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(?:(?<protocol>http(?:s?)|ftp)(?:\\:\\/\\/))(?:(?<usrpwd>\\w+\\:\\w+)(?:\\@))?(?<domain>[^\\/\\r\\n\\:]+)?(?<port>\\:\\d+)?(?<path>(?:\\/.*)*\\/)?(?<filename>.*?\\.(?<ext>\\w{2,4}))?(?<qrystr>\\??(?:\\w+\\=[^\\#]+)(?:\\&?\\w+\\=\\w+)*)*(?<bkmrk>\\#.*)?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input:
      "/^\\({0,1}((0|\\+61)(2|4|3|7|8)){0,1}\\){0,1}(\\ |-){0,1}[0-9]{2}(\\ |-){0,1}[0-9]{2}(\\ |-){0,1}[0-9]{1}(\\ |-){0,1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9#\\*abcdABCD]+$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]+(,[0-9]+)*$/",
    isPumpable: false
  },
  {
    input: "/([0-9]+)\\s(d)\\s(([0-1][0-9])|([2][0-3])):([0-5][0-9]):([0-5][0-9])/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{3}[uU]{1}[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/^[1-4]{1}[0-9]{4}(-)?[0-9]{7}(-)?[0-9]{1}$/",
    isPumpable: false
  },
  {
    input: "/src[^>]*[^\\/].(?:jpg|bmp|gif)(?:\\\"|\\')/",
    isPumpable: false
  },
  {
    input:
      "/\\[bible[=]?([a-zäëïöüæø]*)\\]((([0-9][[:space:]]?)?[a-zäëïöüæø]*[[:space:]]{1}([a-zäëïöüæø]*[[:space:]]?[a-zäëïöüæø]*[[:space:]]{1})?)([0-9]{1,3})(:{1}([0-9]{1,3})(-{1}([0-9]{1,3}))?)?)\\[\\\\/bible\\]/",
    wasParseError: "{ParsingData.NonAsciiInput(16, 195)}"
  },
  {
    input: "/^(\\d|-)?(\\d|,)*\\.?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^(\\d|,)*\\.?\\d*$/",
    isPumpable: false
  },
  {
    input:
      "/^(([1-9][0-9]{0,3}|[1-4][0-9]{4}|5([0-8][0-9]{3}|9([0-2][0-9]{2}|3([0-8][0-9]|9[01]))))|(6(4(5(1[2-9]|[2-9][0-9])|[6-9][0-9]{2})|5([0-4][0-9]{2}|5([0-2][0-9]|3[0-4]))))|(1(3(1(0(7[2-9]|[89][0-9])|[1-9][0-9]{2})|[2-9][0-9]{3})|[4-9][0-9]{4})|[2-9][0-9]{5}|[1-9][0-9]{6,8}|[1-3][0-9]{9}|4([01][0-9]{8}|2([0-8][0-9]{7}|9([0-3][0-9]{6}|4([0-8][0-9]{5}|9([0-5][0-9]{4}|6([0-6][0-9]{3}|7([01][0-9]{2}|2([0-8][0-9]|9[0-4]))))))))))$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5]))$/",
    isPumpable: false
  },
  {
    input: "/^([0-1]?[0-9]{1}\\/[0-3]?[0-9]{1}\\/20[0-9]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/1?(?:[.\\s-]?[2-9]\\d{2}[.\\s-]?|\\s?\\([2-9]\\d{2}\\)\\s?)(?:[1-9]\\d{2}[.\\s-]?\\d{4}\\s?(?:\\s?([xX]|[eE][xX]|[eE][xX]\\.|[eE][xX][tT]|[eE][xX][tT]\\.)\\s?\\d{3,4})?|[a-zA-Z]{7})/",
    isPumpable: false
  },
  {
    input: "/^\\d(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^(-?)(((\\d{1,3})(,\\d{3})*)|(\\d+))(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^((((19[0-9][0-9])|(2[0-9][0-9][0-9]))([-])(0[13578]|10|12)([-])(0[1-9]|[12][0-9]|3[01]))|(((19[0-9][0-9])|(2[0-9][0-9][0-9]))([-])(0[469]|11)([-])([0][1-9]|[12][0-9]|30))|(((19[0-9][0-9])|(2[0-9][0-9][0-9]))([-])(02)([-])(0[1-9]|1[0-9]|2[0-8]))|(([02468][048]00)([-])(02)([-])(29))|(([13579][26]00)([-])(02)([-])(29))|(([0-9][0-9][0][48])([-])(02)([-])(29))|(([0-9][0-9][2468][048])([-])(02)([-])(29))|(([0-9][0-9][13579][26])([-])(02)([-])(29)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|[12][0-9]|3[01])([\\.])(0[13578]|10|12)([\\.])((19[0-9][0-9])|(2[0-9][0-9][0-9])))|(([0][1-9]|[12][0-9]|30)([\\.])(0[469]|11)([\\.])((19[0-9][0-9])|(2[0-9][0-9][0-9])))|((0[1-9]|1[0-9]|2[0-8])([\\.])(02)([\\.])((19[0-9][0-9])|(2[0-9][0-9][0-9])))|((29)([\\.])(02)([\\.])([02468][048]00))|((29)([\\.])(02)([\\.])([13579][26]00))|((29)([\\.])(02)([\\.])([0-9][0-9][0][48]))|((29)([\\.])(02)([\\.])([0-9][0-9][2468][048]))|((29)([\\.])(02)([\\.])([0-9][0-9][13579][26])))$/",
    isPumpable: false
  },
  {
    input: "/([0-9]{11}$)|(^[7-9][0-9]{9}$)/",
    isPumpable: false
  },
  {
    input: "/(?!\\b(xx|yy)\\b)\\b[\\w]+\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^[a-zA-Z\\d]+(([\\'\\,\\.\\- #][a-zA-Z\\d ])?[a-zA-Z\\d]*[\\.]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: ".",
    suffix: "\\x00"
  },
  {
    input: "/^([a-zA-Z]+(.)?[\\s]*)$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z]))$/",
    isPumpable: false
  },
  {
    input: "/^(.*?)([^\\/\\\\]*?)(\\.[^/\\\\.]*)?$/",
    isPumpable: false
  },
  {
    input:
      "/((0?[13578]|10|12)(-|\\/)((0[0-9])|([12])([0-9]?)|(3[01]?))(-|\\/)((\\d{4})|(\\d{2}))|(0?[2469]|11)(-|\\/)((0[0-9])|([12])([0-9]?)|(3[0]?))(-|\\/)((\\d{4}|\\d{2})))/",
    isPumpable: false
  },
  {
    input: "/^100$|^[0-9]{1,2}$|^[0-9]{1,2}\\,[0-9]{1,3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(([0-2]\\d|[3][0-1])\\/([0]\\d|[1][0-2])\\/[2][0]\\d{2})$|^(([0-2]\\d|[3][0-1])\\/([0]\\d|[1][0-2])\\/[2][0]\\d{2}\\s([0-1]\\d|[2][0-3])\\:[0-5]\\d\\:[0-5]\\d)$/",
    isPumpable: false
  },
  {
    input: "/^((61|\\+61)?\\s?)04[0-9]{2}\\s?([0-9]{3}\\s?[0-9]{3}|[0-9]{2}\\s?[0-9]{2}\\s?[0-9]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-9a-zA-Z]+(?:[_\\.\\-]?[0-9a-zA-Z]+)*[@](?:[0-9a-zA-Z]+(?:[_\\.\\-]?[0-9a-zA-Z]+)*\\.[a-zA-Z]{2,}|(?:\\d{1,}\\.){3}\\d{1,}))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input: '/(?<tagname>[^\\s]*)="(?<tagvalue>[^"]*)"/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^((\\.\\.\\/|[a-zA-Z0-9_\\/\\-\\\\])*\\.[a-zA-Z0-9]+)$/",
    isPumpable: false
  },
  {
    input:
      "/^(0?[1-9]|[12][0-9]|3[01])[- \\/.](0?[1-9]|1[012])[- \\/.](19|20)?[0-9]{2}? ?((([0-1]?\\d)|(2[0-3])):[0-5]\\d)?(:[0-5]\\d)? ?([a,p,A,P][m,M])?$/",
    isPumpable: false
  },
  {
    input: "/\\.?[a-zA-Z0-9]{1,}$/",
    isPumpable: false
  },
  {
    input: "/^[\\w ]{0,}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+(([\\'\\,\\.\\- ][a-zA-Z ])?[a-zA-Z]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "A",
    suffix: "\\x00"
  },
  {
    input: "/(0?[1-9]|[12][0-9]|3[01])[\\/ -](0?[1-9]|1[12])[\\/ -](19[0-9]{2}|[2][0-9][0-9]{2})/",
    isPumpable: false
  },
  {
    input:
      "/^((((((0[13578])|(1[02]))[\\s\\.\\-\\/\\\\]?((0[1-9])|([12][0-9])|(3[01])))|(((0[469])|(11))[\\s\\.\\-\\/\\\\]?((0[1-9])|([12][0-9])|(30)))|((02)[\\s\\.\\-\\/\\\\]?((0[1-9])|(1[0-9])|(2[0-8]))))[\\s\\.\\-\\/\\\\]?(((([2468][^048])|([13579][^26]))00)|(\\d\\d\\d[13579])|(\\d\\d[02468][^048])|(\\d\\d[13579][^26])))|(((((0[13578])|(1[02]))[\\s\\.\\-\\/\\\\]?((0[1-9])|([12][0-9])|(3[01])))|(((0[469])|(11))[\\s\\.\\-\\/\\\\]?((0[1-9])|([12][0-9])|(30)))|((02)[\\s\\.\\-\\/\\\\]?((0[1-9])|([12][0-9]))))[\\s\\.\\-\\/\\\\]?(((([2468][048])|([13579][26]))00)|(\\d\\d[2468][048])|(\\d\\d[13579][26])|(\\d\\d0[48]))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?<CountryCode>[1]?)\\s?\\(?(?<AreaCode>[2-9]{1}\\d{2})\\)?\\s?(?<Prefix>[0-9]{3})(?:[-]|\\s)?(?<Postfix>\\d{4})\\s?(?:ext|x\\s?)(?<Extension>[1-9]{1}\\d*)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^((\\(?\\+45\\)?)?)(\\s?\\d{2}\\s?\\d{2}\\s?\\d{2}\\s?\\d{2})$/",
    isPumpable: false
  },
  {
    input:
      '/<(span|font).*?(?:(?:(\\s?style="?).*?((?:\\s?font-size:.+?\\s*(?:;|,|(?="))+)|(?:\\s?color:.+?\\s*(?:;|,|(?="))+))[^"]*((?:\\s?font-size:.+?\\s*(?:;|,|(?="))+)|(?:\\s?color:.+?\\s*(?:;|,|(?="))+))[^"]*("?)|(\\s?size="?.*?(?:(?=\\s)|"|(?=>)))|(\\s?color="?.*?(?:(?=\\s)|"|(?=>)))|(?=>)).*?){3}>/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(67)}"
  },
  {
    input:
      "/^(?=((0[1-9]0)|([1-7][1-7]\\d)|(00[1-9])|(0[1-9][1-9]))-(?=(([1-9]0)|(0[1-9])|([1-9][1-9]))-(?=((\\d{3}[1-9])$|([1-9]\\d{3})$|(\\d[1-9]\\d{2})$|(\\d{2}[1-9]\\d)$))))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/\\d{2}[.]{1}\\d{2}[.]{1}[0-9A-Za-z]{1}/",
    isPumpable: false
  },
  {
    input: "/IT\\d{2}[ ][a-zA-Z]\\d{3}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{3}|IT\\d{2}[a-zA-Z]\\d{22}/",
    isPumpable: false
  },
  {
    input: "/^(0{0,1}[1-9]|[12][0-9]|3[01])[- \\/.](0{0,1}[1-9]|1[012])[- \\/.](\\d{2}|\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^~\\/[0-9a-zA-Z_][0-9a-zA-Z\\/_-]*\\.[0-9a-zA-Z_-]+$/",
    isPumpable: false
  },
  {
    input: "/^A-?|[BCD][+-]?|[SN]?F|W$/",
    isPumpable: false
  },
  {
    input: "/^\\d+\\.\\d\\.\\d[01]\\d[0-3]\\d\\.[1-9]\\d*$/",
    isPumpable: false
  },
  {
    input: "/^\\d+(\\.\\d{2})?$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]\\d?-\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z]+[\\'\\,\\.\\-]?[a-zA-Z ]*)+[ ]([a-zA-Z]+[\\'\\,\\.\\-]?[a-zA-Z ]+)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "AA",
    suffix: ""
  },
  {
    input: "/(?<!\\/)\\/(\\w+\\.\\w+)?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/\\/^[a-zA-Z0-9]+$\\//",
    isPumpable: false
  },
  {
    input:
      "/^(([1-9]|[0-2]\\d|[3][0-1])\\.([1-9]|[0]\\d|[1][0-2])\\.[2][0]\\d{2})$|^(([1-9]|[0-2]\\d|[3][0-1])\\.([1-9]|[0]\\d|[1][0-2])\\.[2][0]\\d{2}\\s([1-9]|[0-1]\\d|[2][0-3])\\:[0-5]\\d)$/",
    isPumpable: false
  },
  {
    input: "/(^[0][.]{1}[0-9]{0,}[1-9]+[0-9]{0,}$)|(^[1-9]+[0-9]{0,}[.]?[0-9]{0,}$)/",
    isPumpable: false
  },
  {
    input: "/^0[1-9]\\d{7,8}$/",
    isPumpable: false
  },
  {
    input: "/^[^\\\\\\\\/\\?\\*\\\"\\'\\>\\<\\:\\|]*$/",
    isPumpable: false
  },
  {
    input: "/[0-9]{1,2}[:|°][0-9]{1,2}[:|'](?:\\b[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+\\b)\"?[N|S|E|W]/",
    wasParseError: "{ParsingData.NonAsciiInput(13, 194)}"
  },
  {
    input:
      "/((([0][1-9]|[12][\\d])|[3][01])[-\\/]([0][13578]|[1][02])[-\\/][1-9]\\d\\d\\d)|((([0][1-9]|[12][\\d])|[3][0])[-\\/]([0][13456789]|[1][012])[-\\/][1-9]\\d\\d\\d)|(([0][1-9]|[12][\\d])[-\\/][0][2][-\\/][1-9]\\d([02468][048]|[13579][26]))|(([0][1-9]|[12][0-8])[-\\/][0][2][-\\/][1-9]\\d\\d\\d)/",
    isPumpable: false
  },
  {
    input: "/[-]?[1-9]\\d{0,16}\\.?\\d{0,2}|[-]?[0]?\\.[1-9]{1,2}|[-]?[0]?\\.[0-9][1-9]/",
    isPumpable: false
  },
  {
    input: "/(<(!--|script)(.|\\n[^<])*(--|script)>)|(<|<)(\\/?[\\w!?]+)\\s?[^<]*(>|>)|(\\&[\\w]+\\;)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<!--",
    pumpable: "\\x0at",
    suffix: ""
  },
  {
    input: "/[^a-zA-Z \\-]|(  )|(\\-\\-)|(^\\s*$)/",
    isPumpable: false
  },
  {
    input: "/^5[1-5][0-9]{14}$/",
    isPumpable: false
  },
  {
    input: "/^[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-DFM]{0,1}$/",
    isPumpable: false
  },
  {
    input:
      "/(25[0-5]|2[0-4][0-9]|[1][0-9]?[0-9]?|[1-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[1][0-9]?[0-9]?|[1-9][0-9]?|[0])\\.(25[0-5]|2[0-4][0-9]|[1][0-9]?[0-9]?|[1-9][0-9]?|[0])\\.(25[0-5]|2[0-4][0-9]|[1][0-9]?[0-9]?|[1-9][0-9]?)/",
    isPumpable: false
  },
  {
    input: "/^((.)(?!\\2{2,}))+$/",
    wasParseError: "{ParsingData.InvalidBackreference(8)}"
  },
  {
    input: "/\\|(http.*)\\|(.*)$\\/ig/",
    isPumpable: false
  },
  {
    input: "/^\\$(\\d{1,3}(\\,\\d{3})*|(\\d+))(\\.\\d{2})?$/",
    isPumpable: false
  },
  {
    input: "/[\\d+]{10}\\@[\\w]+\\.?[\\w]+?\\.?[\\w]+?\\.?[\\w+]{2,4}\\/i/",
    isPumpable: false
  },
  {
    input: "/^\\$YYYY\\$\\$MM\\$\\$DD\\$$/",
    isPumpable: false
  },
  {
    input: "/^(\\w+)s?\\:\\/\\/(\\w+)?(\\.)?(\\w+)?\\.(\\w+)$/",
    isPumpable: false
  },
  {
    input: "/^(\\w+)s?[:]\\/\\/(\\w+)?[.]?(\\w+)[.](\\w+)$/",
    isPumpable: false
  },
  {
    input: "/\\/Dr[.]?|Phd[.]?|MBA\\/i/",
    isPumpable: false
  },
  {
    input: "/[\\w]+\\@[\\w]+\\.?[\\w]+?\\.?[\\w]+?\\.?[\\w+]{2,4}/",
    isPumpable: false
  },
  {
    input: "/(\\d+)?-?(\\d+)-(\\d+)/",
    isPumpable: false
  },
  {
    input:
      "/((0[1-9]|1[0-9]|2[0-9]|3[01])\\/(?:0[13578]|1[02])\\/(?:1[2-9]\\d+|2[0-9]\\d+))|((0[1-9]|1[0-9]|2[0-8])\\/(?:02)\\/(?:1[2-9]\\d+|2[0-9]\\d+))|(29\\/(?:02)\\/((1200|1600|2000|2400)|(1[6-9]|2[0-9])((0[48]|1[26]|2[048]|3[26]|4[048]|5[26]|6[048]|7[26]|8[048]|9[26]))))|((0[1-9]|1[0-9]|2[0-9]|30)\\/(?:0[469]|11)\\/(?:1[2-9]\\d+|2[0-9]\\d+))/",
    isPumpable: false
  },
  {
    input: "/^\\d{3}\\s?\\d{3}\\s?\\d{3}$/",
    isPumpable: false
  },
  {
    input: "/<(?<tag>\\w*|\\w*\\.+\\w*)>+((.|[\\n\\t\\f\\r\\s])*?)<\\/\\k<tag>>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(((0?[1-9]|[12]\\d|3[01])\\.(0[13578]|[13578]|1[02])\\.((1[6-9]|[2-9]\\d)\\d{2}))|((0?[1-9]|[12]\\d|30)\\.(0[13456789]|[13456789]|1[012])\\.((1[6-9]|[2-9]\\d)\\d{2}))|((0?[1-9]|1\\d|2[0-8])\\.0?2\\.((1[6-9]|[2-9]\\d)\\d{2}))|(29\\.0?2\\.((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:31(\\/|-|\\.)(?:0?[13578]|1[02]))\\1|(?:(?:29|30)(\\/|-|\\.)(?:0?[1,3-9]|1[0-2])\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:29(\\/|-|\\.)0?2\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\\d|2[0-8])(\\/|-|\\.)(?:(?:0?[1-9])|(?:1[0-2]))\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$/",
    wasParseError: "{ParsingData.InvalidBackreference(82)}"
  },
  {
    input: "/^START(?=(?:.(?!END|START))*MIDDLE).*?END[^\\n]+/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(6)}"
  },
  {
    input: "/\\{CHBLOCK\\:(.*?\\})/",
    isPumpable: false
  },
  {
    input: "/\\b(?:1[0-2]?|[2-9])\\b/",
    isPumpable: false
  },
  {
    input: "/\\d{2,4}/",
    isPumpable: false
  },
  {
    input: "/^([1-9]+[0-9]* | [1-9])$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z_:]+[a-zA-Z_:\\-\\.\\d]*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{2}-[0-9]{8}-[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{1,3}\\d{6}$/",
    isPumpable: false
  },
  {
    input:
      "/^ *([AaBbCcEeGgHhJjKkLlMmNnPpRrSsTtVvXxYy]\\d[a-zA-Z]) *-* *(\\d[a-zA-Z]\\d) *$|^ *(\\d{5}) *$|^ *(\\d{5}) *-* *(\\d{4}) *$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}-\\d{3}$|^\\d{8}$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-HJ-PR-Y]{2,2}[056][0-9]\\s?[A-HJ-PR-Y]{3,3})$|^([A-HJ-NP-Y]{1,3}[0-9]{2,3}?\\s[A-Z]{3,3})$|^([A-Z]{1,3}\\s?[0-9]{1,4}([A-Z]{1,1})?)$|^([0-9]{4,4}[A-Z]{1,3})$|^([A-Z]{1,2}\\s?[0-9]{1,4})$|^([A-Z]{2,3}\\s?[0-9]{1,4})$|^([0-9]{1,4}\\s?[A-Z]{2,3})$/",
    isPumpable: false
  },
  {
    input: "/^(\\(?\\+?[0-9]*\\)?)?[0-9_\\- \\(\\)]*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9][0-9,]*[0-9]$/",
    isPumpable: false
  },
  {
    input: "/^(19|20)\\d\\d[-\\/.]([1-9]|0[1-9]|1[012])[- \\/.]([1-9]|0[1-9]|[12][0-9]|3[01])$/",
    isPumpable: false
  },
  {
    input: "/(http:\\/\\/([\\w-]+\\.)|([\\w-]+\\.))+[\\w-]*(\\/[\\w- .\\/?%=]*)?/",
    isPumpable: false
  },
  {
    input: "/(\\/\\*(\\s*|.*?)*\\*\\/)|(--.*)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "/*",
    pumpable: "+",
    suffix: ""
  },
  {
    input:
      "/^((\\d?)|(([-+]?\\d+\\.?\\d*)|([-+]?\\d*\\.?\\d+))|(([-+]?\\d+\\.?\\d*\\,\\ ?)*([-+]?\\d+\\.?\\d*))|(([-+]?\\d*\\.?\\d+\\,\\ ?)*([-+]?\\d*\\.?\\d+))|(([-+]?\\d+\\.?\\d*\\,\\ ?)*([-+]?\\d*\\.?\\d+))|(([-+]?\\d*\\.?\\d+\\,\\ ?)*([-+]?\\d+\\.?\\d*)))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "00,",
    suffix: ""
  },
  {
    input:
      '/(?<user>(?:(?:[^ \\t\\(\\)\\<\\>@,;\\:\\\\\\"\\.\\[\\]\\r\\n]+)|(?:\\"(?:(?:[^\\"\\\\\\r\\n])|(?:\\\\.))*\\"))(?:\\.(?:(?:[^ \\t\\(\\)\\<\\>@,;\\:\\\\\\"\\.\\[\\]\\r\\n]+)|(?:\\"(?:(?:[^\\"\\\\\\r\\n])|(?:\\\\.))*\\")))*)@(?<domain>(?:(?:[^ \\t\\(\\)\\<\\>@,;\\:\\\\\\"\\.\\[\\]\\r\\n]+)|(?:\\[(?:(?:[^\\[\\]\\\\\\r\\n])|(?:\\\\.))*\\]))(?:\\.(?:(?:[^ \\t\\(\\)\\<\\>@,;\\:\\\\\\"\\.\\[\\]\\r\\n]+)|(?:\\[(?:(?:[^\\[\\]\\\\\\r\\n])|(?:\\\\.))*\\])))*)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^((.){1,}(\\d){1,}(.){0,})$/",
    isPumpable: false
  },
  {
    input:
      "/^(([+]\\d{2}[ ][1-9]\\d{0,2}[ ])|([0]\\d{1,3}[-]))((\\d{2}([ ]\\d{2}){2})|(\\d{3}([ ]\\d{3})*([ ]\\d{2})+))$/",
    isPumpable: false
  },
  {
    input: "/^\\/{1}(((\\/{1}\\.{1})?[a-zA-Z0-9 ]+\\/?)+(\\.{1}[a-zA-Z0-9]{2,4})?)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "/0",
    pumpable: "0 ",
    suffix: "\\x00"
  },
  {
    input: "/https?:\\/\\/[\\w.\\/]+\\/[\\w.\\/]+\\.(bmp|png|jpg|gif)/",
    isPumpable: false
  },
  {
    input:
      "/[0-3]{1}[0-9]{1}(jan|JAN|feb|FEB|mar|MAR|apr|APR|may|MAY|jun|JUN|jul|JUL|aug|AUG|sep|SEP|oct|OCT|nov|NOV|dec|DEC){1}/",
    isPumpable: false
  },
  {
    input: "/<[iI][mM][gG]([^>]*[^\\/>]*[\\/>]*[>])/",
    isPumpable: false
  },
  {
    input: "/<[iI][fF][rR][aA][mM][eE]([^>]*[^\\/>]*[\\/>]*[>])/",
    isPumpable: false
  },
  {
    input:
      "/^rgb\\(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\,([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\,([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\)$ #Matches standard web rgb pattern/",
    isPumpable: false
  },
  {
    input: "/\\b(get)\\b.*{/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(11)}"
  },
  {
    input: "/\\bfor\\b.*[A-Za-z][<> ][\\d]/",
    isPumpable: false
  },
  {
    input: "/\\b(byte|char|short|long|float|int|double|decimal|bool|string)\\b.*\\s[a-zA-Z](?=;)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(75)}"
  },
  {
    input: "/(\\bprotected\\b.*(public))|(\\bprivate\\b.*(protected))|(\\bprivate\\b.*(public))/",
    isPumpable: false
  },
  {
    input: "/\\b(\\w+).\\1/",
    isPumpable: false
  },
  {
    input:
      "/\\b(public|private|protected|internal)\\b.*(byte|char|short|long|float|int|double|decimal|bool|string)\\b.*(?=,)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(104)}"
  },
  {
    input: "/((\\bm_[a-zA-Z\\d]*\\b)|(\\bin_[a-zA-Z\\d]*\\b)|(\\bin _[a-zA-Z\\d]*\\b))/",
    isPumpable: false
  },
  {
    input: "/\\binterface\\b.*(\\bI[_]\\w*\\b)/",
    isPumpable: false
  },
  {
    input: "/^\\w+(([-+']|[-+.]|\\w+))*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "+",
    suffix: ""
  },
  {
    input: "/^\\s*[a-zA-Z\\s]+\\,[0-9\\s]+\\s*$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}(\\d{3})?$/",
    isPumpable: false
  },
  {
    input: "/(\\d{3}.?\\d{3}.?\\d{3}-?\\d{2})/",
    isPumpable: false
  },
  {
    input:
      "/\\w+([-+.]\\w+)*@(?!(hotmail|gmail|yahoo|msn|excite|lycos|aol|live)\\.com$)\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(15)}"
  },
  {
    input: "/(Word1|Word2).*?(10|[1-9])/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,7}$/",
    isPumpable: false
  },
  {
    input:
      "/^((0|1[0-9]{0,2}|2[0-9]{0,1}|2[0-4][0-9]|25[0-5]|[3-9][0-9]{0,1})\\.){3}(0|1[0-9]{0,2}|2[0-9]{0,1}|2[0-4][0-9]|25[0-5]|[3-9][0-9]{0,1})(?(\\/)\\/([0-9]|[1-2][0-9]|3[0-2])|)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(136, 40)}"
  },
  {
    input:
      "/^((\\d{2}(([02468][048])|([13579][26]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])))))|(\\d{2}(([02468][1235679])|([13579][01345789]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|(1[0-9])|(2[0-8]))))))(\\s(((0?[1-9])|(1[0-9])|(2[0-3]))\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])))?))?$/",
    isPumpable: false
  },
  {
    input: "/^(?:(\\\\d{1,6})-)?(\\\\d{2,10})/(\\\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/(((ht|f)tp(s)?:\\/\\/)|www.){1}([\\w-]+\\.)+[\\w-]+(\\/[\\w- .\\/?%&=]*)?/",
    isPumpable: false
  },
  {
    input: "/(?=^.{6,10}$)(?=.*\\$)(?=.*[a-z])(?=.*[A-Z])(?=.*[!~@#$%^&*()_+}{\":;'?/>.<,])(?!.*\\s).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^0?(5[024])(\\-)?\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/((?:[\\\\?&](?:[a-z\\d\\\\.\\\\[\\\\]%-]+)(?:=[a-z\\\\d\\\\.\\\\[\\\\]%-]*)?)*)/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/(^(\\+?\\-? *[0-9]+)([,0-9 ]*)([0-9 ])*$)|(^ *$)/",
    isPumpable: false
  },
  {
    input: '/^Content-Type:\\s*(\\w+)\\s*/?\\s*(\\w*)?\\s*;\\s*((\\w+)?\\s*=\\s*((".+")|(\\S+)))?/',
    isPumpable: false
  },
  {
    input: "/^([A-Z]|[a-z]|[0-9])(([A-Z])*(([a-z])*([0-9])*(%)*(&)*(')*(\\+)*(-)*(@)*(_)*(\\.)*)|(\\ )[^  ])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a",
    pumpable: ".",
    suffix: "\\x00"
  },
  {
    input: "/\\/^[A-Z]{3}[G|A|F|C|T|H|P]{1}[A-Z]{1}\\d{4}[A-Z]{1}$\\/;/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(51, 59)}"
  },
  {
    input: "/^(?:[\\w]+[\\&\\-_\\.]*)+@(?:(?:[\\w]+[\\-_\\.]*)\\.(?:[a-zA-Z]{2,}?))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "A_",
    suffix: ""
  },
  {
    input: "/^[AaWaKkNn][a-zA-Z]?[0-9][a-zA-Z]{1,3}$/",
    isPumpable: false
  },
  {
    input: "/[0-9A-Fa-f]{2}(\\.?)[0-9A-Fa-f]{2}(\\.?)[0-9A-Fa-f]{2}(\\.?)[0-9A-Fa-f]{2}/",
    isPumpable: false
  },
  {
    input: "/[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/",
    isPumpable: false
  },
  {
    input:
      "/^((([sS]|[nN])[a-hA-Hj-zJ-Z])|(([tT]|[oO])[abfglmqrvwABFGLMQRVW])|([hH][l-zL-Z])|([jJ][lmqrvwLMQRVW]))([0-9]{2})?([0-9]{2})?([0-9]{2})?([0-9]{2})?([0-9]{2})?$/",
    isPumpable: false
  },
  {
    input:
      "/((([sS]|[nN])[a-hA-Hj-zJ-Z])|(([tT]|[oO])[abfglmqrvwABFGLMQRVW])|([hH][l-zL-Z])|([jJ][lmqrvwLMQRVW]))([0-9]{2})?(([a-np-zA-NP-Z]{1}?|([0-9]{2})?([0-9]{2})?([0-9]{2})?([0-9]{2})?))/",
    isPumpable: false
  },
  {
    input: "/^\\.{0,2}[\\/\\\\]/",
    isPumpable: false
  },
  {
    input:
      "/^((http|https|ftp)\\:\\/\\/|www\\.)[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,4}(\\/[a-zA-Z0-9\\-\\._\\?=\\,\\'\\+%\\$#~]*[^\\.\\,\\)\\(\\s])*$/",
    isPumpable: false
  },
  {
    input: "/^(?<1>.*[\\\\/])(?<2>.+)\\.(?<3>.+)?$|^(?<1>.*[\\\\/])(?<2>.+)$|^(?<2>.+)\\.(?<3>.+)?$|^(?<2>.+)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^([\\w\\s\\W]+[\\w\\W]?)\\s([\\d\\-\\\\\\\\/\\w]*)?/",
    isPumpable: false
  },
  {
    input: "/(?<prefix>[\\d]{3})[\\s+\\/\\\\\\-]+(?<number>[\\d\\-\\s]+)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(~?\\/|[a-zA-Z]:[\\\\/]).+/",
    isPumpable: false
  },
  {
    input:
      '/(?=^.{1,160}$)^(?:(?<Workspace>(?<Root>(?:(?<Drive>[a-zA-Z]\\:)|(?<Server>\\\\{2}[a-zA-Z]\\w*)))(?<DirectoryTree>(?:\\\\(?<Directory>(?:(?![\\w\\.]*\\.(?:gdb|mdb|sde|mdf))[^\\\\/:*?<>"| .]+[^\\\\/:*?<>"|]*[^\\\\/:*?<>"| .]+)))*)(?:\\\\(?<Geodatabase>(?<GDBName>[a-zA-Z]\\w*)(?<Extension>\\.(?:gdb|mdb|sde|mdf))))?)\\\\?(?<FeatureDataset>[a-zA-Z]\\w*)?(?:\\\\(?<BaseName>[a-zA-Z]\\w*(?:\\.shp)?)(?<!.+\\k<Extension>.+\\.shp|(?<!.+\\k<Extension>.+)(?<!.+\\.shp))))$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(20, 60)}"
  },
  {
    input:
      "/^([a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+(\\.[a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)*\\.([a-z]{2,})){1}(;[a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+(\\.[a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)*\\.([a-z]{2,}))*$/",
    isPumpable: false
  },
  {
    input: "/(^\\d*\\.?\\d*[1-9]+\\d*$)|(^[1-9]+\\d*\\.\\d*$)/",
    isPumpable: false
  },
  {
    input: "/(^-\\d*\\.?\\d*[1-9]+\\d*$)|(^-[1-9]+\\d*\\.\\d*$)/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[1-9].*$)\\d{0,7}(?:\\.\\d{0,9})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^([0-1]?[0-9]|[2][0-3]):([0-5][0-9]):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]+([\\,|\\.]{0,1}[0-9]{2}){0,1}$/",
    isPumpable: false
  },
  {
    input:
      "/^((A[ABEHKLMPRSTWXYZ])|(B[ABEHKLMT])|(C[ABEHKLR])|(E[ABEHKLMPRSTWXYZ])|(GY)|(H[ABEHKLMPRSTWXYZ])|(J[ABCEGHJKLMNPRSTWXYZ])|(K[ABEHKLMPRSTWXYZ])|(L[ABEHKLMPRSTWXYZ])|(M[AWX])|(N[ABEHLMPRSWXYZ])|(O[ABEHKLMPRSX])|(P[ABCEGHJLMNPRSTWXY])|(R[ABEHKMPRSTWXYZ])|(S[ABCGHJKLMNPRSTWXYZ])|(T[ABEHKLMPRSTWXYZ])|(W[ABEKLMP])|(Y[ABEHKLMPRSTWXYZ])|(Z[ABEHKLMPRSTWXY]))\\d{6}([A-D]|\\s)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z1-9]{5}-[A-Z1-9]{5}-[A-Z1-9]{5}-[A-Z1-9]{5}-[A-Z1-9]{5}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{3}\\d{8}$/",
    isPumpable: false
  },
  {
    input:
      "/^(ht|f)tp((?<=http)s)?:\\/\\/((?<=http:\\/\\/)www|(?<=https:\\/\\/)www|(?<=ftp:\\/\\/)ftp)\\.(([a-z][0-9])|([0-9][a-z])|([a-z0-9][a-z0-9\\-]{1,2}[a-z0-9])|([a-z0-9][a-z0-9\\-](([a-z0-9\\-][a-z0-9])|([a-z0-9][a-z0-9\\-]))[a-z0-9\\-]*[a-z0-9]))\\.(co|me|org|ltd|plc|net|sch|ac|mod|nhs|police|gov)\\.uk(:\\d+)?\\/?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(10)}"
  },
  {
    input:
      "/^(([a-z][0-9])|([0-9][a-z])|([a-z0-9][a-z0-9\\-]{1,2}[a-z0-9])|([a-z0-9][a-z0-9\\-](([a-z0-9\\-][a-z0-9])|([a-z0-9][a-z0-9\\-]))[a-z0-9\\-]*[a-z0-9]))\\.(co|me|org|ltd|plc|net|sch|ac|mod|nhs|police|gov)\\.uk$/",
    isPumpable: false
  },
  {
    input:
      "/^(ht|f)tp((?<=http)s)?:\\/\\/((?<=http:\\/\\/)www|(?<=https:\\/\\/)www|(?<=ftp:\\/\\/)ftp)\\.(([a-z][0-9])|([0-9][a-z])|([a-z0-9][a-z0-9\\-]{1,2}[a-z0-9])|([a-z0-9][a-z0-9\\-](([a-z0-9\\-][a-z0-9])|([a-z0-9][a-z0-9\\-]))[a-z0-9\\-]*[a-z0-9]))\\.(co|me|org|ltd|plc|net|sch|ac|mod|nhs|police|gov)\\.uk$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(10)}"
  },
  {
    input:
      "/^((A(((H[MX])|(M(P|SN))|(X((D[ACH])|(M[DS]))?)))?)|(K7(A)?)|(D(H[DLM])?))(\\d{3,4})[ABD-G][CHJK-NPQT-Y][Q-TV][1-4][B-E]$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]{3}\\s?(\\d{3}|\\d{2}|d{1})\\s?[A-Z])|([A-Z]\\s?(\\d{3}|\\d{2}|\\d{1})\\s?[A-Z]{3})|(([A-HK-PRSVWY][A-HJ-PR-Y])\\s?([0][2-9]|[1-9][0-9])\\s?[A-HJ-PR-Z]{3})$/",
    isPumpable: false
  },
  {
    input: "/^([A-HK-PRSVWY][A-HJ-PR-Y])\\s?([0][2-9]|[1-9][0-9])\\s?[A-HJ-PR-Z]{3}$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{3}\\s?(\\d{3}|\\d{2}|d{1})\\s?[A-Z])|([A-Z]\\s?(\\d{3}|\\d{2}|\\d{1})\\s?[A-Z]{3})$/",
    isPumpable: false
  },
  {
    input: "/^(\\+44\\s?7\\d{3}|\\(?07\\d{3}\\)?)\\s?\\d{3}\\s?\\d{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(((\\+44\\s?\\d{4}|\\(?0\\d{4}\\)?)\\s?\\d{3}\\s?\\d{3})|((\\+44\\s?\\d{3}|\\(?0\\d{3}\\)?)\\s?\\d{3}\\s?\\d{4})|((\\+44\\s?\\d{2}|\\(?0\\d{2}\\)?)\\s?\\d{4}\\s?\\d{4}))(\\s?\\#(\\d{4}|\\d{3}))?$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\(?0\\d{4}\\)?\\s?\\d{3}\\s?\\d{3})|(\\(?0\\d{3}\\)?\\s?\\d{3}\\s?\\d{4})|(\\(?0\\d{2}\\)?\\s?\\d{4}\\s?\\d{4}))(\\s?\\#(\\d{4}|\\d{3}))?$/",
    isPumpable: false
  },
  {
    input: "/[1-9][0-9]{3}(?!SS|SA|SD)[A-Z]{2}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(13)}"
  },
  {
    input: "/(?-i)(?=^.{8,}$)((?!.*\\s)(?=.*[A-Z])(?=.*[a-z]))((?=(.*\\d){1,})|(?=(.*\\W){1,}))^.*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^(0[1-9]|1[012])[\\/](0[1-9]|[12][0-9]|3[01])[\\/][0-9]{4}(\\s((0[1-9]|1[012])\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])\\s))([AM|PM|]{2,2})))?$/",
    isPumpable: false
  },
  {
    input: "/^(0?\\d|1[012])\\/([012]?\\d|3[01])\\/(\\d{2}|\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/<!--\\s*\\#\\s*include\\s+(file|virtual)\\s*=\\s*([\"'])([^\"'<>\\|\\b]+/)*([^\"'<>/\\|\\b]+)\\2\\s*-->/",
    wasParseError: "{ParsingData.UnsupportedEscape(59, 98)}"
  },
  {
    input: "/^((0[1-9])|(1[0-2]))\\/(\\d{2})$/",
    isPumpable: false
  },
  {
    input: "/^(20|21|22|23|[01]\\d|\\d)(([:.][0-5]\\d){1,2})$/",
    isPumpable: false
  },
  {
    input: "/((^\\d{5}$)|(^\\d{8}$))|(^\\d{5}-\\d{3}$)/",
    isPumpable: false
  },
  {
    input: "/^(\\d{2,3}|\\(\\d{2,3}\\))?[ ]?\\d{3,4}[-]?\\d{3,4}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{2,3}|\\(\\d{2,3}\\))[ ]?\\d{3,4}[-]?\\d{3,4}$/",
    isPumpable: false
  },
  {
    input: "/\\/^\\d{2}[\\-\\/]\\d{2}[\\-\\/]\\d{4}$\\//",
    isPumpable: false
  },
  {
    input: "/(antifraud\\.ref\\.num)[0-9]*(@citibank\\.com)/",
    isPumpable: false
  },
  {
    input: "/(^.+\\|+[A-Za-z])/",
    isPumpable: false
  },
  {
    input: "/(?i)(pharmacy)|((p(.{1,3})?h(.{1,3})?a(.{1,3})?r(.{1,3)?m(.{1,3})?a(.{1,3})?c(.{1,3})?y))/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(50)}"
  },
  {
    input: "/^[0-2]?[1-9]{1}$|^3{1}[01]{1}$/",
    isPumpable: false
  },
  {
    input: "/href=[\\\"\\']?((?:[^>]|[^\\s]|[^\"]|[^'])+)[\\\"\\']?/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/\\b(((20)((0[0-9])|(1[0-1])))|(([1][^0-8])?\\d{2}))((0[1-9])|1[0-2])((0[1-9])|(2[0-9])|(3[01]))[-+]?\\d{4}[,.]?\\b/",
    isPumpable: false
  },
  {
    input: "/^(((20)((0[0-9])|(1[0-1])))|(([1][^0-8])?\\d{2}))((0[1-9])|1[0-2])((0[1-9])|(2[0-9])|(3[01]))[-]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\S)[-!#$%&\\'*+\\/=?^_`{|}~,.a-z0-9]{1,64}[@]{1}[-.a-zåäö0-9]{4,253}$/",
    wasParseError: "{ParsingData.NonAsciiInput(58, 195)}"
  },
  {
    input: "/^\\S{1}(?:.){4,}\\S$/",
    isPumpable: false
  },
  {
    input: "/^(((2|8|9)\\d{2})|((02|08|09)\\d{2})|([1-9]\\d{3}))$/",
    isPumpable: false
  },
  {
    input: "/^\\d(\\d)?(\\d)?$/",
    isPumpable: false
  },
  {
    input: "/(^\\*\\.[a-zA-Z][a-zA-Z][a-zA-Z]$)|(^\\*\\.\\*$)/",
    isPumpable: false
  },
  {
    input: "/^[+]\\d{1,2}\\(\\d{2,3}\\)\\d{6,8}(\\#\\d{1,10})?$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^(https?|ftp)(:\\/\\/)(([\\w]{3,}\\.[\\w]+\\.[\\w]{2,6})|([\\d]{3}\\.[\\d]{1,3}\\.[\\d]{3}\\.[\\d]{1,3}))(\\:[0,9]+)*(\\/?$|((\\/[\\w\\W]+)+\\.[\\w]{3,4})?$)\\//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "https://aaa.a.aaaaaa:9/!",
    pumpable: "/0/0",
    suffix: ""
  },
  {
    input: "/^([0-9]{2})?(\\([0-9]{2})\\)([0-9]{3}|[0-9]{4})-[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^\\d{2}(\\x2e)(\\d{3})(-\\d{3})?$/",
    isPumpable: false
  },
  {
    input:
      "/^((nntp|sftp|ftp(s)?|http(s)?|gopher|news|file|telnet):\\/\\/)?(([a-zA-Z0-9\\._-]*([a-zA-Z0-9]\\.[a-zA-Z0-9])[a-zA-Z]{1,6})|(([0-9]{1,3}\\.){3}[0-9]{1,3}))(:\\d+)?(\\/[^:][^\\s]*)?$/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*([A-Za-z]{2,4}\\.?\\s*)?(['\\-A-Za-z]+\\s*){1,2}([A-Za-z]+\\.?\\s*)?(['\\-A-Za-z]+\\s*){1,2}(([jJsSrR]{2}\\.)|([XIV]{1,6}))?\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\+)?[1-9]{1,4})?([-\\s\\.\\/])?((\\(\\d{1,4}\\))|\\d{1,4})(([-\\s\\.\\/])?[0-9]{1,6}){2,6}(\\s?(ext|x)\\s?[0-9]{1,6})?$/",
    isPumpable: false
  },
  {
    input: "/\\/^([a-zA-Z0-9\\.\\_\\-\\&]+)@[a-zA-Z0-9]+\\.[a-zA-Z]{3}|(.[a-zA-Z]{2}(\\.[a-zA-Z]{2}))$\\//",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+[a-zA-Z0-9_-]*@([a-zA-Z0-9]+){1}(\\.[a-zA-Z0-9]+){1,2}/",
    isPumpable: false
  },
  {
    input: "/\\s?\\b((?!\\b50\\b|\\b00\\b)\\w*)\\b\\s?/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(6)}"
  },
  {
    input: "/\\({1}[0-9]{3}\\){1}\\-{1}[0-9]{3}\\-{1}[0-9]{4}/",
    isPumpable: false
  },
  {
    input: "/^(?!000)(?!666)([0-8]\\d{2}) ([ -])? (?!00)\\d\\d ([ -])? (?!0000)\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/(([\\w-]+(?:\\.[\\w-]+)*)@(timbrasil.com.br))*/",
    isPumpable: false
  },
  {
    input: "/^[\\w_.]{5,12}$/",
    isPumpable: false
  },
  {
    input: "/^([^\\s]){5,12}$/",
    isPumpable: false
  },
  {
    input: "/^(01)[0-9]{8}/",
    isPumpable: false
  },
  {
    input: "/^[^<>`~!\\/@\\#}$%:;)(_^{&*=|'+]+$/",
    isPumpable: false
  },
  {
    input: "/\\/\\/.*|\\/\\*[\\s\\S]*?\\*\\//",
    isPumpable: false
  },
  {
    input: "/\\/^(1)?(-|.)?(\\()?([0-9]{3})(\\))?(-|.)?([0-9]{3})(-|.)?([0-9]{4})\\//",
    isPumpable: false
  },
  {
    input:
      "/\\/^(((?=.*(::))(?!.*\\3.+\\3))\\3?|([\\dA-F]{1,4}(\\3|:\\b|$)|\\2))(?4){5}((?4){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})\\z\\/i/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(60, 52)}"
  },
  {
    input: "/http[s]?:\\/\\/[a-zA-Z0-9.-\\/]+/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9]{1,20}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\-]+\\.cn$/",
    isPumpable: false
  },
  {
    input: "/(\\'([^\\'\\\\]*\\\\.)*[^\\'\\\\]*\\')+/",
    isPumpable: false
  },
  {
    input:
      "/20\\d{2}(-|\\/)((0[1-9])|(1[0-2]))(-|\\/)((0[1-9])|([1-2][0-9])|(3[0-1]))(T|\\s)(([0-1][0-9])|(2[0-3])):([0-5][0-9]):([0-5][0-9])/",
    isPumpable: false
  },
  {
    input: "/\\/([^\\x00-\\xFF]\\s*)\\/u/",
    wasParseError: "{ParsingData.NonAsciiInput(3, 255)}"
  },
  {
    input: "/\\/(<\\/?)(\\w+)([^>]*>)\\/e/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(21, 101)}"
  },
  {
    input: "/^[a-zA-Z_]{1}[a-zA-Z0-9_]+$/",
    isPumpable: false
  },
  {
    input: "/&(?![a-zA-Z]{2,6};|#[0-9]{3};)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^([1-9]{1}[\\d]{0,2}(\\.[\\d]{3})*(\\,[\\d]{0,2})?|[1-9]{1}[\\d]{0,}(\\,[\\d]{0,2})?|0(\\,[\\d]{0,2})?|(\\,[\\d]{1,2})?)$/",
    isPumpable: false
  },
  {
    input: "/.\\{\\d\\}/",
    isPumpable: false
  },
  {
    input: "/^\\d{2}([0][1-9]|[1][0-2])([0][1-9]|[1-2][0-9]|[3][0-1])-\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^011-(?<IntlCountryCode>[1-9][0-9]{1,5})-(?<IntlAreaCode>[0-9]+)-(?<IntlPhoneNumber>[0]?\\d[0-9]+)(?:[^\\d\\-]+(?<IntlExtension>\\d{1,4}))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input: "/\\/^[a-z][\\w\\.]+@([\\w\\-]+\\.)+[a-z]{2,7}$\\/i/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{3}[\\s\\-]*[\\d]{3}[\\s\\-]*[\\d]{4}\\s*$/",
    isPumpable: false
  },
  {
    input: '/<link href="../Common/Styles/iLienStyle.css" type="text/css" rel="stylesheet" />/',
    isPumpable: false
  },
  {
    input: "/\\d{1,2}(\\/|-)\\d{1,2}(\\/|-)\\d{2,4}/",
    isPumpable: false
  },
  {
    input: "/(?i)\\s*MOVE\\s+\\w+(\\-\\w+)*\\s+TO\\s+\\w+(\\-\\w+)*/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,2}\\.\\d{3}\\.\\d{3}[-][0-9kK]{1}$/",
    isPumpable: false
  },
  {
    input: "/^((?=.{8,32}$)(?=.*\\p{Lu})(?=.*\\p{Ll})((?=.*\\p{N})|(?=.*\\p{P}))(?!.*\\s))/",
    wasParseError: "{ParsingData.UnsupportedEscape(20, 112)}"
  },
  {
    input:
      "/^([0-9]{1}[\\d]{0,2}(\\,[\\d]{3})*(\\,[\\d]{0,2})?|[0-9]{1}[\\d]{0,}(\\,[\\d]{0,2})?|0(\\,[\\d]{0,2})?|(\\,[\\d]{1,2})?)$/",
    isPumpable: false
  },
  {
    input: '//("(\\\\["\\\\]|[^"])*("|$)|\\S)+/g/',
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(29, 103)}"
  },
  {
    input: '/("(?!")(""|[^"])*("|$)|\\S)+/g/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: '//^("(\\\\["\\\\]|[^"])*"|[^\\n])*(\\n|$)/gm/',
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(35, 103)}"
  },
  {
    input: '//"(\\\\["\\\\]|[^"])*("|$)|(\\\\["\\\\]|[^\\s"])+/g/',
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(41, 103)}"
  },
  {
    input: '//"(?!")(""|[^"])*("|$)|(("")+|[^\\s"])+/g/',
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(39, 103)}"
  },
  {
    input: '//^("(\\\\["\\\\]|[^"])*"|[^\\n])*$/gm/',
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(30, 103)}"
  },
  {
    input: "/\\/(?:(.):)?(?:(.*)\\\\)?(?:(.*)\\.)?(.*)//",
    isPumpable: false
  },
  {
    input: "/\\/(?:(.):)?(?:(.*)\\\\)?((?:[^.]|.(?=[^.]*\\.))*)(?:\\.(.*))?//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(30)}"
  },
  {
    input: "/\\/\"(\\\\[\"\\\\]|[^\"])*(\"|$)|'(\\\\['\\\\]|[^'])*('|$)|(\\\\[\"'\\\\]|[^\\s\"'])+/g/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(65, 103)}"
  },
  {
    input: "/\\/^(\"(\\\\\"|[^\"])*\"|'(\\\\'|[^'])*'|[^\\n])*(\\n|$)/gm/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(45, 103)}"
  },
  {
    input: "/^\\d*(\\.\\d*)$/",
    isPumpable: false
  },
  {
    input: "/^\\d{1}(\\.\\d{3})-\\d{3}(\\.\\d{1})$/",
    isPumpable: false
  },
  {
    input: "/^[-]?\\d*(\\.\\d*)$/",
    isPumpable: false
  },
  {
    input: "/^(\\d+\\.\\d+)$/",
    isPumpable: false
  },
  {
    input:
      "/(\"(?:(?:(?:\\\\.)|[^\"\\\\\\r\\n])*)\"|'(?:(?:(?:\\\\.)|[^'\\\\\\r\\n])*)'|`(?:(?:(?:\\\\.)|[^`\\\\\\r\\n])*)`)|((?:-- .*)|(?:#.*)|(?:/\\*(?:(?:[^*]|\\*(?!/))*)\\*/))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(130)}"
  },
  {
    input:
      '/(?:""(?:(?:(?:\\\\.)|[^""\\\\\\r\\n])*)""|\'(?:(?:(?:\\\\.)|[^\'\\\\\\r\\n])*)\'|`(?:(?:(?:\\\\.)|[^`\\\\\\r\\n])*)`|(?:\\s?(?:\\#|--\\ ).*(?=[\\r\\n]))|(?:/\\*(?:(?:[^*]|\\*(?!/))*)\\*/)|(?:[^;`\'""](?!(?:--\\ |\\#|/\\*)))*(?:[^;`\'""](?=(?:--\\ |\\#|/\\*)))?)*/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(115)}"
  },
  {
    input: "/\\b(([01]?\\d?\\d|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d?\\d|2[0-4]\\d|25[0-5])\\b/",
    isPumpable: false
  },
  {
    input:
      "/^((((0?[1-9]|1[012])\\/(0?[1-9]|1\\d|2[0-8])|(0?[13456789]|1[012])\\/(29|30)|(0?[13578]|1[02])\\/31)\\/(19|[2-9]\\d)\\d{2}|0?2\\/29\\/((19|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(([2468][048]|[3579][26])00))))[\\s]((([0]?[1-9]|1[0-2])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?( )?(AM|am|aM|Am|PM|pm|pM|Pm))|(([0]?[0-9]|1[0-9]|2[0-3])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?))$/",
    isPumpable: false
  },
  {
    input: "/ISBN(-1(?:(0)|3))?:?\\x20(\\s)*[0-9]+[- ][0-9]+[- ][0-9]+[- ][0-9]*[- ]*[xX0-9]/",
    isPumpable: false
  },
  {
    input: "/^\\s*[a-zA-Z0-9,\\s\\-\\'\\.]+\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/^([1-9]|0[1-9]|[12][0-9]|3[01])(-|\\/)(([1-9]|0[1-9])|(1[0-2]))(-|\\/)(([0-9][0-9])|([0-9][0-9][0-9][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(\\d{1,3}\\.){3}\\d{1,3}/",
    isPumpable: false
  },
  {
    input:
      "/^(H(P|T|U|Y|Z)|N(A|B|C|D|F|G|H|J|K|L|M|N|O|R|S|T|U|W|X|Y|Z)|OV|S(C|D|E|G|H|J|K|M|N|O|P|R|S|T|U|W|X|Y|Z)|T(A|F|G|L|M|Q|R|V)){1}\\d{4}(NE|NW|SE|SW)?$|((H(P|T|U|Y|Z)|N(A|B|C|D|F|G|H|J|K|L|M|N|O|R|S|T|U|W|X|Y|Z)|OV|S(C|D|E|G|H|J|K|M|N|O|P|R|S|T|U|W|X|Y|Z)|T(A|F|G|L|M|Q|R|V)){1}(\\d{4}|\\d{6}|\\d{8}|\\d{10}))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?<link>((?<prot>http:\\/\\/)*(?<subdomain>(www|[^\\-\\n]*)*)(\\.)*(?<domain>[^\\-\\n]+)\\.(?<after>[a-zA-Z]{2,3}[^>\\n]*)))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/\\A(\\d+[a-zA-Z]{0,1}\\s{0,1}[-]{1}\\s{0,1}\\d*[a-zA-Z]{0,1}|\\d+[a-zA-Z-]{0,1}\\d*[a-zA-Z]{0,1})\\s*+(.*)/",
    wasParseError: "{ParsingData.UnsupportedPossessiveQuantifier(93)}"
  },
  {
    input:
      "/\\A(.*?)\\s+(\\d+[a-zA-Z]{0,1}\\s{0,1}[-]{1}\\s{0,1}\\d*[a-zA-Z]{0,1}|\\d+[a-zA-Z-]{0,1}\\d*[a-zA-Z]{0,1})/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9][a-zA-Z0-9_]{2,29}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1,4}?[.]{0,1}?\\d{0,3}?)$/",
    isPumpable: false
  },
  {
    input:
      '/<\\s*a\\s[^>]*\\bhref\\s*=\\s*(\'(?<url>[^\']*)\'|""(?<url>[^""]*)""|(?<url>\\S*))[^>]*>(?<body>(.|\\s)*?)<\\s*/a\\s*>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(29, 60)}"
  },
  {
    input:
      "/((DK|FI|HU|LU|MT|SI)(-)?\\d{8})|((BE|EE|DE|EL|LT|PT)(-)?\\d{9})|((PL|SK)(-)?\\d{10})|((IT|LV)(-)?\\d{11})|((LT|SE)(-)?\\d{12})|(AT(-)?U\\d{8})|(CY(-)?\\d{8}[A-Z])|(CZ(-)?\\d{8,10})|(FR(-)?[\\dA-HJ-NP-Z]{2}\\d{9})|(IE(-)?\\d[A-Z\\d]\\d{5}[A-Z])|(NL(-)?\\d{9}B\\d{2})|(ES(-)?[A-Z\\d]\\d{7}[A-Z\\d])/",
    isPumpable: false
  },
  {
    input: "/(^([1-3]{1}[0-9]{0,}(\\.[0-9]{1})?|0(\\.[0-9]{1})?|[4]{1}[0-9]{0,}(\\.[0]{1})?|5(\\.[5]{1}))$)/",
    isPumpable: false
  },
  {
    input: "/([1,2].)(\\d{2}.)(\\d{2}.)(\\d{2}.)(\\d{3}.)(\\d{3}.)(\\d{2})/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9]+[\\s]*[a-zA-Z0-9.\\-\\,\\#]+[\\s]*[a-zA-Z0-9.\\-\\,\\#]+[a-zA-Z0-9\\s.\\-\\,\\#]*$/",
    isPumpable: false
  },
  {
    input: "/^\\-?\\(?([0-9]{0,3}(\\,?[0-9]{3})*(\\.?[0-9]*))\\)?$/",
    isPumpable: false
  },
  {
    input: "/^([0-9][0-9])[.]([0-9][0-9])[.]([0-9][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^(0+[1-9]|[1-9])[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{3}-[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^((CN=['\\w\\d\\s\\-\\&]+,)+(OU=['\\w\\d\\s\\-\\&]+,)*(DC=['\\w\\d\\s\\-\\&]+[,]*){2,})$/",
    isPumpable: false
  },
  {
    input: "/\\b(\\w+)\\s+\\1\\b/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:http|https|ftp|telnet|gopher|ms\\-help|file|notes):\\/\\/)?(?:(?:[a-z][\\w~%!&',;=\\-\\.$\\(\\)\\*\\+]*):.*@)?(?:(?:[a-z0-9][\\w\\-]*[a-z0-9]*\\.)*(?:(?:(?:(?:[a-z0-9][\\w\\-]*[a-z0-9]*)(?:\\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))(?::[0-9]+)?))?(?:(?:(?:\\/(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))+)*\\/(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))*)(?:\\?[^#]+)?(?:#[a-z0-9]\\w*)?)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "u0.",
    suffix: ""
  },
  {
    input:
      "/^(?:mailto:)?(?:[a-z][\\w~%!&',;=\\-\\.$\\(\\)\\*\\+]*)@(?:[a-z0-9][\\w\\-]*[a-z0-9]*\\.)*(?:(?:(?:[a-z0-9][\\w\\-]*[a-z0-9]*)(?:\\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "m@",
    pumpable: "3a.",
    suffix: ""
  },
  {
    input: "/^(?<username>[a-z][\\w.-]*)(?::(?<pwd>[\\w.-]*))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?:[a-z0-9][\\w\\-]*[a-z0-9]*\\.)*(?:(?:(?:[a-z0-9][\\w\\-]*[a-z0-9]*)(?:\\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "3a.",
    suffix: ""
  },
  {
    input:
      "/^(?:(?:\\.\\.\\/)|\\/)?(?:\\w(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))*\\w?)?(?:\\/\\w(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))*\\w?)*(?:\\?[^#]+)?(?:#[a-z0-9]\\w*)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "/0_",
    suffix: "\\x00"
  },
  {
    input:
      "/^(?<scheme>(?:http|https|ftp|telnet|gopher|ms\\-help|file|notes):\\/\\/)?(?:(?<user>[a-z][\\w~%!&',;=\\-\\.$\\(\\)\\*\\+]*):(?<password>.*)?@)?(?:(?<domain>(?:[a-z0-9]\\w*[a-z0-9]*\\.)*(?:(?:(?:[a-z0-9]\\w*[a-z0-9]*)(?:\\.[a-z0-9]+)?)|(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))))(?::(?<port>[0-9]+))?)?(?:(?<path>(?:\\/(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))+)*\\/(?:[\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(?:%\\d\\d))*)(?<params>\\?[^#]+)?(?<fragment>#[a-z0-9]\\w*)?)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/((http|https|ftp|telnet|gopher|ms\\-help|file|notes):\\/\\/)?(([a-z][\\w~%!&',;=\\-\\.$\\(\\)\\*\\+]*)(:.*)?@)?(([a-z0-9][\\w\\-]*[a-z0-9]*\\.)*(((([a-z0-9][\\w\\-]*[a-z0-9]*)(\\.[a-z0-9]+)?)|(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))(:[0-9]+)?))?(((\\/([\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(%\\d\\d))+)*\\/([\\w`~!$=;\\-\\+\\.\\^\\(\\)\\|\\{\\}\\[\\]]|(%\\d\\d))*)(\\?[^#]+)?(#[a-z0-9]\\w*)?)?/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^#[\\dA-Fa-f]{3}(?:[\\dA-Fa-f]{3}[\\dA-Fa-f]{0,2})?$/",
    isPumpable: false
  },
  {
    input: "/^[+]?\\d*$/",
    isPumpable: false
  },
  {
    input: "/^\\({0,1}0(2|3|7|8)\\){0,1}(\\ |-){0,1}[0-9]{4}(\\ |-){0,1}[0-9]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(?=^.{6,255}$)((?=.*\\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^[6]\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/^[SFTG]\\d{7}[A-Z]$/",
    isPumpable: false
  },
  {
    input: '/^"[^"]+"$/',
    isPumpable: false
  },
  {
    input: "/^[\\w]{1,}$/",
    isPumpable: false
  },
  {
    input: "/^\\$?([A-Za-z]{0,2})\\$?([0-9]{0,5}):?\\$?([A-Za-z]{0,2})\\$?([0-9]{0,5})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:\\s*(Sun|Mon|Tue|Wed|Thu|Fri|Sat)\\s*)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+?(0?[1-9]|[1-2][0-9]|3[01])\\s+(2[0-3]|[0-1][0-9]):([0-5][0-9]):(60|[0-5][0-9])\\s+((?:E|C|M|P)(?:ST|DT))\\s+(19[0-9]{2}|[2-9][0-9]{3}|[0-9]{2})/",
    isPumpable: false
  },
  {
    input: "/^(\\$|)([1-9]+\\d{0,2}(\\,\\d{3})*|([1-9]+\\d*))(\\.\\d{2})?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^(\\$|)([1-9]\\d{0,2}(\\,\\d{3})*|([1-9]\\d*))(\\.\\d{2})?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^(?<Drive>([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w].*))(?<Year>\\d{4})-(?<Month>\\d{1,2})-(?<Day>\\d{1,2})(?<ExtraText>.*)(?<Extension>.csv|.CSV)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[0-9]{4}((0[1-9])|(1[0-2]))$/",
    isPumpable: false
  },
  {
    input: "/^(((\\.\\.){1}\\/)*|(\\/){1})?(([a-zA-Z0-9]*)\\/)*([a-zA-Z0-9]*)+([.jpg]|[.gif])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "q",
    suffix: ""
  },
  {
    input: "/^\\w[a-zA-Z0-9öäüÖÄÜ\\.\\-_]+@[a-zA-Z0-9öäüÖÄÜ\\-_]+?\\.[a-zA-Z]{2,3}$/",
    wasParseError: "{ParsingData.NonAsciiInput(13, 195)}"
  },
  {
    input: "/^([a-z|A-Z]{1}[0-9]{3})[-]([0-9]{3})[-]([0-9]{2})[-]([0-9]{3})[-]([0-9]{1})/",
    isPumpable: false
  },
  {
    input: "/[^\\t]+|\\t(?=\\t)|\\t$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(9)}"
  },
  {
    input: "/^(?(FirstString|SecondString)yes|.*)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 40)}"
  },
  {
    input: "/^((?:.*(?!\\d))*(?:\\D*)?)(\\d+)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(7)}"
  },
  {
    input: "/[\\\\s+,]/",
    isPumpable: false
  },
  {
    input: "/<[a-zA-Z]+(\\s+[a-zA-Z]+\\s*=\\s*(\"([^\"]*)\"|'([^']*)'))*\\s*/>/",
    isPumpable: false
  },
  {
    input: "/^([\\w-]+\\.)*?[\\w-]+@[\\w-]+\\.([\\w-]+\\.)*?[\\w]+$/",
    isPumpable: false
  },
  {
    input: "/<!--[\\w\\W]*?-->/",
    isPumpable: false
  },
  {
    input:
      "/((((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?[+A-Za-z0-9!#$%&'*/=?\\^_`{}|\\~-]+(\\.[+A-Za-z0-9!#$%&'*/=?\\^_`{}|\\~-]+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?|(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?\\x22((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(([\\x21\\x23-\\x5b\\x5d-\\x7e]|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f])|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))))*(((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\x22(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/((((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?\\<((((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?[+A-Za-z0-9!#$%&'*/=?\\^_`{}|\\~-]+(\\.[+A-Za-z0-9!#$%&'*/=?\\^_`{}|\\~-]+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?|(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)*(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(\\(((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\x21-\\x27\\x2a-\\x5b\\x5d-\\x7e]|((\\\\([\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|\\x0a*\\x0d*([\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]\\x0a*\\x0d*)*))|\\\\(\\x00|[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x0a|\\x0d))|))*)+((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?\\))+)|((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*)))?\\x22((((([\\x20\\x09]*\\x0d\\x0a)?[\\x20\\x09]+)|[\\x20\\x09]+(\\x0d\\x0a[\\x20\\x09]+)*))?(([\\x21\\x23-\\/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[ \\w]{3,}([A-Za-z]\\.)?([ \\w]*\\#\\d+)?(\\r\\n| )[ \\w]{3,},\\x20[A-Za-z]{2}\\x20\\d{5}(-\\d{4})?$/",
    isPumpable: false
  },
  {
    input: "/(^\\d{1,2}\\.\\d{1,2}\\.\\d{4})|(^\\d{1,2}\\.\\d{1,2})|(^\\d{1,2})$/",
    isPumpable: false
  },
  {
    input: "/^07[789]-\\d{7}$/",
    isPumpable: false
  },
  {
    input: "/(?s)(?:\\e\\[(?:(\\d+);?)*([A-Za-z])(.*?))(?=\\e\\[|\\z)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(39)}"
  },
  {
    input: "/^(([a-zA-ZäöüÄÖÜ]\\D*)\\s+\\d+?\\s*.*)$/",
    wasParseError: "{ParsingData.NonAsciiInput(10, 195)}"
  },
  {
    input: "/^([^ \\x21-\\x26\\x28-\\x2C\\x2E-\\x40\\x5B-\\x60\\x7B-\\xAC\\xAE-\\xBF\\xF7\\xFE]+)$/",
    wasParseError: "{ParsingData.NonAsciiInput(41, 172)}"
  },
  {
    input: "/^((0(1\\d\\d[1-9])|([2-9]\\d\\d\\d))|(?(?=^(^9{5}))|[1-9]\\d{4}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(34, 40)}"
  },
  {
    input:
      "/^(((((((00|\\+)49[ \\-\\/]?)|0)[1-9][0-9]{1,4})[ \\-\\/]?)|((((00|\\+)49\\()|\\(0)[1-9][0-9]{1,4}\\)[ \\-\\/]?))[0-9]{1,7}([ \\-\\/]?[0-9]{1,5})?)$/",
    isPumpable: false
  },
  {
    input: "/^\\(\\d{3}\\) ?\\d{3}( |-)?\\d{4}|^\\d{3}( |-)?\\d{3}( |-)?\\d{4}/",
    isPumpable: false
  },
  {
    input:
      "/(?<Address1>(?:[a-zA-Z0-9\\x20\\x2E\\x2D])*(?:CIRCLE|CIR|MOUNTAIN|MTN|PARKWAY|PKWY|PKY|PLAZA|PLZA|PLZ|RIDGE|RDG|ROUTE|RTE|TURNPIKE|TURNPK|TPKE|TPK|WAY|WY|SOUTHEAST|SOUTHWEST|SOUTH|EAST|NORTHEAST|NORTHWEST|NORTH|WEST|ARCADE|ARC\\x2E|ARC|AVENUE|AVE\\x2E|AVE|BOULEVARD|BVD\\x2E|BVD|BLVD\\x2E|BLVD|CLOSE|CL\\x2E|CL|CRESENT|CRES\\x2E|CRES|DRIVE|DR\\x2E|DR|ESPLANADE|ESP\\x2E|ESP|GROVE|GR\\x2E|GR|HIGHWAY|HWY\\x2E|HWY|LANE|LN\\x2E|LN|PARADE|PDE\\x2E|PDE|PLACE\\x2E|PLACE|PL\\x2E|PL|ROAD|RD\\x2E|RD|SQUARE|SQ\\x2E|SQ|STREET|ST\\x2E|ST|TERRACE|TCE\\x2E|TCE|S\\x2E|W\\x2E|N\\x2E|E\\x2E|N|E|W|S))[,]*\\t*\\s(?<AptBldg>UNIT[a-zA-Z0-9\\x20\\x2D\\x3A]*|BASEMENT[a-zA-Z0-9\\x20\\x2D\\x3A]*|BSMT[a-zA-Z0-9\\x20\\x2D\\x3A]*|BUILDING[a-zA-Z0-9\\x20\\x2D\\x3A]*|DEPARTMENT[a-zA-Z0-9\\x20\\x2D\\x3A]*|DEPT[a-zA-Z0-9\\x20\\x2D\\x3A]*|FLOOR[a-zA-Z0-9\\x20\\x2D\\x3A]*|FL[a-zA-Z0-9\\x20\\x2D\\x3A]*|PENTHOUSE[a-zA-Z0-9\\x20\\x2D\\x3A]*|PH[a-zA-Z0-9\\x20\\x2D\\x3A]*|ROOM[a-zA-Z0-9\\x20\\x2D\\x3A]*|RM[a-zA-Z0-9\\x20\\x2D\\x3A]*|SLIP[a-zA-Z0-9\\x20\\x2D\\x3A]*|SPACE[a-zA-Z0-9\\x20\\x2D\\x3A]*|SPC[a-zA-Z0-9\\x20\\x2D\\x3A]*|SUITE[a-zA-Z0-9\\x20\\x2D\\x3A]*|\\x23[a-zA-Z0-9\\x20\\x2D\\x3A]*|APT[a-zA-Z0-9\\x20\\x2D\\x3A]*|BLDG[a-zA-Z0-9\\x20\\x2D\\x3A]*|PO\\sBOX\\x3A[a-zA-Z0-9\\x20\\x2D]*|P\\x2EO\\x2E\\sBOX[a-zA-Z0-9\\x20\\x2D]*|PO\\sBOX[a-zA-Z0-9\\x20\\x2D]*|BOX[a-zA-Z0-9\\x20\\x2D]*|\\x20*)\\x2C*\\x2E*\\t*(?<City>[a-zA-Z\\x20]*)[,]*\\t*\\x20*(?<State>AL|ALABAMA|AK|ALASKA|AZ|ARIZONA|AR|ARKANSAS|CA|CALIFORNIA|CO|COLORADO|CT|CONNECTICUT|DE|DELAWARE|FL|FLORIDA|GA|GEORGIA|HI|HAWAII|ID|IDAHO|IL|ILLNOIS|IN|INDIANA|IA|IOWA|KS|KANSAS|KY|KENTUCKY|LA|LOUISIANA|ME|MAINE|MD|MARYLAND|MA|MASSACHUSETTS|MI|MICHIGAN|MN|MINNESOTA|MS|MISSISSIPPI|MO|MISSOURI|MT|MONTANA|NE|NEBRASKA|NV|NEVADA|NH|NEW HAMPSHIRE|NJ|NEW JERSEY|NM|NEW MEXICO|NY|NEW YORK|NC|NORTH CAROLINA|ND|NORTH DAKOTA|OH|OHIO|OK|OKLAHOMA|OR|OREGON|PA|PENNSYLVANIA|RI|RHODE ISLAND|SC|SOUTH CAROLINA|SD|SOUTH DAKOTA|TN|TENNESSEE|TX|TEXAS|UT|UTAH|VT|VERMONT|VA|VIRGINIA|WA|WASHINGTON|DC|DISTRICT OF COLUMBIA|WASHINGTON DC|[a-zA-Z]{2})\\x2C*\\t*\\s*(?<ZipCode>[0-9\\x2D\\x20]{5,10}|\\x20*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012])) ([ -])? (?!00)\\d\\d([ -|])? (?!0000)\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^(((0[13578]|10|12)([-.\\/])(0[1-9]|[12][0-9]|3[01])([-.\\/])(\\d{4}))|((0[469]|11)([-.\\/])([0][1-9]|[12][0-9]|30)([-.\\/])(\\d{4}))|((02)([-.\\/])(0[1-9]|1[0-9]|2[0-8])([-.\\/])(\\d{4}))|((02)(\\.|-|\\/)(29)([-.\\/])([02468][048]00))|((02)([-.\\/])(29)([-.\\/])([13579][26]00))|((02)([-.\\/])(29)([-.\\/])([0-9][0-9][0][48]))|((02)([-.\\/])(29)([-.\\/])([0-9][0-9][2468][048]))|((02)([-.\\/])(29)([-.\\/])([0-9][0-9][13579][26])))$/",
    isPumpable: false
  },
  {
    input: "/^\\$?(\\d{1,3}(\\,\\d{3})*|(\\d+))(\\.\\d{0,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^\\$?([1-9]{1}[0-9]{0,2}(\\,[0-9]{3})*(\\.[0-9]{0,2})?|[1-9]{1}[0-9]{0,}(\\.[0-9]{0,2})?|0(\\.[0-9]{0,2})?|(\\.[0-9]{1,2})?)$/",
    isPumpable: false
  },
  {
    input: "/( xmlns:.*=[\",'].*[\",'])|( xmlns=[\",'].*[\",'])/",
    isPumpable: false
  },
  {
    input: "/(^\\d{1,5}$|^\\d{1,5}\\.\\d{1,2}$)/",
    isPumpable: false
  },
  {
    input:
      "/(?<raw_message>\\:(?<source>((?<nick>[^!]+)![~]{0,1}(?<user>[^@]+)@)?(?<host>[^\\s]+)) (?<command>[^\\s]+)( )?(?<parameters>[^:]+){0,1}(:)?(?<text>[^\\r^\\n]+)?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(\\(?\\+44\\)?\\s?(1|2|3|7|8)\\d{3}|\\(?(01|02|03|07|08)\\d{3}\\)?)\\s?\\d{3}\\s?\\d{3}|(\\(?\\+44\\)?\\s?(1|2|3|5|7|8)\\d{2}|\\(?(01|02|03|05|07|08)\\d{2}\\)?)\\s?\\d{3}\\s?\\d{4}|(\\(?\\+44\\)?\\s?(5|9)\\d{2}|\\(?(05|09)\\d{2}\\)?)\\s?\\d{3}\\s?\\d{3}/",
    isPumpable: false
  },
  {
    input: "/\\\\\\\\\\w+?(?:\\\\[\\w\\s$]+)+/",
    isPumpable: false
  },
  {
    input: "/((\\(\\d{3,4}\\)|\\d{3,4}-)\\d{4,9}(-\\d{1,5}|\\d{0}))|(\\d{4,12})/",
    isPumpable: false
  },
  {
    input: "/^\\d+((\\.|\\,)\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/<font[a-zA-Z0-9_\\^\\$\\.\\|\\{\\[\\}\\]\\(\\)\\*\\+\\?\\\\~`!@#%&-=;:'\",/\\n\\s]*>/",
    isPumpable: false
  },
  {
    input: "/^(([0-1]?[0-9])|([2][0-3])):([0-5]?[0-9])(:([0-5]?[0-9]))?$/",
    isPumpable: false
  },
  {
    input: "/(^[A-ZÀ-Ü]{1}[a-zà-ü']+\\s[a-zA-Zà-üÀ-Ü]+((([\\s\\.'])|([a-zà-ü']+))|[a-zà-ü']+[a-zA-Zà-üÀ-Ü']+))/",
    wasParseError: "{ParsingData.NonAsciiInput(6, 195)}"
  },
  {
    input:
      "/(^((((0[1-9])|([1-2][0-9])|(3[0-1]))|([1-9]))\\x2F(((0[1-9])|(1[0-2]))|([1-9]))\\x2F(([0-9]{2})|(((19)|([2]([0]{1})))([0-9]{2}))))$)/",
    isPumpable: false
  },
  {
    input: "/(^\\d{3}\\x2E\\d{3}\\x2E\\d{3}\\x2D\\d{2}$)/",
    isPumpable: false
  },
  {
    input: "/(^\\d{5}\\x2D\\d{3}$)/",
    isPumpable: false
  },
  {
    input: "/(^[0-9]{2,3}\\.[0-9]{3}\\.[0-9]{3}\\/[0-9]{4}-[0-9]{2}$)/",
    isPumpable: false
  },
  {
    input: "/(?!\\.)[a-z]{1,4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/((?:Microsoft)?.?(?:(?:Windows.NT.(?:[1-4].[0-9]))|(?:Win(?:dows)?.?NT).?[1-4](?:.?[0-9])?|NT[1-4]))/",
    isPumpable: false
  },
  {
    input: "/^[0-9,]+['][-](\\d|1[01])\"$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]+\\s*[A-Z]+)$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]+[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^0?.[0]{1,2}[1-9]{1}$|^0?.[1-9]{1}?\\d{0,2}$|^(1|1.{1}[0]{1,3})$|^0?.[0]{1}[1-9]{1}\\d{1}$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{0,3}?[0-9]{9}($[0-9]{0}|[A-Z]{1}))/",
    isPumpable: false
  },
  {
    input: "/(http(s?):\\/\\/|[a-zA-Z0-9\\-]+\\.)[a-zA-Z0-9\\/~\\-]+\\.[a-zA-Z0-9\\/~\\-_,&\\?\\.;]+[^\\.,\\s<]/",
    isPumpable: false
  },
  {
    input: "/https?:\\/\\/[^<>() ]+([ ](((?!https?:\\/\\/)[^<>() ])+)(?=[^<>() ]*[?!=%&-+\\/])[^<>() ]*)*/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(24)}"
  },
  {
    input: "/^[ABCEGHJKLMNPRSTVXY]{1}\\d{1}[A-Z]{1} *\\d{1}[A-Z]{1}\\d{1}$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z]+\\d+)|(\\d+[a-zA-Z]+))[a-zA-Z0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^\\s*[a-zA-Z0-9,&\\s]+\\s*$/",
    isPumpable: false
  },
  {
    input: "/(<(?:.*?)\\s)href\\s*=([\\s\"'])*/?([^\\2:#]+?)\\2((?:.*?)>)/",
    wasParseError: "{ParsingData.UnsupportedEscape(35, 50)}"
  },
  {
    input: "/^([0-9]|[1-9]\\d|[1-7]\\d{2}|800)$/",
    isPumpable: false
  },
  {
    input:
      "/((https?|ftp|gopher|telnet|file|notes|ms-help):((\\/\\/)|(\\\\\\\\))+[\\w\\d:#@%\\/;$()~_\\+-=\\\\\\.&]*)/",
    isPumpable: false
  },
  {
    input:
      "/((((http[s]?|ftp)[:]\\/\\/)([a-zA-Z0-9.-]+([:][a-zA-Z0-9.&%$-]+)*@)?[a-zA-Z][a-zA-Z0-9.-]+|[a-zA-Z][a-zA-Z0-9]+[.][a-zA-Z][a-zA-Z0-9.-]+)[.](com|edu|gov|mil|net|org|biz|pro|info|name|museum|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ax|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)([:][0-9]+)*(\\/[a-zA-Z0-9.,;?'\\\\+&%$#=~_-]+)*)/",
    isPumpable: false
  },
  {
    input: "/(\\bR(\\.|)R(\\.|)|RURAL\\s{0,}(ROUTE|RT(\\.|)))\\s{0,}\\d{1,}(,|)\\s{1,}\\bBOX\\s{0,}\\d/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(((0[13578]|10|12)([\\/])(0[1-9]|[12][0-9]|3[01])([\\/])([1-2][0,9][0-9][0-9]))|((0[469]|11)([\\/])([0][1-9]|[12][0-9]|30)([\\/])([1-2][0,9][0-9][0-9]))|((02)([\\/])(0[1-9]|1[0-9]|2[0-8])([\\/])([1-2][0,9][0-9][0-9]))|((02)([\\/])(29)(\\.|-|\\/)([02468][048]00))|((02)([\\/])(29)([\\/])([13579][26]00))|((02)([\\/])(29)([\\/])([0-9][0-9][0][48]))|((02)([\\/])(29)([\\/])([0-9][0-9][2468][048]))|((02)([\\/])(29)([\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input:
      "/(\\d{2}|\\d{4})(?:\\-)?([0]{1}\\d{1}|[1]{1}[0-2]{1})(?:\\-)?([0-2]{1}\\d{1}|[3]{1}[0-1]{1})(?:\\s)?([0-1]{1}\\d{1}|[2]{1}[0-3]{1})(?::)?([0-5]{1}\\d{1})(?::)?([0-5]{1}\\d{1})/",
    isPumpable: false
  },
  {
    input:
      "/^(0|[-]{1}([1-9]{1}[0-9]{0,1}|[1]{1}([0-1]{1}[0-9]{1}|[2]{1}[0-8]{1}))|(\\+)?([1-9]{1}[0-9]{0,1}|[1]{1}([0-1]{1}[0-9]{1}|[2]{1}[0-7]{1})))$/",
    isPumpable: false
  },
  {
    input: "/(0|(\\+)?([1-9]{1}[0-9]{0,1}|[1]{1}[0-9]{0,2}|[2]{1}([0-4]{1}[0-9]{1}|[5]{1}[0-5]{1})))/",
    isPumpable: false
  },
  {
    input:
      "/^(0|[-]{1}([1-9]{1}[0-9]{0,3}|[1-2]{1}[0-9]{1,4}|[3]{1}([0-1]{1}[0-9]{3}|[2]{1}([0-6]{1}[0-9]{2}|[7]{1}([0-5]{1}[0-9]{1}|([6]{1}[0-8]{1})))))|(\\+)?([1-9]{1}[0-9]{0,3}|[1-2]{1}[0-9]{1,4}|[3]{1}([0-1]{1}[0-9]{3}|[2]{1}([0-6]{1}[0-9]{2}|[7]{1}([0-5]{1}[0-9]{1}|([6]{1}[0-7]{1}))))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(0|(\\+)?([1-9]{1}[0-9]{0,3})|([1-5]{1}[0-9]{1,4}|[6]{1}([0-4]{1}[0-9]{3}|[5]{1}([0-4]{1}[0-9]{2}|[5]{1}([0-2]{1}[0-9]{1}|[3]{1}[0-5]{1})))))$/",
    isPumpable: false
  },
  {
    input:
      "/(0|[1-9]{1}[0-9]{0,8}|[1]{1}[0-9]{1,9}|[-]{1}[2]{1}([0]{1}[0-9]{8}|[1]{1}([0-3]{1}[0-9]{7}|[4]{1}([0-6]{1}[0-9]{6}|[7]{1}([0-3]{1}[0-9]{5}|[4]{1}([0-7]{1}[0-9]{4}|[8]{1}([0-2]{1}[0-9]{3}|[3]{1}([0-5]{1}[0-9]{2}|[6]{1}([0-3]{1}[0-9]{1}|[4]{1}[0-8]{1}))))))))|(\\+)?[2]{1}([0]{1}[0-9]{8}|[1]{1}([0-3]{1}[0-9]{7}|[4]{1}([0-6]{1}[0-9]{6}|[7]{1}([0-3]{1}[0-9]{5}|[4]{1}([0-7]{1}[0-9]{4}|[8]{1}([0-2]{1}[0-9]{3}|[3]{1}([0-5]{1}[0-9]{2}|[6]{1}([0-3]{1}[0-9]{1}|[4]{1}[0-7]{1})))))))))/",
    isPumpable: false
  },
  {
    input:
      "/^(0|(\\+)?[1-9]{1}[0-9]{0,8}|(\\+)?[1-3]{1}[0-9]{1,9}|(\\+)?[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))$/",
    isPumpable: false
  },
  {
    input:
      "/^\\\\\\\\[\\w-]+\\\\(([\\w()-][\\w\\s()-]*[\\w()-]+)|([\\w()-]+))\\$?(\\\\(([\\w()-][\\w\\s()-]*[\\w()-]+)|([\\w()-]+)))*\\\\?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "\\\\a\\(",
    pumpable: "\\((",
    suffix: "\\x00"
  },
  {
    input:
      "/(?<scheme>[a-zA-Z][a-zA-Z0-9\\+\\-\\.]*):(?:\\/\\/(?:(?<username>(?:[a-zA-Z0-9_~!&',;=\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))+):?(?:[a-zA-Z0-9_~!&',;=\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*@)?(?<host>(?:[a-zA-Z0-9_~!&',;=\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*)(?::(?<port>[0-9]*))?(?<path>(?:\\/(?:[a-zA-Z0-9_~!&',;=:@\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*)*)|(?<path>\\/(?:(?:[a-zA-Z0-9_~!&',;=:@\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))+(?:\\/(?:[a-zA-Z0-9_~!&',;=:@\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*)*)?)|(?<path>(?:[a-zA-Z0-9_~!&',;=:@\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))+(?:\\/(?:[a-zA-Z0-9_~!&',;=:@\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*)*))?(?:\\?(?<query>(?:[a-zA-Z0-9_~!&',;=:@\\/?\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*))?(?:\\#(?<fragment>(?:[a-zA-Z0-9_~!&',;=:@\\/?\\.\\-\\$\\(\\)\\*\\+]|(?:%[0-9a-fA-F]{2}))*))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[^_][a-zA-Z0-9_]+[^_]@{1}[a-z]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/",
    isPumpable: false
  },
  {
    input:
      "/^[^_.]([a-zA-Z0-9_]*[.]?[a-zA-Z0-9_]+[^_]){2}@{1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]+[a-zA-Z]*)(\\s|\\-)?([A-Z]+[a-zA-Z]*)?(\\s|\\-)?([A-Z]+[a-zA-Z]*)?$/",
    isPumpable: false
  },
  {
    input:
      "/\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*([,;]\\s*\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^[-\\w`~!@#$%^&*\\(\\)+={}|\\[\\]\\\\:\";'<>?,.\\/ ]*$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z].*$/",
    isPumpable: false
  },
  {
    input: "/<!--[\\s\\S]*?-->/",
    isPumpable: false
  },
  {
    input: "/<\\/?(\\w+)(\\s+\\w+=(\\w+|\"[^\"]*\"|'[^']*'))*>/",
    isPumpable: false
  },
  {
    input: "/^\\{?[a-fA-F\\d]{8}-([a-fA-F\\d]{4}-){3}[a-fA-F\\d]{12}\\}?$/",
    isPumpable: false
  },
  {
    input: "/<[a-zA-Z][^>]*\\son\\w+=(\\w+|'[^']*'|\"[^\"]*\")[^>]*>/",
    isPumpable: false
  },
  {
    input: "/[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+/",
    isPumpable: false
  },
  {
    input:
      "/@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+(?:,@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+)*/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z0-9!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]/",
    isPumpable: false
  },
  {
    input:
      "/[a-zA-Z0-9!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]+(?:\\.[a-zA-Z0-9!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]+)*@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+/",
    isPumpable: false
  },
  {
    input:
      "/^<(?:@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+(?:,@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+)*:)?([a-zA-Z0-9!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]+(?:\\.[a-zA-Z0-9!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]+)*@[a-z0-9][a-z0-9-]*[a-z0-9](?:\\.[a-z0-9][a-z0-9-]*[a-z0-9])+)>$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z]+\\-?[a-zA-Z]+/",
    isPumpable: false
  },
  {
    input: "/[\\/,,\\/.,\\/=,\\s]([0-6]\\d{2}|7[0-6]\\d|77[0-2])(\\s|\\-)?(\\d{2})\\2(\\d{4})[\\/,,\\/.,\\s]/",
    isPumpable: false
  },
  {
    input: "/style=\"[^\"]*\"|'[^']*'/",
    isPumpable: false
  },
  {
    input: "/^(([01][0-9]|[012][0-3]):([0-5][0-9]))*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "00:00",
    suffix: "!"
  },
  {
    input: "/(([1-9]|[0][1-9])|1[012])[- \\/.](([1-9]|[0][1-9])|[12][0-9]|3[01])[- \\/.](19|20)\\d\\d/",
    isPumpable: false
  },
  {
    input: "/^\\d*[0-9](|.\\d*[0-9]|,\\d*[0-9])?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\[(?<name>[^\\]]*)\\](?<value>[^\\[]*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input: "/^(\\+?420)? ?[0-9]{3} ?[0-9]{3} ?[0-9]{3}$/",
    isPumpable: false
  },
  {
    input:
      "/jar:file:\\/(([A-Z]:)?\\/([A-Z 0-9 * ( ) + \\- & $ # @ _ . ! ~ \\/])+)(\\/[A-Z 0-9 _ ( ) \\[ \\] - = + _ ~]+\\.jar!)/",
    isPumpable: false
  },
  {
    input:
      "/(jar:)?file:\\/(([A-Z]:)?\\/([A-Z0-9\\*\\()\\+\\-\\&$#@_.!~\\[\\]\\/])+)((\\/[A-Z0-9_()\\[\\]\\-=\\+_~]+\\.jar!)|([^!])(\\/com\\/regexlib\\/example\\/))/",
    isPumpable: false
  },
  {
    input:
      "/^[A-PR-UWYZ]([0-9]([A-HJKSTUW]|[0-9])?|[A-HK-Y][0-9]([ABEHMNPRVWXY]|[0-9])) [0-9][ABD-HJLNP-UW-Z]{2}|GIR 0AA$/",
    isPumpable: false
  },
  {
    input: "/^(\\+65)?\\d{8}$/",
    isPumpable: false
  },
  {
    input: "/^(([0]?[1-9]|[1-2][0-3])(:)([0-5][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^(([0-1]?[1-9]|2[0-3])(:)([0-5][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]+\\d{0,2},(\\d{3},)*\\d{3}(\\.\\d{1,2})?|[1-9]+\\d*(\\.\\d{1,2})?)$/",
    isPumpable: false
  },
  {
    input:
      "/(((0[13578]|10|12)([-.\\/])(0[1-9]|[12][0-9]|3[01])([-.\\/])(\\d{4}))|((0[469]|11)([-.\\/])([0][1-9]|[12][0-9]|30)([-.\\/])(\\d{4}))|((2)([-.\\/])(0[1-9]|1[0-9]|2[0-8])([-.\\/])(\\d{4}))|((2)(\\.|-|\\/)(29)([-.\\/])([02468][048]00))|((2)([-.\\/])(29)([-.\\/])([13579][26]00))|((2)([-.\\/])(29)([-.\\/])([0-9][0-9][0][48]))|((2)([-.\\/])(29)([-.\\/])([0-9][0-9][2468][048]))|((2)([-.\\/])(29)([-.\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input: "/^(((\\d{1,3})(,\\d{3})*)|(\\d+))(.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/[^\\d^\\-^\\,^\\x20]+/",
    isPumpable: false
  },
  {
    input:
      "/^[1-9]{1}[0-9]{3}-(0[1-9]{1}|1[0-2]{1})-([0-2]{1}[1-9]{1}|3[0-1]{1}) ([0-1]{1}[0-9]{1}|2[0-3]{1}):[0-5]{1}[0-9]{1}:[0-5]{1}[0-9]{1}$/",
    isPumpable: false
  },
  {
    input: "/^([0-1][0-9]|[2][0-3]):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/([a-zA-Z]{2}[0-9]{1,2}\\s{0,1}[0-9]{1,2}[a-zA-Z]{2})/",
    isPumpable: false
  },
  {
    input:
      "/^[A-Fa-f0-9]{32}$|({|\\()?[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}(}|\\))?$|^({)?[0xA-Fa-f0-9]{3,10}(, {0,1}[0xA-Fa-f0-9]{3,6}){2}, {0,1}({)([0xA-Fa-f0-9]{3,4}, {0,1}){7}[0xA-Fa-f0-9]{3,4}(}})$/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(19)}"
  },
  {
    input:
      "/^(\\d|\\d{1,9}|1\\d{1,9}|20\\d{8}|213\\d{7}|2146\\d{6}|21473\\d{5}|214747\\d{4}|2147482\\d{3}|21474835\\d{2}|214748364[0-7])$/",
    isPumpable: false
  },
  {
    input: "/([oO0]*)([|:;=X^])([-']*)([)(oO0\\]\\[DPp*>X^@])/",
    isPumpable: false
  },
  {
    input: "/(?:Error|Warning|Exception)/",
    isPumpable: false
  },
  {
    input: "/^(([+]31|0031)\\s\\(0\\)([0-9]{9})|([+]31|0031)\\s0([0-9]{9})|0([0-9]{9}))$/",
    isPumpable: false
  },
  {
    input: "/(^\\x20*)|(\\x20*$)|(\\x20(?=\\x20))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(23)}"
  },
  {
    input: "/^(([1-4][0-9])|(0[1-9])|(5[0-2]))\\/[1-2]\\d{3}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1}[0-9]{1}[a-zA-Z]{1}(\\-| |){1}[0-9]{1}[a-zA-Z]{1}[0-9]{1}$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/\\/^(?:(?:0?[13578]|1[02])|(?:0?[469]|11)(?!\\/31)|(?:0?2)(?:(?!\\/3[01]|\\/29\\/(?:(?:0[^48]|[13579][^26]|[2468][^048])00|(?:\\d{2}(?:0[^48]|[13579][^26]|[2468][^048]))))))\\/(?:0?[1-9]|[12][0-9]|3[01])\\/(?:0?19|20)\\d{2}$\\//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(38)}"
  },
  {
    input: "/^-?([1-8]?[1-9]|[1-9]0)\\.{1}\\d{1,6}/",
    isPumpable: false
  },
  {
    input: "/^-?([1]?[1-7][1-9]|[1]?[1-8][0]|[1-9]?[0-9])\\.{1}\\d{1,6}/",
    isPumpable: false
  },
  {
    input:
      "/^[a-z0-9!$'*+\\-_]+(\\.[a-z0-9!$'*+\\-_]+)*@([a-z0-9]+(-+[a-z0-9]+)*\\.)+([a-z]{2}|aero|arpa|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|travel)$/",
    isPumpable: false
  },
  {
    input:
      "/^[a-zA-Z]{4}((\\d{2}((0[13578]|1[02])(0[1-9]|[12]\\d|3[01])|(0[13456789]|1[012])(0[1-9]|[12]\\d|30)|02(0[1-9]|1\\d|2[0-8])))|([02468][048]|[13579][26])0229)(H|M)(AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|SM|NE)([a-zA-Z]{3})([a-zA-Z0-9\\s]{1})\\d{1}$+/",
    isPumpable: false
  },
  {
    input: "/([\\r\\n ]*\\/\\/[^\\r\\n]*)+/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: '/(@\\s*".*?")|("([^"\\\\]|\\\\.)*?")/',
    isPumpable: false
  },
  {
    input:
      "/\\b(?<KEYWORD>abstract|event|new|struct|as|explicit|null|switch|base|extern|object|this|bool|false|operator|throw|break|finally|out|true|byte|fixed|override|try|case|float|params|typeof|catch|for|private|uint|char|foreach|protected|ulong|checked|goto|public|unchecked|class|if|readonly|unsafe|const|implicit|ref|ushort|continue|in|return|using|decimal|int|sbyte|virtual|default|interface|sealed|volatile|delegate|internal|short|void|do|is|sizeof|while|double|lock|stackalloc|else|long|static|enum|namespace|string)\\b/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input: "/\\w*/",
    isPumpable: false
  },
  {
    input: "/(^\\d{1,3}([,]\\d{3})*$)|(^\\d{1,16}$)/",
    isPumpable: false
  },
  {
    input: "/^\\#?[A-Fa-f0-9]{3}([A-Fa-f0-9]{3})?$/",
    isPumpable: false
  },
  {
    input: "/([1-9]{1,2})?(d|D)([1-9]{1,3})((\\+|-)([1-9]{1,3}))?/",
    isPumpable: false
  },
  {
    input: "/^([A-Z][a-z]+)\\s([A-Z][a-zA-Z-]+)$/",
    isPumpable: false
  },
  {
    input: "/https?:\\/\\/(?!\\S*?domainname\\.tld\\/)\\S*?\\//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(9)}"
  },
  {
    input: "/^(97(8|9))?\\d{9}(\\d|X)$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:[+\\-]?\\$?)|(?:\\$?[+\\-]?))?(?:(?:\\d{1,3}(?:(?:,\\d{3})|(?:\\d))*(?:\\.(?:\\d*|\\d+[eE][+\\-]\\d+))?)|(?:\\.\\d+(?:[eE][+\\-]\\d+)?))$/",
    isPumpable: false
  },
  {
    input:
      "/([A-Za-z]{0,}[\\.\\,\\s]{0,}[A-Za-z]{1,}[\\.\\s]{1,}[0-9]{1,2}[\\,\\s]{0,}[0-9]{4})| ([0-9]{0,4}[-,\\s]{0,}[A-Za-z]{3,9}[-,\\s]{0,}[0-9]{1,2}[-,\\s]{0,}[A-Za-z]{0,8})| ([0-9]{1,4}[\\/\\.\\-][0-9]{1,4}[\\/\\.\\-][0-9]{1,4})/",
    isPumpable: false
  },
  {
    input: "/([0-9]{1,2}[:][0-9]{1,2}[:]{0,2}[0-9]{0,2}[\\s]{0,}[AMPamp]{0,2})/",
    isPumpable: false
  },
  {
    input: "/^([A-Za-z0-9]\\s?)+([,]\\s?([A-Za-z0-9]\\s?)+)*$/",
    isPumpable: false
  },
  {
    input: "/[?&]([^&#=]+)(?:=([^&#]*))?/",
    isPumpable: false
  },
  {
    input: "/&(?!([a-zA-Z0-9#]{1,6};))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^\\((([2-7][0-9]{2})|(8(0[^0]|[^0]0|1\\d|2[^2]|[^2]2|3[^3]|[^3]3|4[^4]|[^4]4|5[^5]|[^5]5|6[^6]|[^6]6|7[^7]|[^7]7|8[^8]|[^8]8|9\\d){1})|(9(0[^0]|[^0]0|[1-9][1-9])))\\)\\s?[0-9]{3}(-|\\s)?[0-9]{4}$|^(([2-7][0-9]{2})|(8(0[^0]|[^0]0|1\\d|2[^2]|[^2]2|3[^3]|[^3]3|4[^4]|[^4]4|5[^5]|[^5]5|6[^6]|[^6]6|7[^7]|[^7]7|8[^8]|[^8]8|9\\d){1})|(9(0[^0]|[^0]0|[1-9][1-9])))-?[0-9]{3}-?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^(?=\\d)(?:(?:(?:(?:(?:0?[13578]|1[02])(\\/)31)\\1|(?:(?:0?[1,3-9]|1[0-2])(\\/)(?:29|30)\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})|(?:0?2(\\/)29\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))|(?:(?:0?[1-9])|(?:1[0-2]))(\\/)(?:0?[1-9]|1\\d|2[0-8])\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2}))($|\\ (?=\\d)))?(((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\ [AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$\\//",
    wasParseError: "{ParsingData.InvalidBackreference(84)}"
  },
  {
    input:
      '/^((?<DRIVE>[a-z]:)|(\\\\\\\\(?<SERVER>[0-9]*[a-z\\-][a-z0-9\\-]*)\\\\(?<VOLUME>[^\\.\\x01-\\x1F\\\\""\\*\\?<>:|\\\\/][^\\x01-\\x1F\\\\""\\*\\?|><:\\\\/]*)))?(?<FOLDERS>(?<FOLDER1>(\\.|(\\.\\.)|([^\\.\\x01-\\x1F\\\\""\\*\\?|><:\\\\/][^\\x01-\\x1F\\\\""\\*\\?<>:|\\\\/]*)))?(?<FOLDERm>[\\\\/](\\.|(\\.\\.)|([^\\.\\x01-\\x1F\\\\""\\*\\?|><:\\\\/][^\\x01-\\x1F\\\\""\\*\\?<>:|\\\\/]*)))*)?[\\\\/]?$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input:
      '/preg_match_all("/([\\(\\+])?([0-9]{1,3}([\\s])?)?([\\+|\\(|\\-|\\)|\\s])?([0-9]{2,4})([\\-|\\)|\\.|\\s]([\\s])?)?([0-9]{2,4})?([\\.|\\-|\\s])?([0-9]{4,8})\\/",$string, $phones);/',
    isPumpable: false
  },
  {
    input:
      "/(https:[\\/][\\/]|http:[\\/][\\/]|www.)[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?\\/?([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~])*$/",
    isPumpable: false
  },
  {
    input: "/(?<Nbr>[\\+-]?((\\d*\\,\\d+)|(\\d*\\.\\d+)|\\d+))\\s*(?<Unit>mm|cm|dm|min|km|s|m|h)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(\\(?\\d\\d\\d\\)?)?( |-|\\.)?\\d\\d\\d( |-|\\.)?\\d{4,4}(( |-|\\.)?[ext\\.]+ ?\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/\\/^([0-9a-zA-Z]+|[a-zA-Z]:(\\\\(\\w[\\w ]*.*))+|\\\\(\\\\(\\w[\\w ]*.*))+)\\.[0-9a-zA-Z]{1,3}$//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\0",
    pumpable: "\\0\\0",
    suffix: ""
  },
  {
    input: "/(^\\b\\d+-\\d+$\\b)|(^\\b\\d+$\\b)/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{3,4})$/",
    isPumpable: false
  },
  {
    input:
      "/(<meta\\s+)*((name\\s*=\\s*(\"|')(?<name>[^'(\"|')]*)(\"|')){1}|content\\s*=\\s*(\"|')(?<content>[^'(\"|')]*)(\"|')|scheme\\s*=\\s*(\"|')(?<scheme>[^'(\"|')]*)(\"|'))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(31, 60)}"
  },
  {
    input: "/^([EV])?\\d{3,3}(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^([EV])?\\d{3,3}(\\.\\d{1,2})?(, *([EV])?\\d{3,3}(\\.\\d{1,2})?)*$/",
    isPumpable: false
  },
  {
    input: "/^\\d{4,4}[A-Z0-9]$/",
    isPumpable: false
  },
  {
    input: "/^\\d{4,4}[A-Z0-9](, *\\d{4,4})[A-Z0-9]*$/",
    isPumpable: false
  },
  {
    input: "/(\\A|(.*,))VALUE(\\z|([,]?.))/",
    isPumpable: false
  },
  {
    input: "/^[\\w0-9]+( [\\w0-9]+)*$/",
    isPumpable: false
  },
  {
    input: "/((?<strElement>(^[A-Z0-9-;=]*:))(?<strValue>(.*)))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/\\/^[a-zA-Záéíóú]+$\\//",
    wasParseError: "{ParsingData.NonAsciiInput(8, 195)}"
  },
  {
    input: "/\\/^(www\\.|http:\\/\\/|https:\\/\\/|http:\\/\\/www\\.|https:\\/\\/www\\.)[a-z0-9]+\\.[a-z]{2,4}$\\//",
    isPumpable: false
  },
  {
    input: "/^([1-zA-Z0-1@.\\s]{1,255})$/",
    isPumpable: false
  },
  {
    input: '/(\\(")([0-9]*)(\\")/',
    isPumpable: false
  },
  {
    input: '/(")([0-9]*)(",")([0-9]*)("\\))/',
    isPumpable: false
  },
  {
    input:
      "/^(((((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])-(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]))|((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]))),)*)(((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^\\d{1,2}\\/\\d{2,4}$/",
    isPumpable: false
  },
  {
    input: "/(^(\\d|,)*\\.?\\d*[1-9]+\\d*$)|(^[1-9]+(\\d|,)*\\.\\d*$)|(^[1-9]+(\\d|,)*\\d*$)/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d{2})(?=.*[A-Z]{2})(?=.*[\\D,\\W,\\S]{2})(?=.*[a-z]).{15,30}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^((4\\d{3})|(5[1-5]\\d{2}))(-?|\\040?)(\\d{4}(-?|\\040?)){3}|^(3[4,7]\\d{2})(-?|\\040?)\\d{6}(-?|\\040?)\\d{5}/",
    isPumpable: false
  },
  {
    input: "/<script[^>]*>[\\w|\\t|\\r|\\W]*<\\/script>/",
    isPumpable: false
  },
  {
    input: "/(<input )(.*?)(>)/",
    isPumpable: false
  },
  {
    input: "/^(BE)[0-1]{1}[0-9]{9}$|^((BE)|(BE ))[0-1]{1}(\\d{3})([.]{1})(\\d{3})([.]{1})(\\d{3})/",
    isPumpable: false
  },
  {
    input: "/^\\s*(([\\w-]+\\.)+[\\w-]+|([a-zA-Z]{1}|[\\w-]{2,}))@(\\w+\\.)+[A-Za-z]{2,5}$/",
    isPumpable: false
  },
  {
    input: "/^\\s*((([\\w-]+\\.)+[\\w-]+|([a-zA-Z]{1}|[\\w-]{2,}))@(\\w+\\.)+[A-Za-z]{2,5}[?= ]?[?=,;]?[?= ]?)+?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "aa.a@a.aA",
    pumpable: "a.a.a@a.AAA.AA-.-@0.AAA.AA",
    suffix: "\\x00"
  },
  {
    input: "/^((http:\\/\\/www\\.)|(www\\.)|(http:\\/\\/))[a-zA-Z0-9._-]+\\.[a-zA-Z.]{2,5}$/",
    isPumpable: false
  },
  {
    input: "/^\\$?([0-9]{1,3},([0-9]{3},)*[0-9]{3}|[0-9]+)(.[0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input:
      '/^((\\"[^\\"\\f\\n\\r\\t\\v\\b]+\\")|([\\w\\!\\#\\$\\%\\&\\\'\\*\\+\\-\\~\\/\\^\\`\\|\\{\\}]+(\\.[\\w\\!\\#\\$\\%\\&\\\'\\*\\+\\-\\~\\/\\^\\`\\|\\{\\}]+)*))@((\\[(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))\\])|(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))|((([A-Za-z0-9\\-])+\\.)+[A-Za-z\\-]+))$/',
    wasParseError: "{ParsingData.UnsupportedEscape(18, 118)}"
  },
  {
    input:
      "/^[a-zA-Z0-9]+([a-zA-Z0-9\\-\\.]+)?\\.(aero|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly| ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk| pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr| st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zr|zw|AERO|BIZ|COM|COOP|EDU|GOV|INFO|INT|MIL|MUSEUM|NAME|NET|ORG|AC|/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(^[ÑA-Z][a-záéíóúñ'ÑA-Z]*$)|(^[ÑA-Z][a-záéíóúñ'ÑA-Z]*[- ]^[ÑA-Z][a-záéíóúñ'ÑA-Z]*$)/",
    wasParseError: "{ParsingData.NonAsciiInput(3, 195)}"
  },
  {
    input:
      "/^((((((0?[1-9])|([1-2][0-9])|(3[0-1]))-(([jJ][aA][nN])|([mM][aA][rR])|([mM][aA][yY])|([jJ][uU][lL])|([aA][uU][gG])|([oO][cC][tT])|([dD][eE][cC])))|(((0?[1-9])|([1-2][0-9])|(30))-(([aA][pP][rR])|([jJ][uU][nN])|([sS][eE][pP])|([nN][oO][vV])))|(((0?[1-9])|(1[0-9])|(2[0-8]))-([fF][eE][bB])))-(20(([13579][01345789])|([2468][1235679]))))|(((((0?[1-9])|([1-2][0-9])|(3[0-1]))-(([jJ][aA][nN])|([mM][aA][rR])|([mM][aA][yY])|([jJ][uU][lL])|([aA][uU][gG])|([oO][cC][tT])|([dD][eE][cC])))|(((0?[1-9])|([1-2][0-9])|(30))-(([aA][pP][rR])|([jJ][uU][nN])|([sS][eE][pP])|([nN][oO][vV])))|(((0?[1-9])|(1[0-9])|(2[0-9]))-([fF][eE][bB])))-(20(([13579][26])|([2468][048])))))$/",
    isPumpable: false
  },
  {
    input: "/^(\\$?)((\\d{1,20})|(\\d{1,2}((,?\\d{3}){0,6}))|(\\d{3}((,?\\d{3}){0,5})))$/",
    isPumpable: false
  },
  {
    input: "/^\\d+?(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input:
      '/(?<pgnGame>\\s*(?:\\[\\s*(?<tagName>\\w+)\\s*"(?<tagValue>[^"]*)"\\s*\\]\\s*)+(?:(?<moveNumber>\\d+)(?<moveMarker>\\.|\\.{3})\\s*(?<moveValue>(?:[PNBRQK]?[a-h]?[1-8]?x?[a-h][1-8](?:\\=[PNBRQK])?|O(-?O){1,2})[\\+#]?(\\s*[\\!\\?]+)?)(?:\\s*(?<moveValue2>(?:[PNBRQK]?[a-h]?[1-8]?x?[a-h][1-8](?:\\=[PNBRQK])?|O(-?O){1,2})[\\+#]?(\\s*[\\!\\?]+)?))?\\s*(?:\\(\\s*(?<variation>(?:(?<varMoveNumber>\\d+)(?<varMoveMarker>\\.|\\.{3})\\s*(?<varMoveValue>(?:[PNBRQK]?[a-h]?[1-8]?x?[a-h][1-8](?:\\=[PNBRQK])?|O(-?O){1,2})[\\+#]?(\\s*[\\!\\?]+)?)(?:\\s*(?<varMoveValue2>(?:[PNBRQK]?[a-h]?[1-8]?x?[a-h][1-8](?:\\=[PNBRQK])?|O(-?O){1,2})[\\+#]?(\\s*[\\!\\?]+)?))?\\s*(?:\\((?<varVariation>.*)\\)\\s*)?(?:\\{(?<varComment>[^\\}]*?)\\}\\s*)?)*)\\s*\\)\\s*)*(?:\\{(?<comment>[^\\}]*?)\\}\\s*)?)*(?<endMarker>1\\-?0|0\\-?1|1/2\\-?1/2|\\*)?\\s*)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^0[1-6]{1}(([0-9]{2}){4})|((\\s[0-9]{2}){4})|((-[0-9]{2}){4})$/",
    isPumpable: false
  },
  {
    input: "/^(\\d)?(\\d|,)*\\.?\\d{1,2}$/",
    isPumpable: false
  },
  {
    input: "/^(\\+[0-9]{2,}[0-9]{4,}[0-9]*)(x?[0-9]{1,})?$/",
    isPumpable: false
  },
  {
    input: "/^([A-HJ-TP-Z]{1}\\d{4}[A-Z]{3}|[a-z]{1}\\d{4}[a-hj-tp-z]{3})$/",
    isPumpable: false
  },
  {
    input:
      "/(([IXCM])\\2{3,})|[^IVXLCDM]|([IL][LCDM])|([XD][DM])|(V[VXLCDM])|(IX[VXLC])|(VI[VX])|(XC[LCDM])|(LX[LC])|((CM|DC)[DM])|(I[VX]I)|(X[CL]X)|(C[DM]C)|(I{2,}[VX])|(X{2,}[CL])|(C{2,}[DM])/",
    wasParseError: "{ParsingData.InvalidBackreference(9)}"
  },
  {
    input:
      '/^\\\\{2}[-\\w]+\\\\(([^"*/:?|<>\\\\,;[\\]+=.\\x00-\\x20]|\\.[.\\x20]*[^"*/:?|<>\\\\,;[\\]+=.\\x00-\\x20])([^"*/:?|<>\\\\,;[\\]+=\\x00-\\x1F]*[^"*/:?|<>\\\\,;[\\]+=\\x00-\\x20])?)\\\\([^"*/:?|<>\\\\.\\x00-\\x20]([^"*/:?|<>\\\\\\x00-\\x1F]*[^"*/:?|<>\\\\.\\x00-\\x20])?\\\\)*$/',
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      '/^[A-Za-z]:\\\\([^"*/:?|<>\\\\.\\x00-\\x20]([^"*/:?|<>\\\\\\x00-\\x1F]*[^"*/:?|<>\\\\.\\x00-\\x20])?\\\\)*$/',
    isPumpable: false
  },
  {
    input:
      '/^([A-Za-z]:|\\\\{2}([-\\w]+|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\\\\(([^"*/:?|<>\\\\,;[\\]+=.\\x00-\\x20]|\\.[.\\x20]*[^"*/:?|<>\\\\,;[\\]+=.\\x00-\\x20])([^"*/:?|<>\\\\,;[\\]+=\\x00-\\x1F]*[^"*/:?|<>\\\\,;[\\]+=\\x00-\\x20])?))\\\\([^"*/:?|<>\\\\.\\x00-\\x20]([^"*/:?|<>\\\\\\x00-\\x1F]*[^"*/:?|<>\\\\.\\x00-\\x20])?\\\\)*$/',
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/(^([\\w]+[^\\W])([^\\W]\\.?)([\\w]+[^\\W]$))/",
    isPumpable: false
  },
  {
    input:
      '/^[/]*([^/\\\\ \\:\\*\\?"\\<\\>\\|\\.][^/\\\\\\:\\*\\?\\"\\<\\>\\|]{0,63}/)*[^/\\\\ \\:\\*\\?"\\<\\>\\|\\.][^/\\\\\\:\\*\\?\\"\\<\\>\\|]{0,63}$/',
    isPumpable: false
  },
  {
    input: "/wsrp_rewrite\\?(?<wsrp_uri>[\\w%:&\\\\/;.]*)/wsrp_rewrite/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(16, 60)}"
  },
  {
    input: "/^(0*100{1,1}\\.?((?<=\\.)0*)?%?$)|(^0*\\d{0,2}\\.?((?<=\\.)\\d*)?%?)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(16)}"
  },
  {
    input:
      "/^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$/",
    isPumpable: false
  },
  {
    input:
      "/\\b(?:a(?:[nst]|re|nd)?|b[ey]|f(?:or|rom)|i[nst]?|o[fnr]|t(?:o|hat|he|his)|w(?:as|h(?:at|en|ere|ich|o)|i(?:th|ll)))\\b/",
    isPumpable: false
  },
  {
    input: "/(^\\d{9}[V|v|x|X]$)/",
    isPumpable: false
  },
  {
    input: "/([0-9a-zA-Z]+)|([0-9a-zA-Z][0-9a-zA-Z\\\\s]+[0-9a-zA-Z]+)/",
    isPumpable: false
  },
  {
    input: "/(?<commentblock>((?m:^[\\t ]*\\/{2}[^\\n\\r\\v\\f]+[\\n\\r\\v\\f]*){2,})|(\\/\\*[\\w\\W]*?\\*\\/))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[^\\*]{0,}[\\*]{0,1}[^\\*]{0,}$/",
    isPumpable: false
  },
  {
    input: '/<(?i)(?=.[^>]*runat=["]?server)(?<TYPE>\\S[^>\\s]+).[^>]*id=["]?(?<NAME>\\w+).[^>]*>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(33, 60)}"
  },
  {
    input: "/(?=^.{1,254}$)(^(?:(?!\\d+\\.)[a-zA-Z0-9_\\-]{1,63}\\.?)+(?:[a-zA-Z]{2,})$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?=^.{1,254}$)(^(?:[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]\\.?)+(?:[a-zA-Z]{2,})$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^(([0-9])|([0-1][0-9])|([2][0-3])):(([0-9])|([0-5][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^(\\$)?(([1-9]\\d{0,2}(\\,\\d{3})*)|([1-9]\\d*)|(0))(\\.\\d{2})?$/",
    isPumpable: false
  },
  {
    input: "/<!--((?!-->).)*-->/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/\\/\\*((?!\\*\\/).)*\\*\\//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/^(?<CountryPrefix>DK-)?(?<ZipCode>[0-9]{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^([0-9a-fA-F]{1,2})(\\s[0-9a-fA-F]{1,2})*$/",
    isPumpable: false
  },
  {
    input:
      "/(http|ftp|https):\\/\\/(\\w[\\w\\-_\\.]*\\.)?([_\\-\\w]+)(:[0-9]+)?([\\/[\\w_\\.-]+]*)\\/(\\.?\\w[\\w._-]*[\\w_-])?(#\\w+)?([\\w\\-\\.,@?^=%&:\\~\\+#]*[\\w\\-\\@?^=%&\\/\\~\\+#])?/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/^(?:\\s*(Sun|Mon|Tue|Wed|Thu|Fri|Sat),\\s*)?(0?[1-9]|[1-2][0-9]|3[01])\\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+(19[0-9]{2}|[2-9][0-9]{3}|[0-9]{2})\\s+(2[0-3]|[0-1][0-9]):([0-5][0-9])(?::(60|[0-5][0-9]))?\\s+([-\\+][0-9]{2}[0-5][0-9]|(?:UT|GMT|(?:E|C|M|P)(?:ST|DT)|[A-IK-Z]))(\\s*\\((\\\\\\(|\\\\\\)|(?<=[^\\\\])\\((?<C>)|(?<=[^\\\\])\\)(?<-C>)|[^\\(\\)]*)*(?(C)(?!))\\))*\\s*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(314, 60)}"
  },
  {
    input:
      "/^\\s*\\w+\\s*\\((\\s*((\"|')([^\\3]+|\\\\\\3)\\3|\\$?[a-zA-Z_\\x7f-\\xff][a-zA-Z0-9_\\x7f-\\xff]|[0-9]*)\\s*,?)*\\s*\\)/",
    wasParseError: "{ParsingData.UnsupportedEscape(26, 51)}"
  },
  {
    input:
      "/^(?<lat>(-?(90|(\\d|[1-8]\\d)(\\.\\d{1,6}){0,1})))\\,{1}(?<long>(-?(180|(\\d|\\d\\d|1[0-7]\\d)(\\.\\d{1,6}){0,1})))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[a-zA-Z0-9]+([a-zA-Z0-9\\-\\.]+)?\\.(com|org|net|mil|edu|COM|ORG|NET|MIL|EDU)$/",
    isPumpable: false
  },
  {
    input: "/^[0-9](\\.[0-9]+)?$/",
    isPumpable: false
  },
  {
    input: "/(\\d{1,3},(\\d{3},)*\\d{3}(\\.\\d{1,3})?|\\d{1,3}(\\.\\d{3})?)$/",
    isPumpable: false
  },
  {
    input: "/\\$[0-9]?[0-9]?[0-9]?((\\,[0-9][0-9][0-9])*)?(\\.[0-9][0-9]?)?$/",
    isPumpable: false
  },
  {
    input: "/^[2-5](2|4|6|8|0)(A(A)?|B|C|D(D(D)?)?|E|F|G|H)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z][a-z]+((eir|(n|l)h)(a|o))$/",
    isPumpable: false
  },
  {
    input: "/^(\\d)(\\.)(\\d)+\\s(x)\\s(10)(e|E|\\^)(-)?(\\d)+$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}|[A-Z]\\d|\\d[A-Z])[1-9](\\d{1,3})?$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z][a-z]+(tz)?(man|berg)$/",
    isPumpable: false
  },
  {
    input: "/^(Op(.|us))(\\s)[1-9](\\d)*((,)?(\\s)N(o.|um(.|ber))\\s[1-9](\\d)*)?$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z][a-z]+((e(m|ng)|str)a)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{4}[1-8](\\d){2}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{3}(\\s)?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^((\\d){3})(-)?(\\d){2}(-)?(\\d){4}(A|B[1-7]?|M|T|C[1-4]|D)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z][a-z]+((i)?e(a)?(u)?[r(re)?|x]?)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]{3}(\\d|[A-Z]){8,12}$/",
    isPumpable: false
  },
  {
    input: "/^R(\\d){8}/",
    isPumpable: false
  },
  {
    input: "/^[A-Z][a-z]+(o(i|u)(n|(v)?r(t)?|s|t|x)(e(s)?)?)$/",
    isPumpable: false
  },
  {
    input: "/^[A-G](b|#)?((m(aj)?|M|aug|dim|sus)([2-7]|9|13)?)?(\\/[A-G](b|#)?)?$/",
    isPumpable: false
  },
  {
    input: "/~[A-Z][a-z]+(b|ch|d|g|j|k|l|m|n|p|r|s|t|v|z)(ian)$/",
    isPumpable: false
  },
  {
    input: "/\\b[P|p]?(OST|ost)?\\.?\\s*[O|o|0]?(ffice|FFICE)?\\.?\\s*[B|b][O|o|0]?[X|x]?\\.?\\s+[#]?(\\d+)\\b/",
    isPumpable: false
  },
  {
    input: "/\\/*d(9,15)/",
    wasParseError: "{ParsingData.UnbalancedPatternMarker(0)}"
  },
  {
    input: "/^((0[123456789]|1[0-2])(0[1-3]|1[0-9]|2[0-9]))|((0[13456789]|1[0-2])(30))|((0[13578]|1[02])(31))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?!0?2\\/3)(?!0?2\\/29\\/.{3}[13579])(?!0?2\\/29\\/.{2}[02468][26])(?!0?2\\/29\\/.{2}[13579][048])(?!(0?[469]|11)\\/31)(?!0?2\\/29\\/[13579][01345789]0{2})(?!0?2\\/29\\/[02468][1235679]0{2})(0?[1-9]|1[012])\\/(0?[1-9]|[12][0-9]|3[01])\\/([0-9]{4})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^213\\.61\\.220\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])$/",
    isPumpable: false
  },
  {
    input: "/(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])^[\\w!@$#.+-]{8,64}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/((0[1-9])|(1[02]))\\/\\d{2}/",
    isPumpable: false
  },
  {
    input:
      "/((http\\:\\/\\/|https\\:\\/\\/|ftp\\:\\/\\/)|(www.))+(([a-zA-Z0-9\\.-]+\\.[a-zA-Z]{2,4})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(\\/[a-zA-Z0-9%:\\/-_\\?\\.'~]*)?/",
    isPumpable: false
  },
  {
    input:
      "/(((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp):\\/\\/)|(www\\.))+(([a-zA-Z0-9\\._-]+\\.[a-zA-Z]{2,6})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(\\/[a-zA-Z0-9\\&%_\\.\\/-~-]*)?/",
    isPumpable: false
  },
  {
    input:
      "/(http:\\/\\/|https:\\/\\/)([a-zA-Z0-9]+\\.[a-zA-Z0-9\\-]+|[a-zA-Z0-9\\-]+)\\.[a-zA-Z\\.]{2,6}(\\/[a-zA-Z0-9\\.\\?=\\/#%&\\+-]+|\\/|)/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^0[23489]{1}(\\-)?[^0\\D]{1}\\d{6}$/",
    isPumpable: false
  },
  {
    input: "/^0(5[012345678]|6[47]){1}(\\-)?[^0\\D]{1}\\d{5}$/",
    isPumpable: false
  },
  {
    input: "/.+\\.([^.]+)$/",
    isPumpable: false
  },
  {
    input: "/^(smtp)\\.([\\w\\-]+)\\.[\\w\\-]{2,3}$/",
    isPumpable: false
  },
  {
    input: "/^(?:(?:[\\w\\.\\-_]+@[\\w\\d]+(?:\\.[\\w]{2,6})+)[,;]?\\s?)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a@a.a0",
    pumpable: "a@a.a0.AA.@0.00",
    suffix: "\\x00"
  },
  {
    input:
      "/(([Gg]rand)?([Ff]ather|[Mm]other|mom|pop|son|daughter|parent|((p|m)a)|uncle|aunt)s?)|(([cC]ousin)?((?<=[cC]ousin)\\s+(?=brother|sister))?(?<siblings>brother|sister)?((?<=brother|sister)s?)?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(138, 60)}"
  },
  {
    input:
      "/^((A[LKSZR])|(C[AOT])|(D[EC])|(F[ML])|(G[AU])|(HI)|(I[DLNA])|(K[SY])|(LA)|(M[EHDAINSOT])|(N[EVHJMYCD])|(MP)|(O[HKR])|(P[WAR])|(RI)|(S[CD])|(T[NX])|(UT)|(V[TIA])|(W[AVIY]))$/",
    isPumpable: false
  },
  {
    input:
      "/^((A[LKZR])|(C[AOT])|(D[EC])|(FL)|(GA)|(HI)|(I[DLNA])|(K[SY])|(LA)|(M[EDAINSOT])|(N[EVHJMYCD])|(O[HKR])|(PA)|(RI)|(S[CD])|(T[NX])|(UT)|(V[TA])|(W[AVIY]))$/",
    isPumpable: false
  },
  {
    input:
      "/^((http:\\/\\/)|(https:\\/\\/))((([a-zA-Z0-9_-]*).?([a-zA-Z0-9_-]*))|(([a-zA-Z0-9_-]*).?([a-zA-Z0-9_-]*).?([a-zA-Z0-9_-]*)))\\/?([a-zA-Z0-9_\\/?%=&+#.-~]*)$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z0-9_\\-\\._]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-_]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$/",
    isPumpable: false
  },
  {
    input: "/<(?![!\\/]?[ABIU][>\\s])[^>]*>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(http:\\/\\/)?(www\\.)?youtu(be)?\\.([a-z])+\\/(watch(.*?)(\\?|\\&)v=)?(.*?)(&(.)*)?$/",
    isPumpable: false
  },
  {
    input: "/^([9]{1})([234789]{1})([0-9]{8})$/",
    isPumpable: false
  },
  {
    input: "/[\\w\\-_\\+\\(\\)]{0,}[\\.png|\\.PNG]{4}/",
    isPumpable: false
  },
  {
    input:
      "/(http:\\/\\/)?(www\\.)?(youtube|yimg|youtu)\\.([A-Za-z]{2,4}|[A-Za-z]{2}\\.[A-Za-z]{2})\\/(watch\\?v=)?[A-Za-z0-9\\-_]{6,12}(&[A-Za-z0-9\\-_]{1,}=[A-Za-z0-9\\-_]{1,})*/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]{1}[-][0-9]{7}[-][a-zA-Z]{1}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9+]{5}-[0-9+]{7}-[0-9]{1}$/",
    isPumpable: false
  },
  {
    input: "/^\\s*-?((\\d{1,3}(\\.(\\d){3})*)|\\d*)(,\\d{1,2})?\\s?(\\u20AC)?\\s*$/",
    wasParseError: "{ParsingData.UnsupportedEscape(49, 117)}"
  },
  {
    input: "/^(([a-z])+.)+[A-Z]([a-z])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a{",
    pumpable: "aaa{",
    suffix: ""
  },
  {
    input:
      "/^(http|https|ftp)\\:\\/\\/(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])|([a-zA-Z0-9_\\-\\.])+\\.(com|net|org|edu|int|mil|gov|arpa|biz|aero|name|coop|info|pro|museum|uk|me))((:[a-zA-Z0-9]*)?\\/?([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~])*)$/",
    isPumpable: false
  },
  {
    input: "/^.*(yourdomain.com).*$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z]){4}(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MC|MN|ME|MS|MA|MZ|MM|MA|NR|NP|NL|AN|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|SH|KN|LC|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SK|SI|SB|SO|ZA|GS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})$/",
    isPumpable: false
  },
  {
    input:
      "/^(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Sept|Oct(ober)?|Nov(ember)?|Dec(ember)?)$/",
    isPumpable: false
  },
  {
    input: '/(?<=(?:^|,)")(?:[^"]|"")+/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^(([1][0-2])|([0]?[1-9]{1}))\\/(([0-2]?\\d{1})|([3][0,1]{1}))\\/(([1]{1}[9]{1}[9]{1}\\d{1})|([2-9]{1}\\d{3}))$/",
    isPumpable: false
  },
  {
    input: "/(^([0-9]|[0-1][0-9]|[2][0-3]):([0-5][0-9])$)|(^([0-9]|[1][0-9]|[2][0-3])$)/",
    isPumpable: false
  },
  {
    input: "/^\\s+|\\s+$/",
    isPumpable: false
  },
  {
    input: "/[0][x][0-9a-fA-F]+/",
    isPumpable: false
  },
  {
    input: "/(?<=[\\w\\s](?:[\\.\\!\\? ]+[\\x20]*[\\x22\\xBB]*))(?:\\s+(?![\\x22\\xBB](?!\\w)))/",
    wasParseError: "{ParsingData.NonAsciiInput(35, 187)}"
  },
  {
    input: "/\\d{4}-\\d{4}-\\d{2}|\\d{5}-\\d{3}-\\d{2}|\\d{5}-\\d{4}-\\d{1}|\\d{5}-\\*\\d{3}-\\d{2}/",
    isPumpable: false
  },
  {
    input:
      "/^((([0]?[1-9]|1[0-2])(:|\\.)(00|15|30|45)?( )?(AM|am|aM|Am|PM|pm|pM|Pm))|(([0]?[0-9]|1[0-9]|2[0-3])(:|\\.)(00|15|30|45)?))$/",
    isPumpable: false
  },
  {
    input: "/^[0]|[0-3]\\.(\\d?\\d?)|[4].[0]$/",
    isPumpable: false
  },
  {
    input: "/^(\\w(([.-])*)(\\s)?)+$/",
    isPumpable: false
  },
  {
    input:
      "/^(000000[1-9])$|^(00000[1-9][0-9])$|^(0000[1-9][0-9][0-9])$|^(000[1-9][0-9][0-9][0-9])$|^(00[1-9][0-9][0-9][0-9][0-9])$|^(0[1-9][0-9][0-9][0-9][0-9][0-9])$|^([1-9][0-9][0-9][0-9][0-9][0-9][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^((0[1-9])|(1[0-2]))\\/((0[1-9])|(1[0-9])|(2[0-9])|(3[0-1]))\\/(\\d{4})$/",
    isPumpable: false
  },
  {
    input:
      "/^(((\\d{4}((0[13578]|1[02])(0[1-9]|[12]\\d|3[01])|(0[13456789]|1[012])(0[1-9]|[12]\\d|30)|02(0[1-9]|1\\d|2[0-8])))|((\\d{2}[02468][048]|\\d{2}[13579][26]))0229)){0,8}$/",
    isPumpable: false
  },
  {
    input: "/([a-z\\s.\\-_'])*<\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*\\>/",
    isPumpable: false
  },
  {
    input:
      "/([a-z\\s.\\-_'])*<\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*\\>|^\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*/",
    isPumpable: false
  },
  {
    input: "/^\\d*$|^\\d+$*[a-zA-Z]*$;^\\d+$|^\\d+$*[a-zA-Z]+$/",
    isPumpable: false
  },
  {
    input: "/(?<=[[]tex[]]).*?(?=[[]\\/tex[]])/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/(?<!aaa((?!bbb)[\\s\\S])*)SomeText/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^(\\d{5}-\\d{4}|\\d{5}|\\d{9})$|^([a-zA-Z]\\d[a-zA-Z]( )?\\d[a-zA-Z]\\d)$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z0-9]*/",
    isPumpable: false
  },
  {
    input:
      "/^(([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}\\/(DC=['\\w\\d\\s\\-\\&]+[,]*){2,})|((\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\/(DC=['\\w\\d\\s\\-\\&]+[,]*){2,})|((DC=['\\w\\d\\s\\-\\&]+[,]*){2,})$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^[-_.[:alnum:]]+@((([[:alnum:]]|[[:alnum:]][[:alnum:]-]*[[:alnum:]])\\.)+(ad|ae|aero|af|ag|ai|al|am|an|ao|aq|ar|arpa|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|biz|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|com|coop|cr|cs|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|edu|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gh|gi|gl|gm|gn|gov|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|in|info|int|io|iq|ir|is|it|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mil|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|name|nc|ne|net|nf|ng|ni|nl|no|np|nr|nt|nu|nz|om|org|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|pro|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)$|(([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5])\\.){3}([0-9][0-9]?|[0-1][0-9][0-9]|[2][0-4][0-9]|[2][5][0-5]))$\\/i/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^(http\\:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(?:\\/\\S*)?(?:[a-zA-Z0-9_])+\\.(?:[a-zA-Z])+)$/",
    isPumpable: false
  },
  {
    input: "/[^\\u0009\\u000A\\u000D\\u0020-\\uD7FF\\uE000-\\uFFFD\\u10000-\\u10FFFF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(3, 117)}"
  },
  {
    input: "/^-?\\d+(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^\\d+(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/[+]346[0-9]{8}/",
    isPumpable: false
  },
  {
    input:
      "/^[\\(]? ([^0-1]){1}([0-9]){2}([-,\\),\\/,\\.])*([ ])?([^0-1]){1}([0-9]){2}[ ]?[-]?[\\/]?[\\.]? ([0-9]){4}$/",
    isPumpable: false
  },
  {
    input: '/\\.(?=([^"]*"[^"]*")*(?![^"]*"))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/[^.]*\\((?>[^()]+|\\((?<DEPTH>)|\\)(?<-DEPTH>))*(?(DEPTH)(?!))\\)[^.]*|[^.]+/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(21, 60)}"
  },
  {
    input: "/^100$|^\\s*(\\d{0,2})((\\.|\\,)(\\d*))?\\s*\\%?\\s*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{1,}(,[0-9]+){0,}$/",
    isPumpable: false
  },
  {
    input:
      "/^(1|2|3)((\\d{2}((0[13578]|1[02])(0[1-9]|[12]\\d|3[01])|(0[13456789]|1[012])(0[1-9]|[12]\\d|30)|02(0[1-9]|1\\d|2[0-8])))|([02468][048]|[13579][26])0229)(\\d{5})$/",
    isPumpable: false
  },
  {
    input: "/^([A-ZÄÖÜ][a-zäöüß]+(([.] )|( )|([-])))+[1-9][0-9]{0,3}[a-z]?$/",
    wasParseError: "{ParsingData.NonAsciiInput(6, 195)}"
  },
  {
    input: "/^[^<^>]*$/",
    isPumpable: false
  },
  {
    input:
      "/(?<!%)(?:%%)*%(?(([1-9]\\d?)!([\\-\\+0\\ \\#])?(\\d+|\\*)?(\\.\\*|\\.\\d+)?([hLIw]|l{1,2}|I32|I64)?([cCdiouxXeEfgGaAnpsSZ])!)|(?:([1-9]\\d?)(?![!\\d])))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(16, 40)}"
  },
  {
    input:
      "/(?<!%)(?:%%)*%([\\-\\+0\\ \\#])?(\\d+|\\*)?(\\.\\*|\\.\\d+)?([hLIw]|l{1,2}|I32|I64)?([cCdiouxXeEfgGaAnpsSZ])/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/\\{\\\\\\*\\\\bkmkstart\\s(.*?)\\}/",
    isPumpable: false
  },
  {
    input: "/^([9]{1})+(6|3|2|1{1})+([0-9]{7})$/",
    isPumpable: false
  },
  {
    input: "/(1 )?\\d{3} \\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input:
      "/^([0]\\d|[1][0-2])\\/([0-2]\\d|[3][0-1])\\/([2][01]|[1][6-9])\\d{2}(\\s([0-1]\\d|[2][0-3])(\\:[0-5]\\d){1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/((^((1[8-9]\\d{2})|([2-9]\\d{3}))(10|12|0?[13578])(3[01]|[12][0-9]|0?[1-9])$)|(^((1[8-9]\\d{2})|([2-9]\\d{3}))(11|0?[469])(30|[12][0-9]|0?[1-9])$)|(^((1[8-9]\\d{2})|([2-9]\\d{3}))(0?2)(2[0-8]|1[0-9]|0?[1-9])$)|(^([2468][048]00)(0?2)(29)$)|(^([3579][26]00)(0?2)(29)$)|(^([1][89][0][48])(0?2)(29)$)|(^([2-9][0-9][0][48])(0?2)(29)$)|(^([1][89][2468][048])(0?2)(29)$)|(^([2-9][0-9][2468][048])(0?2)(29)$)|(^([1][89][13579][26])(0?2)(29)$)|(^([2-9][0-9][13579][26])(0?2)(29)$))/",
    isPumpable: false
  },
  {
    input: "/(^[0]{1}$|^[-]?[1-9]{1}\\d*$)/",
    isPumpable: false
  },
  {
    input:
      "/(^((?<salutation>[MRD]\\S+)[ ]+)?(?<first>\\S+)[ ]+((?<middle>\\S+)[ ]+)??(?<last>\\S+)([ ]+(?<suffix>(PHD|MD|RN|JR|II|SR|III)))?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input: "/^.*(?=.{6,})(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\\W]).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input:
      "/^([\\(]{1}[0-9]{3}[\\)]{1}[ |\\-]{0,1}|^[0-9]{3}[\\-| ])?[0-9]{3}(\\-| ){1}[0-9]{4}(([ ]{0,1})|([ ]{1}[0-9]{3,4}|))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\/^[0-9a-fA-F]+$\\//",
    isPumpable: false
  },
  {
    input: "/\\b([0-1]?\\d{1,2}|2[0-4]\\d|25[0-5])(\\.([0-1]?\\d{1,2}|2[0-4]\\d|25[0-5])){3}\\b/",
    isPumpable: false
  },
  {
    input: "/^[-+]?\\d+(\\.\\d{2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^[a-zA-Z0-9]+([_.-]?[a-zA-Z0-9]+)?@[a-zA-Z0-9]+([_-]?[a-zA-Z0-9]+)*([.]{1})[a-zA-Z0-9]+([.]?[a-zA-Z0-9]+)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "aa-a@0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input: "/^[^<>&~\\s^%A-Za-z\\\\][^A-Za-z%^\\\\<>]{1,25}$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}[0-9]{3}\\s{0,1}?[a-zA-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^(\\(\\d{3}\\)|\\d{3})[\\s.-]?\\d{3}[\\s.-]?\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?<Contry>\\d{1,1})(?<5>[- ]?)?)?(?:(?<1>[(])?(?<AreaCode>[2-9]\\d{2})(?(1)[)])(?(1)(?<2>[ ])|(?:(?<3>[-])|(?<4>[ ])))?)?(?<Prefix>[1-9]\\d{2})(?(AreaCode)(?:(?(1)(?(2)[- ]|[-]?))|(?(3)[-])|(?(4)[- ]))|[- ]?)(?<Suffix>\\d{4})(?:[ ]?[#xXeE]?(?<Ext>\\d{2,4}))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input:
      "/^\\+?1[0-7]\\d(\\.\\d+)?$)|(^\\+?([1-9])?\\d(\\.\\d+)?$)|(^-180$)|(^-1[1-7]\\d(\\.\\d+)?$)|(^-[1-9]\\d(\\.\\d+)?$)|(^\\-\\d(\\.\\d+)?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^\\+?([1-8])?\\d(\\.\\d+)?$)|(^-90$)|(^-(([1-8])?\\d(\\.\\d+)?$))/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^((1[01])|(\\d)):[0-5]\\d(:[0-5]\\d)?\\s?([apAP][Mm])?$/",
    isPumpable: false
  },
  {
    input: "/^<\\s*(td|TD)\\s*(\\w|\\W)*\\s*>(\\w|\\W)*<\\/(td|TD)>$/",
    isPumpable: false
  },
  {
    input:
      "/^((([1]\\d{2})|(22[0-3])|([1-9]\\d)|(2[01]\\d)|[1-9]).(([1]\\d{2})|(2[0-4]\\d)|(25[0-5])|([1-9]\\d)|\\d).(([1]\\d{2})|(2[0-4]\\d)|(25[0-5])|([1-9]\\d)|\\d).(([1]\\d{2})|(2[0-4]\\d)|(25[0-5])|([1-9]\\d)|\\d))$/",
    isPumpable: false
  },
  {
    input: "/(.*\\.([wW][mM][aA])|([mM][pP][3])$)/",
    isPumpable: false
  },
  {
    input:
      "/^[-]?P(?!$)(?:(?<year>\\d+)+Y)?(?:(?<month>\\d+)+M)?(?:(?<days>\\d+)+D)?(?:T(?!$)(?:(?<hours>\\d+)+H)?(?:(?<minutes>\\d+)+M)? (?:(?<seconds>\\d+(?:\\.\\d+)?)+S)?)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(16, 60)}"
  },
  {
    input: "/(\\s*\\S*){2}(ipsum)(\\S*\\s*){2}/",
    isPumpable: false
  },
  {
    input: "/^(0|([1-9]\\d{0,3}|[1-5]\\d{4}|[6][0-5][0-5]([0-2]\\d|[3][0-5])))$/",
    isPumpable: false
  },
  {
    input: "/\\/\\*.+?\\*\\//",
    isPumpable: false
  },
  {
    input: "/^([1-9]{1}(([0-9])?){2})+(,[0-9]{1}[0-9]{2})*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "1",
    pumpable: "11",
    suffix: "!"
  },
  {
    input: "/[\\+]{0,1}(\\d{10,13}|[\\(][\\+]{0,1}\\d{2,}[\\13)]*\\d{5,13}|\\d{2,6}[\\-]{1}\\d{2,13}[\\-]*\\d{3,13})/",
    wasParseError: "{ParsingData.UnsupportedEscape(41, 49)}"
  },
  {
    input: "/<a[\\s]+[^>]*?href[\\s]?=[\\s\\\"\\']*(.*?)[\\\"\\']*.*?>([^<]+|.*?)?<\\/a>/",
    isPumpable: false
  },
  {
    input: "/^(([0-1][0-9]|2[0-3])[0-5][0-9]\\-([0-1][0-9]|2[0-3])[0-5][0-9]|[C|c]losed)$/",
    isPumpable: false
  },
  {
    input: "/(\\/\\/-->\\s*)?<\\/?SCRIPT([^>]*)>(\\s*<!--\\s)?/",
    isPumpable: false
  },
  {
    input: "/^\\{?[a-fA-F\\d]{32}\\}?$/",
    isPumpable: false
  },
  {
    input: "/^\\b(29[0-9]|2[0-9][0-9]|[01]?[0-9][0-9]?)\\\\/(29[0-9]|2[0-9][0-9]|[01]?[0-9][0-9]?)$/",
    isPumpable: false
  },
  {
    input: "/((www|http)(\\W+\\S+[^).,:;?\\]\\} \\r\\n$]+))/",
    isPumpable: false
  },
  {
    input: "/[0-9][.][0-9]{3}$/",
    isPumpable: false
  },
  {
    input: "/(?:^.*\\r*\\n*)*?(?:(?=^\\s*GO\\s*$)|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(18)}"
  },
  {
    input: "/^((0{1})?([0-3]{0,1}))(\\.[0-9]{0,2})?$|^(4)(\\.[0]{1,2})?$|^((0{1})?([0-4]{0,1}))(\\.)?$/",
    isPumpable: false
  },
  {
    input:
      "/^(([A-Za-z0-9]+_+)|([A-Za-z0-9]+\\-+)|([A-Za-z0-9]+\\.+)|([A-Za-z0-9]+\\++))*[A-Za-z0-9]+@((\\w+\\-+)|(\\w+\\.))*\\w{1,63}\\.[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input:
      "/(?<url>(?<protocol>http(s?)|ftp)\\:\\/\\/(?<host>(?<hostname>((?<subdomain>([a-z]\\w*\\.)*[a-z]\\w*)\\.)?((?<ip>(\\d{1,3}\\.){3}\\d{1,3})|((?<org>[a-z]\\w*)\\.(?<domain>[a-z]{2,3}))))?(\\:(?<port>\\d+))?)(?<path>(?<directory>(\\/.*)*\\/)?(?<file>[a-z]\\w*\\.\\w+)?)?(\\#(?<hash>[^?\\n\\r]+))?(\\?(?<search>(\\&?[^\\=\\n\\r]+\\=[^\\&\\n\\r]*)+))?)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^(0{0,1}[1-9][0-9]){1}(\\s){0,1}(\\-){0,1}(\\s){0,1}[1-9]{1}([0-9]{3}|[0-9]{4})(\\-){0,1}(\\s){0,1}[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z][a-zA-Z0-9_\\-\\,\\.]{5,31}/",
    isPumpable: false
  },
  {
    input: "/^(\\+){0,1}\\d{1,10}$/",
    isPumpable: false
  },
  {
    input: "/^((\\+92)|(0092))-{0,1}\\d{3}-{0,1}\\d{7}$|^\\d{11}$|^\\d{4}-\\d{7}$/",
    isPumpable: false
  },
  {
    input:
      "/([,!@#$%^&*()\\[\\]]+|\\\\\\.\\.|\\\\\\\\\\.|\\.\\.\\\\\\|\\.\\\\\\|\\.\\.\\/|\\.\\/|\\/\\.\\.|\\/\\.|;|(?<![A-Z]):)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(74)}"
  },
  {
    input:
      "/^[_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)?@[a-zA-Z0-9-]+(((\\.[0-9]{1,3}){0,3})|((\\.(co|com|net|org|edu|gov|mil|aero|coop|info|museum|name|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|fr|fx|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nt|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zr|zw)){1,2}))$/",
    isPumpable: false
  },
  {
    input:
      "/(script)|(<)|(>)|(%3c)|(%3e)|(SELECT) |(UPDATE) |(INSERT) |(DELETE)|(GRANT) |(REVOKE)|(UNION)|(&lt;)|(&gt;)/",
    isPumpable: false
  },
  {
    input: "/(^([0-9]+[.]+[0-9]+)|(0)$)/",
    isPumpable: false
  },
  {
    input: "/^(100(\\.0{0,2}?)?$|([1-9]|[1-9][0-9])(\\.\\d{1,2})?)$/",
    isPumpable: false
  },
  {
    input:
      "/^((([0]?[1-9]|1[0-2])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?( )?(AM|am|aM|Am|PM|pm|pM|Pm))|(([0]?[0-9]|1[0-9]|2[0-3])(:|\\.)[0-5][0-9]((:|\\.)[0-5][0-9])?))$/",
    isPumpable: false
  },
  {
    input: "/(^1300\\d{6}$)|(^1800|1900|1902\\d{6}$)|(^0[2|3|7|8]{1}[0-9]{8}$)|(^13\\d{4}$)|(^04\\d{2,3}\\d{6}$)/",
    isPumpable: false
  },
  {
    input: "/^(( )*\\£{0,1}( )*)\\d*(.\\d{1,2})?$/",
    wasParseError: "{ParsingData.NonAsciiInput(6, 194)}"
  },
  {
    input:
      "/(([a-zA-Z]{3}[0-9]{3})|(\\w{2}-\\w{2}-\\w{2})|([0-9]{2}-[a-zA-Z]{3}-[0-9]{1})|([0-9]{1}-[a-zA-Z]{3}-[0-9]{2})|([a-zA-Z]{1}-[0-9]{3}-[a-zA-Z]{2}))/",
    isPumpable: false
  },
  {
    input:
      "/((EQD[^']*')(RFF[^']*'){0,9}(EQN[^']*')?(TMD[^']*'){0,9}(DTM[^']*'){0,9}(LOC[^']*'){0,9}(MEA[^']*'){0,9}(DIM[^']*'){0,9}(TMP[^']*'){0,9}(RNG[^']*'){0,9}(SEL[^']*'){0,9}(FTX[^']*'){0,9}(DGS[^']*'){0,9}(EQA[^']*'){0,9}(NAD[^']*')?)((TDT[^']*')(RFF[^']*'){0,9}(LOC[^']*'){0,9}(DTM[^']*'){0,9})?/",
    isPumpable: false
  },
  {
    input:
      "/(LOC[^']*')(GID[^']*')?(GDS[^']*')?(FTX[^']*'){0,9}(MEA[^']*'){1,9}(DIM[^']*'){0,9}(TMP[^']*')?(RNG[^']*')?(LOC[^']*'){0,9}(RFF[^']*')((EQD[^']*')(EQA[^']*'){0,9}(NAD[^']*')?){0,3}/",
    isPumpable: false
  },
  {
    input:
      "/^((\\D*[a-z]\\D*[A-Z]\\D*)|(\\D*[A-Z]\\D*[a-z]\\D*)|(\\D*\\W\\D*[a-z])|(\\D*\\W\\D*[A-Z])|(\\D*[a-z]\\D*\\W)|(\\D*[A-Z]\\D*\\W))$/",
    isPumpable: false
  },
  {
    input: "/^.*(?=.{6,10})(?=.*[a-zA-Z].*[a-zA-Z].*[a-zA-Z].*[a-zA-Z])(?=.*\\d.*\\d).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input: "/<!\\[CDATA\\[([^\\]]*)\\]\\]>/",
    isPumpable: false
  },
  {
    input:
      "/^(19|20)[0-9]{2}-((01|03|05|07|08|10|12)-(0[1-9]|[12][0-9]|3[01]))|(02-(0[1-9]|[12][0-9]))|((04|06|09|11)-(0[1-9]|[12][0-9]|30))$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0?[13578])|(1[02]))[\\-]?((0?[1-9]|[0-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-]?((0?[1-9]|[0-2][0-9])|(30)))|(0?[2][\\-]?(0?[1-9]|[0-2][0-9])))[\\-]?\\d{2}$/",
    isPumpable: false
  },
  {
    input: "/(.*\\.jpe?g|.*\\.JPE?G)/",
    isPumpable: false
  },
  {
    input:
      "/(^([1-9]|[1][0-2]):([0-5][0-9])(\\s{0,1})(AM|PM|am|pm|aM|Am|pM|Pm{2,2})$)|(^([0-9]|[1][0-9]|[2][0-3]):([0-5][0-9])$)|(^([1-9]|[1][0-2])(\\s{0,1})(AM|PM|am|pm|aM|Am|pM|Pm{2,2})$)|(^([0-9]|[1][0-9]|[2][0-3])$)/",
    isPumpable: false
  },
  {
    input:
      "/^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\-\\.]+\\.(com|org|net|mil|edu|COM|ORG|NET|MIL|EDU)$/",
    isPumpable: false
  },
  {
    input: "/megaupload\\.com.*(?:\\?|&)(?:(?:folderi)?d|f)=([A-Z-a-z0-9]{8})/",
    isPumpable: false
  },
  {
    input:
      "/^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/",
    isPumpable: false
  },
  {
    input:
      "/\\b([a-z]+)(?:(?<=emphas|fantas)|(?<!ba|ma|pr|se|s))([iy])z(a(?:bl[ey]|tion(?:|al(?:|ly)|s))|es?|ed|ers?|ing)\\b/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/\\b([a-z]+)(?:(?<=ic|[ai]m|[^a-z]pr|[eiou][tr])|(?<![rd]a|c|gu|m|parad|o|p|r|[acrs]t|v|w))([iy])s(a(?:bl[ey]|tion(?:|al(?:|ly)|s))|e|ed|ers?|(?<!ys)es|ing)\\b/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[0]*?[1-9]\\d*\\.?[0]*$/",
    isPumpable: false
  },
  {
    input: "/^([a-z]+?\\.[a-z]+)+\\%$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a.a",
    pumpable: "a.aaa.a",
    suffix: ""
  },
  {
    input: "/\\b(0?[1-9]|1[0-2])(\\/)(0?[1-9]|1[0-9]|2[0-9]|3[0-1])(\\/)(0[0-8])\\b/",
    isPumpable: false
  },
  {
    input: "/\\b(0?[1-9]|1[0-2])(\\-)(0?[1-9]|1[0-9]|2[0-9]|3[0-1])(\\-)(0[0-8])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b(0[0-9]|1[0-9]|2[0-3])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b(0[0-9]|1[0-1])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b(0[0-9]|1[0-1])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])(\\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])\\s*(AM|PM|A|P)\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b(((J(ANUARY|UNE|ULY))|FEBRUARY|MARCH|(A(PRIL|UGUST))|MAY|(SEPT|NOV|DEC)EMBER|OCTOBER))\\s*(0?[1-9]|1[0-9]|2[0-9]|3[0-1])\\s*(\\,)\\s*(200[0-9])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b(((J(ANUARY|UNE|ULY))|FEBRUARY|MARCH|(A(PRIL|UGUST))|MAY|(SEPT|NOV|DEC)EMBER|OCTOBER))\\s*(0?[1-9]|1[0-9]|2[0-9]|3[0-1])\\s*(\\,)\\s*(0[0-9])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b((J(AN|UN|UL))|FEB|MAR|(A(PR|UG))|MAY|SEP|NOV|DEC|OCT)\\s*(0?[1-9]|1[0-9]|2[0-9]|3[0-1])\\s*(\\,)\\s*(200[0-9])\\b/",
    isPumpable: false
  },
  {
    input:
      "/\\b((J(AN|UN|UL))|FEB|MAR|(A(PR|UG))|MAY|SEP|NOV|DEC|OCT)\\s*(0?[1-9]|1[0-9]|2[0-9]|3[0-1])\\s*(\\,)\\s*(0[0-9])\\b/",
    isPumpable: false
  },
  {
    input: "/\\b(0?[1-9]|1[0-2])(\\/)(0?[1-9]|1[0-9]|2[0-9]|3[0-1])(\\/)(200[0-8])\\b/",
    isPumpable: false
  },
  {
    input: "/\\b(0?[1-9]|1[0-2])(\\-)(0?[1-9]|1[0-9]|2[0-9]|3[0-1])(\\-)(200[0-8])\\b/",
    isPumpable: false
  },
  {
    input: "/(\\$\\s*[\\d,]+\\.\\d{2})\\b/",
    isPumpable: false
  },
  {
    input: "/\\b[1-9]\\b/",
    isPumpable: false
  },
  {
    input: "/\\b4[0-9]\\b/",
    isPumpable: false
  },
  {
    input: "/(\\d{1,2}(\\:|\\s)\\d{1,2}(\\:|\\s)\\d{1,2}\\s*(AM|PM|A|P))/",
    isPumpable: false
  },
  {
    input: "/^.*(?:kumar).*$/",
    isPumpable: false
  },
  {
    input: "/(\\b(1|2|3|4|5|6|7|8|9)?[0-9]\\b)/",
    isPumpable: false
  },
  {
    input: "/(\\b(10|11|12|13|14|15|16|17|18|19)[0-9]\\b)/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{3}[-|\\/]{1}[0-9]{6}[-|\\/]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{8}$/",
    isPumpable: false
  },
  {
    input: "/^[SC]{2}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{2}[ ]{0,1}[0-9]{2}[ ]{0,1}[a-zA-Z]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-z0-9]+[@]{1}[a-zA-Z]+[.]{1}[a-zA-Z]+$/",
    isPumpable: false
  },
  {
    input: "/^[ISBN]{4}[ ]{0,1}[0-9]{1}[-]{1}[0-9]{3}[-]{1}[0-9]{5}[-]{1}[0-9]{0,1}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{0,5}[ ]{0,1}[0-9]{0,6}$/",
    isPumpable: false
  },
  {
    input: "/[cC]{1}[0-9]{0,7}/",
    isPumpable: false
  },
  {
    input: "/([0-8][0-9]|[9][0])°' '[0-9][0-9]\\.[0-9]´' '[NS]/",
    wasParseError: "{ParsingData.NonAsciiInput(19, 194)}"
  },
  {
    input: "/(([01][0-7]|[00][0-9])[0-9]|[1][8][0])°' '[0-9][0-9]\\.[0-9]´' '[EW]/",
    wasParseError: "{ParsingData.NonAsciiInput(38, 194)}"
  },
  {
    input: "/<a[\\s]+[^>]*?.*?>([^<]+|.*?)?<\\/a>/",
    isPumpable: false
  },
  {
    input: "/(\\[b\\])([^\\[\\]]+)(\\[\\/b\\])/",
    isPumpable: false
  },
  {
    input: "/(\\[[abiu][^\\[\\]]*\\])([^\\[\\]]+)(\\[\\/?[abiu]\\])/",
    isPumpable: false
  },
  {
    input: '/(\\[a url=\\"[^\\[\\]\\"]*\\"\\])([^\\[\\]]+)(\\[/a\\])/',
    isPumpable: false
  },
  {
    input: '/url=\\"([^\\[\\]\\"]*)\\"/',
    isPumpable: false
  },
  {
    input: "/\\b\\w+\\b/",
    isPumpable: false
  },
  {
    input: "/(<b>)([^<>]+)(<\\/b>)/",
    isPumpable: false
  },
  {
    input: "/(<\\/?\\w*[^<>]*>)/",
    isPumpable: false
  },
  {
    input: "/<!*[^<>]*>/",
    isPumpable: false
  },
  {
    input: "/&#x((?=.*[ABCDEF]))*((?=.*[0-9]))*.{2,5};/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: "/&[a-zA-Z]+\\d{0,3};/",
    isPumpable: false
  },
  {
    input: "/&#\\d{2,5};/",
    isPumpable: false
  },
  {
    input: "/<\\/?[a-z][a-z0-9]*[^<>]*>/",
    isPumpable: false
  },
  {
    input: "/(?=[-_a-zA-Z0-9]*?[A-Z])(?=[-_a-zA-Z0-9]*?[a-z])(?=[-_a-zA-Z0-9]*?[0-9])[-_a-zA-Z0-9]{6,}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/For IP-Address:(?<First>2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.(?<Second>2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.(?<Third>2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.(?<Fourth>2[0-4]\\d|25[0-5]|[01]?\\d\\d?)  For Number: (\\+|\\*{0,2})?(\\d*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 60)}"
  },
  {
    input:
      "/^(([1-9][0-9]*)|((([0])|([1-9][0-9]*))\\.[0-9]+)|((([1-9][0-9]*)|((([0])|([1-9][0-9]*))\\.[0-9]+))\\:)*(([1-9][0-9]*)|((([0])|([1-9][0-9]*))\\.[0-9]+)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\+\\d{2}[ \\-]{0,1}){0,1}(((\\({0,1}[ \\-]{0,1})0{0,1}\\){0,1}[2|3|7|8]{1}\\){0,1}[ \\-]*(\\d{4}[ \\-]{0,1}\\d{4}))|(1[ \\-]{0,1}(300|800|900|902)[ \\-]{0,1}((\\d{6})|(\\d{3}[ \\-]{0,1}\\d{3})))|(13[ \\-]{0,1}([\\d \\-]{5})|((\\({0,1}[ \\-]{0,1})0{0,1}\\){0,1}4{1}[\\d \\-]{8,10})))$/",
    isPumpable: false
  },
  {
    input: "/^\\d*\\d?((5)|(0))\\.?((0)|(00))?$/",
    isPumpable: false
  },
  {
    input: "/^\\(\\d{1,2}(\\s\\d{1,2}){1,2}\\)\\s(\\d{1,2}(\\s\\d{1,2}){1,2})((-(\\d{1,4})){0,1})$/",
    isPumpable: false
  },
  {
    input: "/^((?:\\+62|62)|0)[2-9]{1}[0-9]+$/",
    isPumpable: false
  },
  {
    input:
      "/(^|\\s|(\\[))(::)?([a-f\\d]{1,4}::?){0,7}(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?=(?(2)\\]|($|\\s|(?(3)($|\\s)|(?(4)($|\\s)|:\\d)))))|((?(3)[a-f\\d]{1,4})|(?(4)[a-f\\d]{1,4}))(?=(?(2)\\]|($|\\s))))(?(2)\\])(:\\d{1,5})?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(78, 40)}"
  },
  {
    input:
      "/(?:^|\\s)([a-z]{3,6}(?=:\\/\\/))?(:\\/\\/)?((?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))(?::(\\d{2,5}))?(?:\\s|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(19)}"
  },
  {
    input: "/^([a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\\.)+([a-zA-Z0-9]{3,5})$/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z]{3,}:\\/\\/[a-zA-Z0-9\\.]+\\/*[a-zA-Z0-9\\/\\\\%_.]*\\?*[a-zA-Z0-9/\\\\%_.=&]*/",
    isPumpable: false
  },
  {
    input: "/(8[^0]\\d|8\\d[^0]|[0-79]\\d{2})-\\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input: "/((\\(\\d{2}\\) ?)|(\\d{2}\\/))?\\d{2}\\/\\d{4} ([0-2][0-9]\\:[0-6][0-9])/",
    isPumpable: false
  },
  {
    input:
      "/^( )*(\\+?( )?\\(?( )?(\\d{1,3})?)\\)?(.|-|_ )?\\(?(\\d{3})\\)?(.|-|_ )?\\(?(\\d{3})\\)?(.|-|_ )?\\(?(\\d{4})\\)?( )*$/",
    isPumpable: false
  },
  {
    input:
      "/^\\+31(?:(?:1[035]|2[0346]|3[03568]|4[0356]|5[0358]|7\\d)[2-8]\\d{6}|(?:11[134578]|16[124-8]|17[24]|18[0-467]|22[2346-9]|25[125]|29[479]|31[3-8]|32[01]|34[1-8]|41[12368]|47[58]|48[15-8]|49[23579]|51[1-9]|52[1-5789]|54[13-8]|56[126]|57[0-3578]|59[1-9])[2-8]\\d{5}|(?:6[1-68]|8[4578]|91)\\d{7}|(?:800(?:0[013-8]|1\\d|2[01]|4[1369]|[5-9][01])|90[069](?:0[0-35-9]|1[345789]|8[013468]|9[235-8]))\\d{2}|(?:800(?:0[29]|[26-9][2-9]|3\\d|4[24578])|90[069](?:04|1[0126]|[2-7]\\d|8[2579]|9[0149]))\\d{5})$/",
    isPumpable: false
  },
  {
    input: "/^\\+32(?:1[0-69]|[23][2-8]|4[236-9]|5\\d|6[01345789]|7[01689]|8[0-79]|9[012])\\d{6}$/",
    isPumpable: false
  },
  {
    input:
      "/\\+49(?:(?:30|40|69|89)(?!11)[1-9]\\d{3,7}|(?:20[12389]|21[124]|22[18]|23[14]|2[4-9]1|3[35-9][15]|34[015]|4[2-9]1|5[1-9]1|6[1-8]1|7[1-9]1|8[1-8]1|906|9[1-9]1)(?!11)[1-9]\\d{2,6}|(?:204[135]|205[1-468]|206[456]|210[234]|2129|213[1237]|215[0-46-9]|216[1-6]|217[1345]|218[123]|219[12356]|22[023][2-8]|224[1-8]|225[1-7]|226[1-9]|227[1-5]|229[1-7]|230[1-9]|232[3457]|233\\d|235[1-5789]|236\\d|23[78][1-5789]|239[1-5]|24[02][1-9]|243[1-6]|244[013-9]|245[1-6]|246[1-5]|247[1-4]|248[2456]|250[124-9]|252\\d|253[3-68]|254[1235-8]|25[56][1-8]|257[1-5]|258[1-8]|259\\d|260[1-8]|262[0-8]|263\\d|264[1-7]|265[1-7]|266[1-467]|267[1-8]|268\\d|269[1-7]|272[1-5]|273[2-9]|274[1-57]|275[0-589]|276[1-4]|277\\d|280[1-4]|282[1-8]|283[1-9]|284[1-5]|285\\d|286[1-7]|287[1-4]|290[2-5]|29[2-5][1-578]|296[1-4]|297[1-57]|298[1-5]|299[1-4]|330[1-467]|332[12789]|333[124578]|33[46][1246]|337[125789]|338[1256]|339[145]|342[135]|34[34][13578]|346[1246]|347[1356]|349[1346]|350[14]|352[123589]|353[1357]|354[1246]|356[1-4]|357[13468]|358[13568]|359[1246]|360[1356]|362[1-489]|363[12456]|364[1347]|366[13]|367[12579]|368[12356]|369[135]|372[1-7]|373[1357]|374[145]|376[1-5]|377[1-4]|3821|383[1468]|384[1347]|386[0135-9]|387[1467]|388[136]|390[12479]|392[1358]|393[1357]|394[134679]|396[1-9]|397[136]|398[147]|399[1468]|410[1-9]|412\\d|413[1-9]|414[0-4689]|415[1-689]|41[67][1-9]|418\\d|419[1-5]|420[2-9]|422[1-4]|42[34]\\d|425[1-8]|426\\d|427[1-7]|428[1-9]|429[2-8]|430[23578]|432[0-46-9]|433\\d|434[02346-9]|435[1-8]|436[1-7]|437[12]|438[1-5]|439[234]|440[1-9]|442[12356]|443[1-5]|444[1-7]|445[1-68]|446[1-9]|447[1-5789]|448\\d|449[1-9]|450[1-689]|452[1-9]|453[1-79]|454[1-7]|455\\d|456[1-4]|460[2-9]|462[1-7]|463\\d|464[1-46]|4651|466[1-8]|46[78][1-4]|470[2-8]|472[1-5]|473[1-7]|474\\d|475[1-8]|476[1-9]|477\\d|479[1-6]|480[2-6]|482[1-9]|483[02-9]|484[1-9]|485[1-9]|486[1-5]|487[1-7]|488[1-5]|489[23]|490[23]|492\\d|493[1-689]|494[1-8]|495\\d|496[1-8]|497[1-7]|502[1-8]|503[1-7]|504[1-5]|505[1-6]|506[02-9]|507[1-4]|508[2-6]|510[123589]|512[136-9]|513[0125-9]|514[1-9]|515[1-9]|516[1-8]|517[1-7]|518[1-7]|519\\d|520[1-9]|522[1-68]|523[1-8]|524[124-8]|525[0-5789]|526[1-6]|527[1-8]|528[1-6]|529[2-5]|53[02]\\d|533[1-79]|534[14-7]|53[56][1-8]|537[1-9]|538[1-4]|540[1-79]|54[235][1-9]|54[46][1-8]|547[1-6]|54[89][1-5]|550[2-9]|552[0-5789]|55[345][1-6]|556[1-5]|557[1-4]|558[2-6]|559[2-4]|560[1-9]|56[23][1-6]|564[1-8]|565\\d|566[1-5]|567[1-7]|56[89][1-6]|570[2-7]|57[24][1-6]|573[1-4]|575[1-5]|576[13-9]|577[1-7]|580[2-8]|582\\d|583[1-9]|584[0-689]|585[0-5789]|586[1-5]|587[2-5]|588[23]|590[1-9]|592[1-6]|593[1-79]|594[1-8]|595[1-7]|596[1-6]|597[135-8]|600[23478]|602[0-46-9]|603[1-69]|604[1-9]|605\\d|606[12368]|607[1348]|608[1-7]|609[2-6]|610[1-9]|612[02346-9]|613[0-689]|614[24-7]|615[01245789]|616[1-7]|617[1-5]|618[1-8]|619[02568]|62[04][1-79]|622[0-46-9]|62[36][1-9]|62[59][1-8]|627[12456]|628[1-7]|63[09][1-8]|63[235][1-9]|634\\d|636[1-4]|637[1-5]|638[1-7]|64[02]\\d|643[0-689]|644[0-79]|645[1-8]|646[124-8]|647[1-9]|648[2-6]|650\\d|652[2-7]|653[1-6]|654[1-5]|655\\d|656[1-9]|657[1-58]|658\\d|659[1-79]|66[25]\\d|66[36][013-9]|66[49][1-8]|667[02-8]|668[1-4]|670[1346-9]|67[25][1-8]|67[34][1-7]|67[67][1-6]|678[1-9]|680[2-69]|682[14-7]|68[35][1-8]|684[1-489]|686[14-9]|687[1-6]|688[178]|689[3478]|70[245][1-6]|703[1-4]|706[236]|707[123]|708[1-5]|712[1-9]|713[0-689]|714[1-8]|715[0-46-9]|71[67][1-6]|718[1-4]|719[1-5]|720[2-4]|722\\d|72[37][1-7]|724[02-9]|72[56]\\d|730[02-9]|73[28][1-9]|73[36][1-7]|734[03-8]|735[1-8]|737[13-6]|739[1-5]|740[234]|742[02-9]|743[1-6]|744\\d|745[1-9]|746[1-7]|747[1-8]|748[2-6]|750[2-6]|753[0245789]|754[1-6]|755[1-8]|756[1-9]|757[0-9|758[1-7]|7602|762\\d|76[347][1-6]|765[1-7]|766\\d|768[1-5]|770[2-9]|772\\d|773[1-689]|774[1-8]|775[1345]|776[1-5]|777[13457]|780[2-8]|782[1-6]|783[1-9]|78[45][1-4]|790[3-7]|79[34]\\d|795[0-5789]|79[67][1-7]|802\\d|803[1-689]|804[12356]|80[56][1-7]|80[78][1-6]|809[1-5]|810[2-6]|812[1-4]|813[13-9]|814[1-6]|815[12378]|816[15-8]|817[016-9]|819[1-6]|820[2-8]|82[29][1-6]|823[/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^(\\$)?((\\d+)|(\\d{1,3})(\\,\\d{3})*)(\\.\\d{2,})?$/",
    isPumpable: false
  },
  {
    input:
      "/((\\+44\\s?\\(0\\)\\s?\\d{2,4})|(\\+44\\s?(01|02|03|07|08)\\d{2,3})|(\\+44\\s?(1|2|3|7|8)\\d{2,3})|(\\(\\+44\\)\\s?\\d{3,4})|(\\(\\d{5}\\))|((01|02|03|07|08)\\d{2,3})|(\\d{5}))(\\s|-|.)(((\\d{3,4})(\\s|-)(\\d{3,4}))|((\\d{6,7})))/",
    isPumpable: false
  },
  {
    input: "/^([0-9]( |-)?)?(\\(?[0-9]{3}\\)?|[0-9]{3})( |-)?([0-9]{3}( |-)?[0-9]{4}|[a-zA-Z0-9]{7})$/",
    isPumpable: false
  },
  {
    input:
      "/([0369]*([147][0369]*([147][0369]*[258])*[0369]*[147][0369]*([258][0369]*[147])*[0369]*[0369]*([258][0369]*[147])*[0369]*[147]|[258][0369]*([258][0369]*[147])*[0369]*[258][0369]*([147][0369]*[258])*[0369]*[0369]*([147][0369]*[258])*[0369]*[258]|[147][0369]*([147][0369]*[258])*[0369]*[258]|[258][0369]*([258][0369]*[147])*[0369]*[147])*[0369]*)*/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/[+-]?(0|[1-9]([0-9]{0,2})(,[0-9]{3})*)(\\.[0-9]+)?/",
    isPumpable: false
  },
  {
    input: "/[+-]?\\d(\\.\\d+)?[Ee][+-]?\\d+/",
    isPumpable: false
  },
  {
    input: "/(\\w)(\\w)?(\\w)?\\w?(?(3)\\3)(?(2)\\2)\\1/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(19, 40)}"
  },
  {
    input: "/[ \\t]+$/",
    isPumpable: false
  },
  {
    input: "/[\\uFDD0-\\uFDEF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(2, 117)}"
  },
  {
    input:
      "/^(([A-Z|a-z|&]{3}|[A-Z|a-z]{4})\\d{2}((0[1-9]|1[012])(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])(29|30)|(0[13578]|1[02])31)|([02468][048]|[13579][26])0229)(\\w{2})([A|a|0-9]{1})$/",
    isPumpable: false
  },
  {
    input: "/<!--[\\d\\D]*?-->/",
    isPumpable: false
  },
  {
    input: "/^\\d{2}[0-1][0-9][0-3][0-9]-{0,1}\\d{2}-{0,1}\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(0[1-9]|[12][0-9]|3[01])\\s(J(anuary|uly)|Ma(rch|y)|August|(Octo|Decem)ber)\\s[1-9][0-9]{3}|(0[1-9]|[12][0-9]|30)\\s(April|June|(Sept|Nov)ember)\\s[1-9][0-9]{3}|(0[1-9]|1[0-9]|2[0-8])\\sFebruary\\s[1-9][0-9]{3}|29\\sFebruary\\s((0[48]|[2468][048]|[13579][26])00|[0-9]{2}(0[48]|[2468][048]|[13579][26]))/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:\\+?1[\\s])|(?:\\+?1(?=(?:\\()|(?:\\d{10})))|(?:\\+?1[\\-](?=\\d)))?(?:\\([2-9]\\d{2}\\)\\ ?|[2-9]\\d{2}(?:\\-?|\\ ?))[2-9]\\d{2}[- ]?\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(24)}"
  },
  {
    input:
      "/(?:^(?:(?:\\+?1[\\s])|(?:\\+?1(?=(?:\\()|(?:\\d{10})))|(?:\\+?1[\\-](?=\\d)))?(?:\\([2-9]\\d{2}\\)\\ ?|[2-9]\\d{2}(?:\\-?|\\ ?))[2-9]\\d{2}[- ]?\\d{4}$)|(?:^[2-9]\\d{2}[- ]?\\d{4}$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(27)}"
  },
  {
    input:
      "/^(?<title>.*\\.\\s)*(?<firstname>([A-Z][a-z]+\\s*)+)(\\s)(?<middleinitial>([A-Z]\\.?\\s)*)(?<lastname>[A-Z][a-zA-Z-']+)(?<suffix>.*)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[a-zA-Z_][a-zA-Z0-9_]*$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0[1-9]|[12][0-9]|3[01])(0[13578]|10|12)(\\d{2}))|(([0][1-9]|[12][0-9]|30)(0[469]|11)(\\d{2}))|((0[1-9]|1[0-9]|2[0-8])(02)(\\d{2}))|((29)(02)(00))|((29)(02)([2468][048]))|((29)(02)([13579][26])))[-]\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/[a-z]{1}[a-z0-9\\-_\\.]{2,24}@tlen\\.pl/",
    isPumpable: false
  },
  {
    input: "/[a-zA-Z_:][a-zA-Z0-9_,\\.\\-]*?/",
    isPumpable: false
  },
  {
    input: "/(.)\\1{2,}/",
    isPumpable: false
  },
  {
    input: "/<.*\\b(bgcolor\\s*=\\s*[\\\"|\\']*(\\#\\w{6})[\\\"|\\']*).*>/",
    isPumpable: false
  },
  {
    input: "/(< *balise[ *>|:(.|\\n)*>| (.|\\n)*>](.|\\n)*<\\/balise *>)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<balise\\x0a",
    pumpable: "\\x0a",
    suffix: ""
  },
  {
    input: "/^(sip|sips)\\:\\+?([\\w|\\:?\\.?\\-?\\@?\\;?\\,?\\=\\%\\&]+)/",
    isPumpable: false
  },
  {
    input: "/[NS] \\d{1,}(\\:[0-5]\\d){2}.{0,1}\\d{0,},[EW] \\d{1,}(\\:[0-5]\\d){2}.{0,1}\\d{0,}/",
    isPumpable: false
  },
  {
    input: '/".*?[^"\\\\]"(?!")|""/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(11)}"
  },
  {
    input:
      '/\\(\\s*@*(".*?[^"\\\\]"(?!")||"")\\s*,\\s*@*(".*?[^"\\\\]"(?!")|"")\\s*(?:\\)|(?:,\\s*@*(".*?[^"\\\\]"(?!")||"")\\s*))?\\)/',
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/((?=[^147]*([147][^147]*[147][^147]*[147][^147]*)*$)[^258]*([258][^258]*[258][^258]*[258][^258]*)*)|((?=[^147]*([147][^147]*[147][^147]*[147][^147]*)*[147][^147]*$)[^258]*([258][^258]*[258][^258]*[258][^258]*)*[258][^258]*)|((?=[^147]*([147][^147]*[147][^147]*[147][^147]*)*[147][^147]*[147][^147]*$)[^258]*([258][^258]*[258][^258]*[258][^258]*)*[258][^258]*[258][^258]*)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/([1-3]{0,1}\\n{0,1}\\s{0,1}\\n{0,1}[a-zA-Z]+\\s{1}\\n{0,1}\\d{1,2}:{1}\\s{0,1}\\d{1,2}){1}(,{1}\\n{0,1}\\s{0,1}\\d{1,2}({1}\\s{0,9}\\n{0,1}\\d{1,2}){0,9}){0,9}(-{1}\\s{0,1}\\n{0,1}\\d{1,2}){0,9}(,{1}\\s{0,1}\\d{1,2}){0,9}(;\\s{0,1}\\n{0,1}\\d{1,2}\\s{0,1}:{1}\\s{0,1}\\d{1,2}(-{1}\\s{0,9}\\n{0,1}\\d{1,2}){0,9}(,{1}\\s{0,9}\\d{1,2}(-{1}\\s{0,9}\\n{0,1}\\d{1,2}){0,9}){0,9}){0,9}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^(\\d{4})\\D?(0[1-9]|1[0-2])\\D?([12]\\d|0[1-9]|3[01])(\\D?([01]\\d|2[0-3])\\D?([0-5]\\d)\\D?([0-5]\\d)?)?$/",
    isPumpable: false
  },
  {
    input: "/^((\\d{1,3}((,\\d{3})*|\\d*)(\\.{0,1})\\d+)|\\d+)$/",
    isPumpable: false
  },
  {
    input:
      "/(((0[1-9]|[12][0-9]|3[01])([\\/])(0[13578]|10|12)([\\/])(\\d{4}))|(([0][1-9]|[12][0-9]|30)([\\/])(0[469]|11)([\\/])(\\d{4}))|((0[1-9]|1[0-9]|2[0-8])([\\/])(02)([\\/])(\\d{4}))|((29)(\\.|-|\\/)(02)([\\/])([02468][048]00))|((29)([\\/])(02)([\\/])([13579][26]00))|((29)([\\/])(02)([\\/])([0-9][0-9][0][48]))|((29)([\\/])(02)([\\/])([0-9][0-9][2468][048]))|((29)([\\/])(02)([\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input: "/<(?:[^\"']+?|.+?(?:\"|').*?(?:\"|')?.*?)*?>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<",
    pumpable: "?''",
    suffix: ""
  },
  {
    input:
      "/((http|ftp|https):\\/\\/w{3}[\\d]*.|(http|ftp|https):\\/\\/|w{3}[\\d]*.)([\\w\\d\\._\\-#\\(\\)\\[\\]\\\\,;:]+@[\\w\\d\\._\\-#\\(\\)\\[\\]\\\\,;:])?([a-z0-9]+.)*[a-z\\-0-9]+.([a-z]{2,3})?[a-z]{2,6}(:[0-9]+)?(\\/[\\/a-z0-9\\._\\-,]+)*[a-z0-9\\-_\\.\\s\\%]+(\\?[a-z0-9=%&\\.\\-,#]+)?/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "http://",
    pumpable: "x0a{",
    suffix: ""
  },
  {
    input: "/0{3,}|1{3,}|2{3,}|3{3,}|4{3,}|5{3,}|6{3,}|7{3,}|8{3,}|9{3,}/",
    isPumpable: false
  },
  {
    input:
      "/^(?<hours>\\d{2}):(?<minutes>\\d{2}):(?<seconds>\\d{2}) (?<month>[a-zA-Z]{3}) (?<day>\\d{1,}), (?<year>\\d{4}) (?<timezone>[a-zA-Z]{3})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^(?<dayOfWeek>\\w{3}) (?<monthName>\\w{3}) (?<day>\\d{1,2}) (?<year>\\d{4})? ?(?<hours>\\d{1,2}):(?<minutes>\\d{1,2}):(?<seconds>\\d{1,2}) (GMT|UTC)(?<timeZoneOffset>[-+]?\\d{4}) (?<year>\\d{4})?\\(?(?<timeZoneName>[a-zA-Z\\s]+)?\\)?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^([07][1-7]|1[0-6]|2[0-7]|[35][0-9]|[468][0-8]|9[0-589])-?\\d{7}$/",
    isPumpable: false
  },
  {
    input:
      "/(?<protocol>(http|ftp|https|ftps):\\/\\/)?(?<site>[\\w\\-_\\.]+\\.(?<tld>([0-9]{1,3})|([a-zA-Z]{2,3})|(aero|arpa|asia|coop|info|jobs|mobi|museum|name|travel))+(?<port>:[0-9]+)?\\/?)((?<resource>[\\w\\-\\.,@^%:\\/~\\+#]*[\\w\\-\\@^%\\/~\\+#])(?<queryString>(\\?[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\~',]*=[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\~',]*)+(&[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\~',]*=[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\~',]*)*)?)?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/((http|ftp|https|ftps):\\/\\/)?[\\w\\-_\\.]+\\.(([0-9]{1,3})|([a-zA-Z]{2,3})|(aero|arpa|asia|coop|info|jobs|mobi|museum|name|travel))+(:[0-9]+)?\\/?(([\\w\\-\\.,@^%:\\/~\\+#]*[\\w\\-\\@^%\\/~\\+#])((\\?[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\=~',]*=[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\=~',]*)+(&[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\=~',]*=[a-zA-Z0-9\\[\\]\\-\\._+%\\$#\\=~',]*)*)?)?/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^(?![DFIOQU])([ABCEGHJ-NPRSTVXY]\\d[A-Z][ ]\\d[A-Z]\\d)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(?=.*\\d)(?=.*[A-Za-z])(?!.*[!@#\\$%\\^&\\*\\(\\)\\+=\\|;'\"{}<>\\.\\?\\-_\\\\/:,~`]).{6,20}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/\\?<.+?>/",
    isPumpable: false
  },
  {
    input:
      "/(?<username>#?[+_a-zA-Z0-9+-]+(\\.[+_a-zA-Z0-9+-]+)*)@(?<domain>[a-zA-Z0-9]+(-(?!-)|[a-zA-Z0-9\\.])*?[a-zA-Z0-9]+\\.([0-9]{1,3}|[a-zA-Z]{2,3}|(aero|arpa|asia|coop|info|jobs|mobi|museum|name|travel)))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/\\(?(?<areacode>[1]?[2-9]\\d{2})\\)?[\\s-]?(?<prefix>[2-9]\\d{2})[\\s-]?(?<linenumber>[\\d]{4})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input: "/((&#[0-9]+|&[a-zA-Z]+[0-9]*?);)/",
    isPumpable: false
  },
  {
    input: "/^-?(?:90(?:(?:\\.0{1,6})?)|(?:[0-9]|[1-8][0-9])(?:(?:\\.[0-9]{1,6})?))$/",
    isPumpable: false
  },
  {
    input: "/^-?(?:180(?:(?:\\.0{1,6})?)|(?:[0-9]|[1-9][0-9]|1[1-7][0-9])(?:(?:\\.[0-9]{1,6})?))$/",
    isPumpable: false
  },
  {
    input: "/<\\s*\\/?\\s*\\w+(\\s*\\w+\\s*=\\s*(['\"][^'\"]*['\"]|[\\w#]+))*\\s*/?\\s*>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<0",
    pumpable: " a=00A=0",
    suffix: ""
  },
  {
    input: "/(?<=(\\n|^))(>\\s*)+/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(\\s{1,})/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z_]{1}[a-zA-Z0-9_@$#]*$/",
    isPumpable: false
  },
  {
    input: "/(:[a-z]{1}[a-z1-9\\$#_]*){1,31}/",
    isPumpable: false
  },
  {
    input: "/^\\(?([0-9]{3})\\)?[\\s\\.\\-]*([0-9]{3})[\\s\\.\\-]*([0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/^\\s*(\\d{0,2})(\\.?(\\d*))?\\s*\\%?\\s*$/",
    isPumpable: false
  },
  {
    input: "/\\/^[0-9]+\\.d{3}? *$\\//",
    isPumpable: false
  },
  {
    input:
      "/^((((([1-9])|(0[1-9])|(1\\d)|(2[0-8]))\\/(([1-9])|(0[1-9])|(1[0-2])))|((31\\/(((0[13578])|([13578]))|(1[02])))|((29|30)\\/(((0[1,3-9])|([1,3-9]))|(1[0-2])))))\\/((20[0-9][0-9]))|(((([1-9])|(0[1-9])|(1\\d)|(2[0-8]))\\/(([1-9])|(0[1-9])|(1[0-2])))|((31\\/(((0[13578])|([13578]))|(1[02])))|((29|30)\\/(((0[1,3-9])|([1,3-9]))|(1[0-2])))))\\/((19[0-9][0-9]))|(29\\/(02|2)\\/20(([02468][048])|([13579][26])))|(29\\/(02|2)\\/19(([02468][048])|([13579][26]))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(0?[1-9]|1[0-2])\\/(0?[1-9]|[1-2][0-9]|3[0-1])\\/(0[1-9]|[1-9][0-9]|175[3-9]|17[6-9][0-9]|1[8-9][0-9]{2}|[2-9][0-9]{3})$/",
    isPumpable: false
  },
  {
    input: "/^\\w+[\\w-\\.]*\\@\\w+((-\\w+)|(\\w*))\\.[a-z]{2,3}$/",
    isPumpable: false
  },
  {
    input: "/(^(\\d{2}.\\d{3}.\\d{3}\\/\\d{4}-\\d{2})|(\\d{14})$)|(^(\\d{3}.\\d{3}.\\d{3}-\\d{2})|(\\d{11})$)/",
    isPumpable: false
  },
  {
    input: "/^[ a - z, 0 - 9 , ?   -   ?   ,?   -   ? , ?    -  ?   ,?   -  ? , . ]/",
    isPumpable: false
  },
  {
    input: '/[^""\\?\\/\\&\\;\\:\\|\\”\\“\\(\\)\\[\\]\\=\\^\\.\\%\\$\\#\\!\\*\\?\\?\\»\\«\\×\\?]/',
    wasParseError: "{ParsingData.NonAsciiInput(16, 226)}"
  },
  {
    input: "/^.+@[^\\.].*\\.[a-z]{2,}$/",
    isPumpable: false
  },
  {
    input: "/<[iI][mM][gG]([^>]*[^\\/>])/",
    isPumpable: false
  },
  {
    input: "/^\\\\w*$/",
    isPumpable: false
  },
  {
    input:
      '/href=(?<QUOTE>[\\""\\\'])?(?<URL>(?<SCHEME>(file|ftp|http|https|news|nntp):\\/\\/|mailto\\:)?(?<EMAIL>[\\w-]+@)?(?<HOST>(?(SCHEME)[\\w]+(\\.[\\w-]+)*?))(?<PATH>\\/?\\w*[\\w-%\\:\\.\\+\\/]+)?(?<QUERY>\\?[\\w-%\\+:\\.]*(=[\\w-%\\+:\\.]*)?(&[\\w-%\\+\\:\\.]*(=[\\w-%\\+:\\.]*)?)*)?(?<ANCHOR>\\#[\\w-%\\+:\\.]+)?)(?<-QUOTE>[\\""\\\'])?(?(PATH)|(?(SCHEME)|(?!)))(?(QUOTE)(?!))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input:
      '/<a (?:(?<ATTRIBUTES>[\\w-]+=[\\""\\\']?[\\w\\S ]+?[\\""\\\'])[ ]+)*href=(?<QUOTE>[\\""\\\'])?(?<URL>(?<SCHEME>(file|ftp|http|https|news|nntp):\\/\\/|mailto\\:)?(?<EMAIL>[\\w-]+@)?(?<HOST>(?(SCHEME)[\\w]+(\\.[\\w-]+)*?))(?<PATH>\\/?\\w*[\\w-%\\:\\.\\+\\/]+)?(?<QUERY>\\?[\\w-%\\+:\\.]*(=[\\w-%\\+:\\.]*)?(&[\\w-%\\+\\:\\.]*(=[\\w-%\\+:\\.]*)?)*)?(?<ANCHOR>\\#[\\w-%\\+:\\.]+)?)?(?<-QUOTE>[\\""\\\'])?(?:[ ]+(?<ATTRIBUTES>[\\w-]+=[\\""\\\']?[\\w\\S ]+?[\\""\\\']))*>(?<TEXT>.+?)<\\/a>(?(PATH)|(?(SCHEME)|(?!)))(?(QUOTE)(?!))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input: "/^0$|^0\\.{1}(\\d{1,2})$|^[1-9]{1}[0-9]*\\.?(\\d{1,2})$|^[1-9]+[0-9]*$/",
    isPumpable: false
  },
  {
    input:
      "/\\b(((((one|t((en)|(wo)|(hree)|(welve)|(hirteen))|(evelen)|(f((our)|(ive))|s((ix)|(even))|eight|nine)(teen)?))\\b(\\s+hundred\\s*)?)| ((t((wen)|(hir))|f((or)|(if))|s((ix)|(even))|eigh|nin)ty)(-(one|t((wo)|(hree))|f((our)|(ive))|s((ix)|(even))|eight|nine))?) (\\s*(hundred|thousand|((([mb]|(t|quad)r))illion))\\s*(and\\s+)?)?)+/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/^(?ni:(((?:((((((?<month>(?<monthname>(Jan(uary)?|Ma(r(ch)?|y)|Jul(y)?|Aug(ust)?|Oct(ober)?|Dec(ember)?)))\\ )|(?<month>(?<monthnum>(0?[13578])|10)(?<sep>[-\\/.])))(?<day>31)(?(monthnum)|st)?)|((((?<month>(?<monthname>Jan(uary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sept|Nov|Dec)(ember)?))\\ )|((?<month>(?<monthnum>(0?[13-9])|1[012]))(?<sep>[-\\/.])))(?<day>((0?[1-9]|([12]\\d)|30)|(?(monthname)(\\b2?(1st|2nd|3rd|[4-9]th)|(2|3)0th|1\\dth\\b))))))|((((?<month>(?<monthname>Feb(ruary)?))\\ )|((?<month>0?2)(?<sep>[-\\/.])))((?(monthname)(?<day>(\\b2?(1st|2nd|3rd|[4-8]th)|9th|20th|1\\dth\\b)|(0?[1-9]|1\\d|2[0-8])))|(?<day>29(?=(\\k<sep>|(?(monthname)th)?,\\ )((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))))(?(sep)\\k<sep>|((?(monthname)th)?,\\ ))(?<year>(1[6-9]|[2-9]\\d)\\d{2}))$|((?<days>(31(?<suffix>st)?(?!(\\ (Feb(ruary)?|Apr(il)?|June?|(Sep(?=\\b|t)t?|Nov)(ember)?))|[-\\/.](0?[2469]|11)))|((30|29)(?<suffix>th)?(?!((\\ Feb(ruary)?)|([-\\/.]0?2))))|(29(?<suffix>th)?(?=((\\ Feb(ruary)?\\ )|([ -\\/.]0?2))(((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(?<suffix>(?=\\d\\d?[nrst][dht]\\ [JFMASOND])(\\b2?(1st|2nd|3rd|[4-8]th)|20th|1\\dth\\b)|((0?[1-9])|1\\d|2[0-8])))(?<month>(\\ (?<monthname>(Jan(uary)?|Feb(ruary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sep(?=\\b|t)t?|Nov|Dec)(ember)?))\\ )|(?(\\k<suffix>)|((?<sep>[-\\/.])(0?[1-9]|1[012])\\k<sep>)))(?<year>(1[6-9]|[2-9]\\d)\\d{2}))|\\b((?<year>((1[6-9])|([2-9]\\d))\\d\\d)(?<sep>[\\/.-])(?<month>0?[1-9]|1[012])\\k<sep>(?<day>((?<!(\\k<sep>((0?[2469])|11)\\k<sep>))31)|(?<!\\k<sep>(0?2)\\k<sep>)(29|30)|((?<=((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00)\\k<sep>(0?2)\\k<sep>)29)|((0?[1-9])|(1\\d)|(2[0-8]))))\\b)(?:(?=\\x20\\d)\\x20|$))?((?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2}))?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  {
    input:
      "/ISBN(-1(?:(0)|3))?:?\\x20+(?(1)(?(2)(?:(?=.{13}$)\\d{1,5}([ -])\\d{1,7}\\3\\d{1,6}\\3(?:\\d|x)$)|(?:(?=.{17}$)97(?:8|9)([ -])\\d{1,5}\\4\\d{1,7}\\4\\d{1,6}\\4\\d$))|(?(.{13}$)(?:\\d{1,5}([ -])\\d{1,7}\\5\\d{1,6}\\5(?:\\d|x)$)|(?:(?=.{17}$)97(?:8|9)([ -])\\d{1,5}\\6\\d{1,7}\\6\\d{1,6}\\6\\d$)))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(27, 40)}"
  },
  {
    input: "/ISBN(?:-13)?:?\\x20*(?=.{17}$)97(?:8|9)([ -])\\d{1,5}\\1\\d{1,7}\\1\\d{1,6}\\1\\d$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(19)}"
  },
  {
    input:
      "/^(?:(?:(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(\\/|-|\\.)(?:0?2\\1(?:29)))|(?:(?:(?:1[6-9]|[2-9]\\d)?\\d{2})(\\/|-|\\.)(?:(?:(?:0?[13578]|1[02])\\2(?:31))|(?:(?:0?[1,3-9]|1[0-2])\\2(29|30))|(?:(?:0?[1-9])|(?:1[0-2]))\\2(?:0?[1-9]|1\\d|2[0-8]))))$/",
    wasParseError: "{ParsingData.InvalidBackreference(194)}"
  },
  {
    input: "/^(([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w ]*))+\\.(txt|TXT)$/",
    isPumpable: false
  },
  {
    input: "/^(?i:(?=[MDCLXVI])((M{0,3})((C[DM])|(D?C{0,3}))?((X[LC])|(L?XX{0,2})|L)?((I[VX])|(V?(II{0,2}))|V)?))$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^(?:(?:(?:0?[13578]|1[02])(\\/|-|\\.)31)\\1|(?:(?:0?[13-9]|1[0-2])(\\/|-|\\.)(?:29|30)\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$|^(?:0?2(\\/|-|\\.)29\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:(?:0?[1-9])|(?:1[0-2]))(\\/|-|\\.)(?:0?[1-9]|1\\d|2[0-8])\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2})$/",
    wasParseError: "{ParsingData.InvalidBackreference(81)}"
  },
  {
    input:
      "/^(?=\\d)(?:(?:(?:(?:(?:0?[13578]|1[02])(\\/|-|\\.)31)\\1|(?:(?:0?[1,3-9]|1[0-2])(\\/|-|\\.)(?:29|30)\\2))(?:(?:1[6-9]|[2-9]\\d)?\\d{2})|(?:0?2(\\/|-|\\.)29\\3(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))|(?:(?:0?[1-9])|(?:1[0-2]))(\\/|-|\\.)(?:0?[1-9]|1\\d|2[0-8])\\4(?:(?:1[6-9]|[2-9]\\d)?\\d{2}))($|\\ (?=\\d)))?(((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\ [AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$/",
    wasParseError: "{ParsingData.InvalidBackreference(94)}"
  },
  {
    input: "/^((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\ [AP]M))$|^([01]\\d|2[0-3])(:[0-5]\\d){0,2}$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(((Jan(uary)?|Ma(r(ch)?|y)|Jul(y)?|Aug(ust)?|Oct(ober)?|Dec(ember)?)\\ 31)|((Jan(uary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sept|Nov|Dec)(ember)?)\\ (0?[1-9]|([12]\\d)|30))|(Feb(ruary)?\\ (0?[1-9]|1\\d|2[0-8]|(29(?=,\\ ((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))))\\,\\ ((1[6-9]|[2-9]\\d)\\d{2}))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(235)}"
  },
  {
    input:
      "/^((31(?!\\ (Feb(ruary)?|Apr(il)?|June?|(Sep(?=\\b|t)t?|Nov)(ember)?)))|((30|29)(?!\\ Feb(ruary)?))|(29(?=\\ Feb(ruary)?\\ (((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])\\ (Jan(uary)?|Feb(ruary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sep(?=\\b|t)t?|Nov|Dec)(ember)?)\\ ((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/^(?:J(anuary|u(ne|ly))|February|Ma(rch|y)|A(pril|ugust)|(((Sept|Nov|Dec)em)|Octo)ber)$/",
    isPumpable: false
  },
  {
    input: "/^(Sun|Mon|(T(ues|hurs))|Fri)(day|\\.)?$|Wed(\\.|nesday)?$|Sat(\\.|urday)?$|T((ue?)|(hu?r?))\\.?$/",
    isPumpable: false
  },
  {
    input: "/ISBN\\x20(?=.{13}$)\\d{1,5}([- ])\\d{1,7}\\1\\d{1,6}\\1(\\d|X)$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(8)}"
  },
  {
    input:
      "/^(?n:(?<address1>(\\d{1,5}(\\ 1\\/[234])?(\\x20[A-Z]([a-z])+)+ )|(P\\.O\\.\\ Box\\ \\d{1,5}))\\s{1,2}(?i:(?<address2>(((APT|B LDG|DEPT|FL|HNGR|LOT|PIER|RM|S(LIP|PC|T(E|OP))|TRLR|UNIT)\\x20\\w{1,5})|(BSMT|FRNT|LBBY|LOWR|OFC|PH|REAR|SIDE|UPPR)\\.?)\\s{1,2})?)(?<city>[A-Z]([a-z])+(\\.?)(\\x20[A-Z]([a-z])+){0,2})\\, \\x20(?<state>A[LKSZRAP]|C[AOT]|D[EC]|F[LM]|G[AU]|HI|I[ADL N]|K[SY]|LA|M[ADEHINOPST]|N[CDEHJMVY]|O[HKR]|P[ARW]|RI|S[CD] |T[NX]|UT|V[AIT]|W[AIVY])\\x20(?<zipcode>(?!0{5})\\d{5}(-\\d {4})?))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  {
    input: '/<(\\w+)(\\s(\\w*=".*?")?)*((/>)|((/*?)>.*?</\\1>))/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "<0",
    pumpable: ' =""\\x09=""',
    suffix: ""
  },
  {
    input:
      "/(?n:^(?=\\d)((?<month>(0?[13578])|1[02]|(0?[469]|11)(?!.31)|0?2(?(.29)(?=.29.((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00))|(?!.3[01])))(?<sep>[-.\\/])(?<day>0?[1-9]|[12]\\d|3[01])\\k<sep>(?<year>(1[6-9]|[2-9]\\d)\\d{2})(?(?=\\x20\\d)\\x20|$))?(?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(?i:\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      "/^(?n:(?<lastname>(St\\.\\ )?(?-i:[A-Z]\\'?\\w+?\\-?)+)(?<suffix>\\ (?i:([JS]R)|((X(X{1,2})?)?((I((I{1,2})|V|X)?)|(V(I{0,3})))?)))?,((?<prefix>Dr|Prof|M(r?|(is)?)s)\\ )?(?<firstname>(?-i:[A-Z]\\'?(\\w+?|\\.)\\ ??){1,2})?(\\ (?<mname>(?-i:[A-Z])(\\'?\\w+?|\\.))){0,2})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  {
    input: "/^(?!\\u00a2)\\p{Sc}?(?!0,?\\d)(\\d{1,3}(\\,\\d{3})*|(\\d+))(\\.\\d{2})?$/",
    wasParseError: "{ParsingData.UnsupportedEscape(5, 117)}"
  },
  {
    input: "/^(\\x22|\\x27)((?!\\1).|\\1{2})*\\1$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(13)}"
  },
  {
    input:
      "/^(?=\\d)(?:(?:31(?!.(?:0?[2469]|11))|(?:30|29)(?!.0?2)|29(?=.0?2.(?:(?:(?:1[6-9]|[2-9]\\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00)))(?:\\x20|$))|(?:2[0-8]|1\\d|0?[1-9]))([-.\\/])(?:1[012]|0?[1-9])\\1(?:1[6-9]|[2-9]\\d)?\\d\\d(?:(?=\\x20\\d)\\x20|$))?(((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/,(?!(?<=(?:^|,)\\s*\\x22(?:[^\\x22]|\\x22\\x22|\\\\\\x22)*,)(?:[^\\x22]|\\x22\\x22|\\\\\\x22)*\\x22\\s*(?:,|$))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/& (?ni:\\#((x([\\dA-F]){1,5})|(104857[0-5]|10485[0-6]\\d|1048[0-4]\\d\\d|104[0-7]\\d{3}|10[0-3]\\d{4}|0?\\d{1,6}))|([A-Za-z\\d.]{2,31}));/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 110)}"
  },
  {
    input:
      "/(?!(?:10(?<sep>[-.\\/])(?:0?[5-9]|1[0-4])\\k<sep>(?:1582))|(?:0?9(?<sep>[-.\\/])(?:0?[3-9]|1[0-3])\\k<sep>(?:1752)))(?n:^(?=\\d)((?<month>(0?[13578])|1[02]|(0?[469]|11)(?!.31)|0?2(?(.29)(?=.29.(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:(?:\\d\\d)(?:[02468][048]|[13579][26])(?!\\x20BC))|(?:00(?:42|3[0369]|2[147]|1[258]|09)\\x20BC)))|(?!.3[01])))(?<sep>[-.\\/])(?<day>0?[1-9]|[12]\\d|3[01])\\k<sep>(?!0000)(?<year>(?=(?:00(?:4[0-5]|[0-3]?\\d)\\x20BC)|(?:\\d{4}(?:\\z|(?:\\x20\\d))))\\d{4}(?:\\x20BC)?)(?(?=\\x20\\d)\\x20|$))?(?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(?i:\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(10, 60)}"
  },
  {
    input: "/\\p{IsBasicLatin}/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 112)}"
  },
  {
    input: "/\\p{N}/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 112)}"
  },
  {
    input: "/\\p{Sm}/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 112)}"
  },
  {
    input: "/^(?=[^\\d_].*?\\d)\\w(\\w|[!@#$%]){7,20}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^(?ni:(?=\\d)((?'year'((1[6-9])|([2-9]\\d))\\d\\d)(?'sep'[\\/.-])(?'month'0?[1-9]|1[012])\\2(?'day'((?<!(\\2((0?[2469])|11)\\2))31)|(?<!\\2(0?2)\\2)(29|30)|((?<=((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00)\\2\\3\\2)29)|((0?[1-9])|(1\\d)|(2[0-8])))(?:(?=\\x20\\d)\\x20|$))?((?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2}))?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  {
    input: "/(?i:([A-D])(?!\\1)([A-D])(?!\\1|\\2)([A-D])(?!\\1|\\2|\\3)([A-D]))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(11)}"
  },
  {
    input: "/^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012]))([ -]?)(?!00)\\d\\d\\3(?!0000)\\d{4}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/(<\\/?)(?i:(?<element>a(bbr|cronym|ddress|pplet|rea)?|b(ase(font)?|do|ig|lockquote|ody|r|utton)?|c(aption|enter|ite|(o(de|l(group)?)))|d(d|el|fn|i(r|v)|l|t)|em|f(ieldset|o(nt|rm)|rame(set)?)|h([1-6]|ead|r|tml)|i(frame|mg|n(put|s)|sindex)?|kbd|l(abel|egend|i(nk)?)|m(ap|e(nu|ta))|no(frames|script)|o(bject|l|pt(group|ion))|p(aram|re)?|q|s(amp|cript|elect|mall|pan|t(r(ike|ong)|yle)|u(b|p))|t(able|body|d|extarea|foot|h|itle|r|t)|u(l)?|var))(\\s(?<attr>.+?))*>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(12, 60)}"
  },
  {
    input:
      "/(?i:on(blur|c(hange|lick)|dblclick|focus|keypress|(key|mouse)(down|up)|(un)?load|mouse(move|o(ut|ver))|reset|s(elect|ubmit)))/",
    isPumpable: false
  },
  {
    input:
      "/(?n:^(?=\\d)((?<month>(0?[13578])|1[02]|(0?[469]|11)(?!.31)|0?2(?(.29)(?=.29.((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00))|(?!.3[01])))(?<sep>[-.\\/])(?<day>0?[1-9]|[12]\\d|3[01])\\k<sep>(?<year>(1[6-9]|[2-9]\\d)\\d{2})\\x20)(?<time>(?<hours>[01]\\d|2[0-3]):(?<minutes>[0-5]\\d):(?<seconds>[0-5]\\d)\\.(?<milliseconds>\\d{3}))$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      '/^((?:[a-zA-Z]:)|(?:\\\\{2}\\w[-\\w]*)\\$?)\\\\(?!\\.)((?:(?![\\\\/:*?<>"|])(?![.\\x20](?:\\\\|$))[\\x20-\\x7E])+\\\\(?!\\.))*((?:(?:(?![\\\\/:*?<>"|])(?![ .]$)[\\x20-\\x7E])+)\\.((?:(?![\\\\/:*?<>"|])(?![ .]$)[\\x20-\\x7E]){2,15}))?$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(39)}"
  },
  {
    input:
      "/(?!(?:1582\\D10\\D(?:0?[5-9]|1[0-4]))|(?:1752\\D0?9\\D(?:0?[3-9]|1[0-3])))(?n:^(?=\\d)((?'year'\\d{4})(?'sep'[-.\\/])(?'month'0?[1-9]|1[012])\\k'sep'(?'day'(?<!(?:0?[469]|11).)31|(?<!0?2.)30|2[0-8]|1\\d|0?[1-9]|(?:(?<=(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:\\d\\d)(?:[02468][048]|[13579][26]))\\k'sep'(?:0?2)\\k'sep')|(?<!\\k'sep'(?:0?2)\\k'sep'))29)(?(?=\\x20\\d)\\x20|$))?(?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(?i:\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(72, 110)}"
  },
  {
    input:
      "/(?=\\d)^(?:(?!(?:10\\D(?:0?[5-9]|1[0-4])\\D(?:1582))|(?:0?9\\D(?:0?[3-9]|1[0-3])\\D(?:1752)))((?:0?[13578]|1[02])|(?:0?[469]|11)(?!\\/31)(?!-31)(?!\\.31)|(?:0?2(?=.?(?:(?:29.(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:(?:\\d\\d)(?:[02468][048]|[13579][26])(?!\\x20BC))|(?:00(?:42|3[0369]|2[147]|1[258]|09)\\x20BC))))))|(?:0?2(?=.(?:(?:\\d\\D)|(?:[01]\\d)|(?:2[0-8])))))([-.\\/])(0?[1-9]|[12]\\d|3[01])\\2(?!0000)((?=(?:00(?:4[0-5]|[0-3]?\\d)\\x20BC)|(?:\\d{4}(?!\\x20BC)))\\d{4}(?:\\x20BC)?)(?:$|(?=\\x20\\d)\\x20))?((?:(?:0?[1-9]|1[012])(?::[0-5]\\d){0,2}(?:\\x20[aApP][mM]))|(?:[01]\\d|2[0-3])(?::[0-5]\\d){1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^(?=\\d)(?:(?!(?:(?:0?[5-9]|1[0-4])(?:\\.|-|\\/)10(?:\\.|-|\\/)(?:1582))|(?:(?:0?[3-9]|1[0-3])(?:\\.|-|\\/)0?9(?:\\.|-|\\/)(?:1752)))(31(?!(?:\\.|-|\\/)(?:0?[2469]|11))|30(?!(?:\\.|-|\\/)0?2)|(?:29(?:(?!(?:\\.|-|\\/)0?2(?:\\.|-|\\/))|(?=\\D0?2\\D(?:(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:(?:\\d\\d)(?:[02468][048]|[13579][26])(?!\\x20BC))|(?:00(?:42|3[0369]|2[147]|1[258]|09)\\x20BC))))))|2[0-8]|1\\d|0?[1-9])([-.\\/])(1[012]|(?:0?[1-9]))\\2((?=(?:00(?:4[0-5]|[0-3]?\\d)\\x20BC)|(?:\\d{4}(?:$|(?=\\x20\\d)\\x20)))\\d{4}(?:\\x20BC)?)(?:$|(?=\\x20\\d)\\x20))?((?:(?:0?[1-9]|1[012])(?::[0-5]\\d){0,2}(?:\\x20[aApP][mM]))|(?:[01]\\d|2[0-3])(?::[0-5]\\d){1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^(?=\\d)(?:(?!(?:1582(?:\\.|-|\\/)10(?:\\.|-|\\/)(?:0?[5-9]|1[0-4]))|(?:1752(?:\\.|-|\\/)0?9(?:\\.|-|\\/)(?:0?[3-9]|1[0-3])))(?=(?:(?!000[04]|(?:(?:1[^0-6]|[2468][^048]|[3579][^26])00))(?:(?:\\d\\d)(?:[02468][048]|[13579][26]))\\D0?2\\D29)|(?:\\d{4}\\D(?!(?:0?[2469]|11)\\D31)(?!0?2(?:\\.|-|\\/)(?:29|30))))(\\d{4})([-\\/.])(0?\\d|1[012])\\2((?!00)[012]?\\d|3[01])(?:$|(?=\\x20\\d)\\x20))?((?:(?:0?[1-9]|1[012])(?::[0-5]\\d){0,2}(?:\\x20[aApP][mM]))|(?:[01]\\d|2[0-3])(?::[0-5]\\d){1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(?!\\u00a2)\\p{Sc}?(?!0,?\\d)(?:\\d{1,3}(?:([, .])\\d{3})?(?:\\1\\d{3})*|(?:\\d+))((?!\\1)[,.]\\d{2})?$/",
    wasParseError: "{ParsingData.UnsupportedEscape(5, 117)}"
  },
  {
    input: "/^\\d?\\d'(\\d|1[01])\"$/",
    isPumpable: false
  },
  {
    input:
      "/^(?n:(?!-[\\d\\,]*K)      (?!-((\\d{1,3},)*((([3-9]\\d\\d|2[89]\\d|27[4-9])\\xB0C)|(((4[6-9]|[5-9]\\d)\\d)\\xB0F))))  -?\\d{1,3}(,\\d{3})*(\\xB0[CF]|K) )$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  {
    input: "/([2-9JQKA]|10)([\\u2660\\u2663\\u2665\\u2666])/",
    wasParseError: "{ParsingData.UnsupportedEscape(17, 117)}"
  },
  {
    input: "/(?-i:\\b\\p{Ll}+\\b)/",
    wasParseError: "{ParsingData.UnsupportedEscape(8, 112)}"
  },
  {
    input: "/(?-i:\\b\\p{Lu}+\\b)/",
    wasParseError: "{ParsingData.UnsupportedEscape(8, 112)}"
  },
  {
    input: "/\\b-?[1-9](?:\\.\\d+)?[Ee][-+]?\\d+\\b/",
    isPumpable: false
  },
  {
    input: "/(?![\\uD800-\\uDBFF])(?![\\uDC00-\\uDFFF])[\\u0080-\\uFFFF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(5, 117)}"
  },
  {
    input: "/[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(2, 117)}"
  },
  {
    input: "/(\\S+)\\x20{2,}(?=\\S+)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(13)}"
  },
  {
    input: "/^(?:[ -~]{10,25}(?:$|(?:[\\w!?.])\\s))/",
    isPumpable: false
  },
  {
    input:
      "/^((31(?!(\\-)((F|f)(E|e)(B|b)|(A|a)(P|p)(R|r)|(J|j)(U|u)(N|n)|(S|s)(E|e)(P|p)|(N|n)(O|o)(V|v))))|((30|29)(?!(\\-)((F|f)(E|e)(B|b))))|(29(?=(\\-)(F|f)(E|e)(B|b)(\\-)(((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])(\\-)((J|j)(A|a)(N|n)|(F|f)(E|e)(B|b)|(M|m)(A|a)(R|r)|((M|m)(A|a)(Y|y))|(A|a)(P|p)(R|r)|(J|j)(U|u)(L|l)|(J|j)(U|u)(N|n)|(A|a)(U|u)(G|g)|(O|o)(C|c)(T|t)|(S|s)(E|e)(P|p)|(N|n)(O|o)(V|v)|(D|d)(E|e)(C|c))(\\-)((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/^([A-Z]{2}-[A-Z]{2}-[0-9]{2}$|^([A-Z]{2}-[0-9]{2}-[A-Z]{2}$|^([0-9]{2}-[A-Z]{2}-[A-Z]{2}$|^([A-Z]{2}-[0-9]{2}-[0-9]{2}$\\//",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(a(?:[cdefgilmnoqrstuwxz]|ero|(?:rp|si)a)|b(?:[abdefghijmnorstvwyz]iz)|c(?:[acdfghiklmnoruvxyz]|at|o(?:m|op))|d[ejkmoz]|e(?:[ceghrstu]|du)|f[ijkmor]|g(?:[abdefghilmnpqrstuwy]|ov)|h[kmnrtu]|i(?:[delmnoqrst]|n(?:fo|t))|j(?:[emop]|obs)|k[eghimnprwyz]|l[abcikrstuvy]|m(?:[acdeghklmnopqrstuvwxyz]|il|obi|useum)|n(?:[acefgilopruz]|ame|et)|o(?:m|rg)|p(?:[aefghklmnrstwy]|ro)|qa|r[eosuw]|s[abcdeghijklmnortuvyz]|t(?:[cdfghjklmnoprtvwz]|(?:rav)?el)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])/",
    isPumpable: false
  },
  {
    input: "/(?:-(?!0))?\\d+(?:(?: \\d+)?\\/\\d+)?/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: "/^([a-zA-Z0-9]{1,15})$/",
    isPumpable: false
  },
  {
    input:
      "/([A-HJ-PR-Y]{2}([0][1-9]|[1-9][0-9])|[A-HJ-PR-Y]{1}([1-9]|[1-2][0-9]|30|31|33|40|44|55|50|60|66|70|77|80|88|90|99|111|121|123|222|321|333|444|555|666|777|888|999|100|200|300|400|500|600|700|800|900))[ ][A-HJ-PR-Z]{3}$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{4})-([0-1][0-9])-([0-3][0-9])\\s([0-1][0-9]|[2][0-3]):([0-5][0-9]):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\x20'\\.]{8,64}[^\\s]$/",
    isPumpable: false
  },
  {
    input: "/^((?:\\+27|27)|0)(\\d{2})-?(\\d{3})-?(\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^\\d{3}-\\d{2}-\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^(([A-Z]{1,2}[0-9]{1,2})|([A-Z]{1,2}[0-9][A-Z]))\\s?([0-9][A-Z]{2})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z]{5})([a-zA-Z0-9-]{3,12})/",
    isPumpable: false
  },
  {
    input:
      "/^09(73|74|05|06|15|16|17|26|27|35|36|37|79|38|07|08|09|10|12|18|19|20|21|28|29|30|38|39|89|99|22|23|32|33)\\d{3}\\s?\\d{4}/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z|a-z|&]{3})(([0-9]{2})([0][13456789]|[1][012])([0][1-9]|[12][\\d]|[3][0])|([0-9]{2})([0][13578]|[1][02])([0][1-9]|[12][\\d]|[3][01])|([02468][048]|[13579][26])([0][2])([0][1-9]|[12][\\d])|([1-9]{2})([0][2])([0][1-9]|[12][0-8]))(\\w{2}[A|a|0-9]{1})$|^([A-Z|a-z]{4})(([0-9]{2})([0][13456789]|[1][012])([0][1-9]|[12][\\d]|[3][0])|([0-9]{2})([0][13578]|[1][02])([0][1-9]|[12][\\d]|[3][01])|([02468][048]|[13579][26])([0][2])([0][1-9]|[12][\\d])|([1-9]{2})([0][2])([0][1-9]|[12][0-8]))((\\w{2})([A|a|0-9]{1})){0,3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(0[1-9]|[12][0-9]|3[01])[\\s\\.\\-\\/](J(anuary|uly|an|AN)|M(arch|ar|AR|ay|AY)|A(ugust|ug|UG)|(O(ctober|ct|CT)|(D(ecember|ec|EC))))[\\s\\.\\-\\/][1-9][0-9]{3}|(0[1-9]|[12][0-9]|30)[\\s\\.\\-\\/](A(pril|pr|PR)|J(une|un|UN)|S(eptember|ep|EP)|N(ovember|ov|OV))[\\s\\.\\-\\/][1-9][0-9]{3}|(0[1-9]|1[0-9]|2[0-8])[\\s\\.\\-\\/]F(ebruary|eb|EB)[\\s\\.\\-\\/][1-9][0-9]{3}|29[\\s\\.\\-\\/]F(ebruary|eb|EB)[\\s\\.\\-\\/]((0[48]|[2468][048]|[13579][26])00|[0-9]{2}(0[48]|[2468][048]|[13579][26]))$/",
    isPumpable: false
  },
  {
    input: "/(<(?!\\btd|tr\\b)(\\w*)[^>\\/]*>)(\\s*)(<\\/\\2>)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/(<\\b(\\w*)\\b[^>\\/]*>)(?<content>.*?)(<\\/\\2>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(21, 60)}"
  },
  {
    input:
      "/^(((0?[1-9]|1[012])\\/(0?[1-9]|1\\d|2[0-8])|(0?[13456789]|1[012])\\/(29|30)|(0?[13578]|1[02])\\/31)\\/(19|[2-9]\\d)\\d{2}|0?2\\/29\\/((19|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(([2468][048]|[3579][26])00)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|1[012])\\/(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])\\/(29|30)|(0[13578]|1[02])\\/31)\\/[2-9]\\d{3}|02\\/29\\/(([2-9]\\d)(0[48]|[2468][048]|[13579][26])|(([2468][048]|[3579][26])00)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|[12]\\d|3[01])\\/(0[13578]|1[02])\\/((19|[2-9]\\d)\\d{2}))|((0[1-9]|[12]\\d|30)\\/(0[13456789]|1[012])\\/((19|[2-9]\\d)\\d{2}))|((0[1-9]|1\\d|2[0-8])\\/02\\/((19|[2-9]\\d)\\d{2}))|(29\\/02\\/((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^([2-9]\\d{3}((0[1-9]|1[012])(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])(29|30)|(0[13578]|1[02])31)|(([2-9]\\d)(0[48]|[2468][048]|[13579][26])|(([2468][048]|[3579][26])00))0229)$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\d{2}((0[1-9]|1[012])(0[1-9]|1\\d|2[0-8])|(0[13456789]|1[012])(29|30)|(0[13578]|1[02])31)|([02468][048]|[13579][26])0229)$/",
    isPumpable: false
  },
  {
    input: "/^([01]\\d|2[0123])([0-5]\\d){2}$/",
    isPumpable: false
  },
  {
    input:
      "/^((((0?[1-9]|[12]\\d|3[01])[\\.\\-\\/](0?[13578]|1[02])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|[12]\\d|30)[\\.\\-\\/](0?[13456789]|1[012])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|1\\d|2[0-8])[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|(29[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00)))|(((0[1-9]|[12]\\d|3[01])(0[13578]|1[02])((1[6-9]|[2-9]\\d)?\\d{2}))|((0[1-9]|[12]\\d|30)(0[13456789]|1[012])((1[6-9]|[2-9]\\d)?\\d{2}))|((0[1-9]|1\\d|2[0-8])02((1[6-9]|[2-9]\\d)?\\d{2}))|(2902((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\d{2}((0[13578]|1[02])(0[1-9]|[12]\\d|3[01])|(0[13456789]|1[012])(0[1-9]|[12]\\d|30)|02(0[1-9]|1\\d|2[0-8])))|([02468][048]|[13579][26])0229)$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0?[1-9]|[12]\\d|3[01])[\\.\\-\\/](0?[13578]|1[02])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|[12]\\d|30)[\\.\\-\\/](0?[13456789]|1[012])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|1\\d|2[0-8])[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|(29[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00)))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0?[1-9]|[12]\\d|3[01])[\\.\\-\\/](0?[13578]|1[02])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}|\\d))|((0?[1-9]|[12]\\d|30)[\\.\\-\\/](0?[13456789]|1[012])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}|\\d))|((0?[1-9]|1\\d|2[0-8])[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}|\\d))|(29[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00|[048])))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|[12]\\d|3[01])\\/(0[13578]|1[02])\\/(\\d{2}))|((0[1-9]|[12]\\d|30)\\/(0[13456789]|1[012])\\/(\\d{2}))|((0[1-9]|1\\d|2[0-8])\\/02\\/(\\d{2}))|(29\\/02\\/((0[48]|[2468][048]|[13579][26])|(00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0[1-9]|[12]\\d|3[01])\\/(0[13578]|1[02])\\/((1[6-9]|[2-9]\\d)\\d{2}))|((0[1-9]|[12]\\d|30)\\/(0[13456789]|1[012])\\/((1[6-9]|[2-9]\\d)\\d{2}))|((0[1-9]|1\\d|2[0-8])\\/02\\/((1[6-9]|[2-9]\\d)\\d{2}))|(29\\/02\\/((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))$/",
    isPumpable: false
  },
  {
    input: "/^[\\u0621-\\u064A]+$/",
    wasParseError: "{ParsingData.UnsupportedEscape(3, 117)}"
  },
  {
    input:
      "/((?<strPOBox>((POBox|PO\\sBox)\\s*\\d*)),?\\s?)?(((?<strUnit>([\\w\\d\\s\\,]*)),\\s?)?( (?<strStreet>([\\w\\s\\-]*\\w\\s(st\\s)?[\\w]*\\s(street|st|road|rd|close|cl|avenue|ave|av|path|ph|drive|drv|LOOP|COURT|CT|CIRCLE|LANE|LN))  ),?\\s?))?((?<strTown>([\\p{Ll}\\p{Lu}\\p{Lo}\\p{Pc}\\p{Lt}\\p{Lm}\\s]*)),?\\s?)?((?<strState>(Victoria|VIC|New South Wales|NSW|South Australia|SA|Northern Territory|NT|West Australia|WA|Tasmania|TAS|ACT|Queensland|QLD))\\s*)?(?<strPostalCode>(\\d{4}),?\\s?)?(?<strCountry>(Australia))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/(?:[Yy][Oo][Uu][Tt][Uu][Bb][Ee]\\.[Cc][Oo][Mm]\\/watch\\?v=)([\\w-]{11})/",
    isPumpable: false
  },
  {
    input: "/'('{2})*([^'\\r\\n]*)('{2})*([^'\\r\\n]*)('{2})*'/",
    isPumpable: false
  },
  {
    input: "/(^\\([0]\\d{1}\\))(\\d{7}$)|(^\\([0][2]\\d{1}\\))(\\d{6,8}$)|([0][8][0][0])([\\s])(\\d{5,8}$)/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}(\\-)(\\d{3})?$/",
    isPumpable: false
  },
  {
    input:
      "/^[0-9]%?$|^1[0-9]%?$|^2[0-9]%?$|^3[0-5]%?$|^[0-9]\\.\\d{1,2}%?$|^1[0-9]\\.\\d{1,2}%?$|^2[0-9]\\.\\d{1,2}%?$|^3[0-4]\\.\\d{1,2}%?$|^35%?$/",
    isPumpable: false
  },
  {
    input: "/^(([0]?[1-9])|(1[0-2]))\\/(([0]?[1-9])|([1,2]\\d{1})|([3][0,1]))\\/[12]\\d{3}$/",
    isPumpable: false
  },
  {
    input: "/(^(09|9)[1][1-9]\\\\d{7}$)|(^(09|9)[3][12456]\\\\d{7}$)/",
    isPumpable: false
  },
  {
    input: "/<[^>]*>/",
    isPumpable: false
  },
  {
    input: "/[\\u0600-\\u06FF]/",
    wasParseError: "{ParsingData.UnsupportedEscape(2, 117)}"
  },
  {
    input: "/^([0-1])*$/",
    isPumpable: false
  },
  {
    input: "/^([0-7])*$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-fA-F]){8}$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-fA-F])*$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\$|R\\$|\\-\\$|\\-R\\$|\\$\\-|R\\$\\-|-)?([0-9]{1}[0-9]{0,2}(\\.[0-9]{3})*(\\,[0-9]{0,2})?|[1-9]{1}[0-9]{0,}(\\,[0-9]{0,2})?|0(\\,[0-9]{0,2})?|(\\,[0-9]{1,2})?)$/",
    isPumpable: false
  },
  {
    input:
      "/^[a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+(\\.[a-z0-9,!#\\$%&'\\*\\+\\/=\\?\\^_`\\{\\|}~-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)*\\.([a-z]{2,})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-ZáéíóúàèìòùãõâêîôûüïçÁÉÍÓÚÀÈÌÒÙÂÊÎÔÛÃÕÜÏÇ£¢$#,.ºª°\\s\\/-[0-9]]){1,40}$/",
    wasParseError: "{ParsingData.NonAsciiInput(9, 195)}"
  },
  {
    input: "/^\\d[a-zA-Z]\\w{1}\\d{2}[a-zA-Z]\\w{1}\\d{3}$/",
    isPumpable: false
  },
  {
    input: "/^\\d[a-zA-Z0-9]+$/",
    isPumpable: false
  },
  {
    input: "/Validation of Mexican RFC for tax payers (individuals)/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-zA-Z]+[-._+&])*[0-9a-zA-Z]+@([-0-9a-zA-Z]+[.])+[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input: "/^((ht|f)tp(s?))\\:\\/\\/([0-9a-zA-Z\\-]+\\.)+[a-zA-Z]{2,6}(\\:[0-9]+)?(\\/\\S*)?$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\+971[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}|[\\s]{0,1}0)(5[056]{1})[\\s]{0,1}[\\-]{0,1}[\\s]{0,1}[1-9]{1}[0-9]{6}$/",
    isPumpable: false
  },
  {
    input: "/(\\s*\\(?0\\d{4}\\)?\\s*\\d{6}\\s*)|(\\s*\\(?0\\d{3}\\)?\\s*\\d{3}\\s*\\d{4}\\s*)/",
    isPumpable: false
  },
  {
    input: '/"{(<h)([1-6])(.id=\\")(.+?\\")(.+?)(</h[1-6])}",\'\\\\2~<a href="#\\\\4\\\\5</a\'/',
    wasParseError: "{ParsingData.IncompleteRangeDefinition(1)}"
  },
  {
    input: "/^(\\$)?(\\s)?(\\-)?((\\d+)|(\\d{1,3})(\\,\\d{3})*)(\\.\\d{2,})?$/",
    isPumpable: false
  },
  {
    input: "/^(9\\d{2})([ \\-]?)([7]\\d|8[0-8])([ \\-]?)(\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/\\/\\*((?!\\*\\/)[\\d\\D\\s])*\\*\\//",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input:
      '/("(([a-zA-Z]:)|(\\\\\\\\[^/\\\\:\\*\\?""<>\\|]+(\\\\[a-zA-Z]\\$)?))\\\\([^/\\\\:\\*\\?""<>\\|]+\\\\)*[^/\\\\:\\*\\?""<>\\|]+(\\.[^/\\\\:\\*\\?""<>\\|]+[^/\\\\:\\*\\?""<>\\|\\s])?")|((([a-zA-Z]:)|(\\\\\\\\[^/\\\\:\\*\\?""<>\\|\\s]+(\\\\[a-zA-Z]\\$)?))\\\\([^/\\\\:\\*\\?""<>\\|\\s]+\\\\)*[^/\\\\:\\*\\?""<>\\|\\s]+(\\.[a-zA-Z0-9]+)?)/',
    isPumpable: false
  },
  {
    input: "/(^\\+[0-9]{2}|^\\+[0-9]{2}\\(0\\)|^\\(\\+[0-9]{2}\\)\\(0\\)|^00[0-9]{2}|^0)([0-9]{9}$|[0-9\\-\\s]{10}$)/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{4}\\s{0,1}[a-zA-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/([^_.]([a-zA-Z0-9_]*[.]?[a-zA-Z0-9_]+[^_]){2})@([a-z0-9]+[.]([a-z]{2,3}|[a-z]{2,3}[.][a-z]{2,3}))/",
    isPumpable: false
  },
  {
    input: "/^\\[0-9]{4}\\-\\[0-9]{2}\\-\\[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: "/(?:\\d|I{1,3})?\\s?\\w{2,}\\.?\\s*\\d{1,}\\:\\d{1,}-?,?\\d{0,2}(?:,\\d{0,2}){0,2}/",
    isPumpable: false
  },
  {
    input:
      "/(?:\\+?1[ .*-]?)?(?:\\(? ?)?\\d{3}(?: ?\\)?)? ?(?:\\*|(?:\\.|-){1,2})? ?\\d{3} ?(?:\\*|(?:\\.|-){1,2})? ?\\d{4}/",
    isPumpable: false
  },
  {
    input: "/(-?(\\d*\\.\\d{1}?\\d*|\\d{1,}))/",
    isPumpable: false
  },
  {
    input: "/[0-9A-Za-z]/",
    isPumpable: false
  },
  {
    input: "/[^A-Za-z0-9]/",
    isPumpable: false
  },
  {
    input: "/[a-z0-9]{1,11}/",
    isPumpable: false
  },
  {
    input: "/^([0-9]*\\-?\\ ?\\/?[0-9]*)$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{6}[0-9]{2}[A-Za-z]{1}[0-9]{2}[A-Za-z]{1}[0-9]{3}[A-Za-z]{1}$/",
    isPumpable: false
  },
  {
    input:
      "/(^([A-Za-z])([-_.\\dA-Za-z]{1,10})([\\dA-Za-z]{1}))(@)(([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})|(([\\dA-Za-z{1}][-_.\\dA-Za-z]{1,25})\\.([A-Za-z]{2,4}))$)/",
    isPumpable: false
  },
  {
    input: "/^1?[1-9]$|^[1-2]0$/",
    isPumpable: false
  },
  {
    input: "/^[+-]?(?(\\d{1,3},)(\\d{1,3}(,\\d{3})+)|\\d+)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 40)}"
  },
  {
    input:
      "/^((?-i)A[cglmrstu]|B[aehikr]?|C[adeflmorsu]?|D[bsy]|E[rsu]|F[emf]?|G[ade]|H[efgos]?|I[nk]?|Kr?|L[airu]|M[dgnot]|N[abdeiop]|Os?|P[abdmortu]?|R[abefghnu]|S[bcegimnr]?|T[abcehil]|U(u[bhopqst])?|V|W|Xe|Yb?|Z[nr])$/",
    isPumpable: false
  },
  {
    input:
      "/^(ftp|https?):\\/\\/([^:]+:[^@]*@)?([a-zA-Z0-9][-_a-zA-Z0-9]*\\.)*([a-zA-Z0-9][-_a-zA-Z0-9]*){1}(:[0-9]+)?\\/?(((\\/|\\[|\\]|-|~|_|\\.|:|[a-zA-Z0-9]|%[0-9a-fA-F]{2})*)\\?((\\/|\\[|\\]|-|~|_|\\.|,|:|=||\\{|\\}|[a-zA-Z0-9]|%[0-9a-fA-F]{2})*\\&?)*)?(#([-_.a-zA-Z0-9]|%[a-fA-F0-9]{2})*)?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^([+a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,6}|[0-9]{1,3})(\\]?)$/",
    isPumpable: false
  },
  {
    input:
      "/(?i)^((((0[1-9])|([12][0-9])|(3[01])) ((JAN)|(MAR)|(MAY)|(JUL)|(AUG)|(OCT)|(DEC)))|((((0[1-9])|([12][0-9])|(30)) ((APR)|(JUN)|(SEP)|(NOV)))|(((0[1-9])|([12][0-9])) FEB))) \\d\\d\\d\\d ((([0-1][0-9])|(2[0-3])):[0-5][0-9]:[0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: '/(?mi:(?<=^(([^\'"\\n])|("[^"]*"))*[\\t ])_(?=\\s*$))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/(http|ftp|https):\\/\\/[\\w\\-_]+(\\.[\\w\\-_]+)+([\\w\\-\\.,@?^=%&:\\/~\\+#]*[\\w\\-\\@?^=%&\\/~\\+#])?/",
    isPumpable: false
  },
  {
    input: "/^(([0-9]|1[0-9]|2[0-4])(\\.[0-9][0-9]?)?)$|([2][5](\\.[0][0]?)?)$/",
    isPumpable: false
  },
  {
    input: '/(?<!\\\\)\\"(?:[^\\"]*(?<!\\\\)\\\\\\")*[^\\"]*\\"/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^(?:(?<scheme>[a-z]+):\\/\\/)?(?:(?<usern>[a-z0-9_.]*)(?::(?<passw>[a-z0-9_.]*))?@)?(?<domain>(?:(?:[a-z][a-z0-9_-]+\\.?)+|[0-9]{1,3}(?:\\.[0-9]{1,3}){3}))(?::(?<port>[0-9]+))?(?<path>(?:\\/[.%a-z0-9_]*)+)?(?:\\?(?<query>(?:&?[][a-z0-9_]+(?:\\=?[a-z0-9_;]*)?)+))?(?:#(?<fragment>[a-z0-9_]+))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/^\\([0-9]{3}\\)\\s?[0-9]{3}(-|\\s)?[0-9]{4}$|^[0-9]{3}-?[0-9]{3}-?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^.*([^\\.][\\.](([gG][iI][fF])|([Jj][pP][Gg])|([Jj][pP][Ee][Gg])|([Bb][mM][pP])|([Pp][nN][Gg])))/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1}$|^[0-9]{1}[0-9]{1}[0-9]{1}[0-9]{1}$|^9999$/",
    isPumpable: false
  },
  {
    input: "/^(([0-2])?([0-9]))$/",
    isPumpable: false
  },
  {
    input:
      "/^\\d{2}\\-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\\-\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/(?<DATE>(?:(?:(?<year1>(?:1[89])|(?:[2468][048]|[3579][26])(?!00))(?<year2>00|[02468][1235679]|[13579][01345789])(?:(?:(?<month>(?:[0][13578])|(?:1[02]))(?<day>0[1-9]|[12][0-9]|3[01]))|(?:(?<month>0[469]|11)(?<day>0[1-9]|[12][0-9]|30))|(?:(?<month>02)(?<day>0[1-9]|1[0-9]|2[0-8])))|(?:(?:(?<year1>(?:[2468][048]|[3579][26])00)|(?<year1>(?:(?:1[89])|[2468][048]|[3579][26])(?!00))(?<year2>[02468][048]|[13579][26]))(?:(?:(?<month>(?:(?:[0][13578])|(?:1[02])))(?<day>0[1-9]|[12][0-9]|3[01]))|(?:(?<month>0[469]|11)(?<day>(?:0[1-9]|[12][0-9]|30)))|(?:(?<month>02)(?<day>0[1-9]|[12][0-9])))))))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^\\-?[0-9]{1,3}(\\,[0-9]{3})*(\\.[0-9]+)?$|^[0-9]+(\\.[0-9]+)?$/",
    isPumpable: false
  },
  {
    input: "/^\\$?(\\d{1,3},?(\\d{3},?)*\\d{3}(\\.\\d{1,3})?|\\d{1,3}(\\.\\d{2})?)$/",
    isPumpable: false
  },
  {
    input: "/^\\d{0,2}(\\.\\d{1,4})? *%?$/",
    isPumpable: false
  },
  {
    input: "/(^\\d*\\.\\d{2}$)/",
    isPumpable: false
  },
  {
    input: '/^[a-zA-Z]:(\\\\|(\\\\[^\\\\/\\s:*"<>|]+)+)>/',
    isPumpable: false
  },
  {
    input:
      "/[p|P][\\s]*[o|O][\\s]*[b|B][\\s]*[o|O][\\s]*[x|X][\\s]*[a-zA-Z0-9]*|\\b[P|p]+(OST|ost|o|O)?\\.?\\s*[O|o|0]+(ffice|FFICE)?\\.?\\s*[B|b][O|o|0]?[X|x]+\\.?\\s+[#]?(\\d+)*(\\D+)*\\b/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/(((^[>]?1.0)(\\d)?(\\d)?)|(^[<]?1.0(([1-9])|(\\d[1-9])|([1-9]\\d)))|(^[<]?1.4(0)?(0)?)|(^[<>]?1.(([123])(\\d)?(\\d)?)))$/",
    isPumpable: false
  },
  {
    input:
      "/(^(4|5)\\d{3}-?\\d{4}-?\\d{4}-?\\d{4}|(4|5)\\d{15})|(^(6011)-?\\d{4}-?\\d{4}-?\\d{4}|(6011)-?\\d{12})|(^((3\\d{3}))-\\d{6}-\\d{5}|^((3\\d{14})))/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[a-zA-Z])[^\\*\\s]{4,8}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      '/^(?:"[^\\"]*"|[a-z0-9&+_-](?:\\.?[a-z0-9&+_-]+)*)@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])*(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])*)*|(\\[)?(?:[01]?\\d?\\d|2[0-4]\\d|25[0-5])(?:\\.(?:[01]?\\d?\\d|2[0-4]\\d|25[0-5])){3}(?(1)\\]|))$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(199, 40)}"
  },
  {
    input: '/(\\"(?<word>[^\\"]+|\\"\\")*\\"|(?<word>[^,]*))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input:
      "/^(\\{1}[2-9]{1}[0-9]{2}\\){1}[ ]?[2-9]{1}[0-9]{2}(-| )?[0-9]{4}|[2-9]{1}[0-9]{2}[ ]{1}[2-9]{1}[0-9]{2}[ ]{1}[0-9]{4}|[2-9]{1}[0-9]{2}[2-9]{1}[0-9]{6}|[2-9]{1}[0-9]{2}-{1}[2-9]{1}[0-9]{2}-{1}[0-9]{4}){1}$/",
    isPumpable: false
  },
  {
    input:
      "/^((Sir|Dr.|Mr.|Mrs.|Ms.|Rev.){1}[ ]?)?([A-Z]{1}[.]{1}([A-Z]{1}[.]{1})?|[A-Z]{1}[a-z]{1,}|[A-Z]{1}[a-z]{1,}[-]{1}[A-Z]{1}[a-z]{1,}|[A-Z]{1}[a-z]{0,}[ ]{1}[A-Z]{1}[a-z]{0,}){1}$/",
    isPumpable: false
  },
  {
    input: "/<(.*?)>/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{6}[\\s\\-]{1}[0-9]{12}|[0-9]{18})$/",
    isPumpable: false
  },
  {
    input:
      "/^[1-9]\\d{2}\\s*-\\s*\\d{3}\\s*-\\s*\\d{4}$|^[2-9]\\d{9}|^\\x28\\s*[2-9]\\d{2}\\s*\\x29\\s*\\d{3}\\s*-\\s*\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^ ?(([BEGLMNSWbeglmnsw][0-9][0-9]?)|(([A-PR-UWYZa-pr-uwyz][A-HK-Ya-hk-y][0-9][0-9]?)|(([ENWenw][0-9][A-HJKSTUWa-hjkstuw])|([ENWenw][A-HK-Ya-hk-y][0-9][ABEHMNPRVWXYabehmnprvwxy])))) ?[0-9][ABD-HJLNP-UW-Zabd-hjlnp-uw-z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[+-]?[0-9]+$/",
    isPumpable: false
  },
  {
    input: "/^[+-]?\\d*(([,.]\\d{3})+)?([,.]\\d+)?([eE][+-]?\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$/",
    isPumpable: false
  },
  {
    input: "/^#?(([a-fA-F0-9]{3}){1,2})$/",
    isPumpable: false
  },
  {
    input:
      "/(^\\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)|(^::$)/",
    isPumpable: false
  },
  {
    input: "/^(\\(?[0-9]{3}[\\)-\\.]?\\ ?)?[0-9]{3}[-\\.]?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\\s).{8,20}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/[A-Za-z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+\\/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?:\\.)+(?:[A-Z]{2}|aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|us)\\b/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "^.^@0",
    pumpable: "000",
    suffix: ""
  },
  {
    input: "/^((19|20)\\d\\d)[- \\/.](([1-9]|[0][1-9]|1[012]))[- \\/.](([1-9]|[0][1-9]|1[012])|([12][0-9]|3[01]))$/",
    isPumpable: false
  },
  {
    input: "/\\b(((?!\\d\\d\\d)\\d+|1\\d\\d|2[0-4]\\d|25[0-5])(\\b|\\.)){4}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: "/\\w*$/",
    isPumpable: false
  },
  {
    input: "/\\d{0,7}([\\.|\\,]\\d{0,2})?/",
    isPumpable: false
  },
  {
    input: "/\\d+([\\.|\\,][0]+?[1-9]+)?/",
    isPumpable: false
  },
  {
    input: "/(<(!--.*|script)(.|\\n[^<])*(--|script)>)|(<|<)(\\/?[\\w!?]+)\\s?[^<]*(>|>)|(\\&[\\w]+\\;)/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<!--",
    pumpable: "\\x0at",
    suffix: ""
  },
  {
    input: "/^(\\d{5}-\\d{4}|\\d{5})$|^([a-zA-Z]\\d[a-zA-Z] \\d[a-zA-Z]\\d)$/",
    isPumpable: false
  },
  {
    input: "/^(user=([a-z0-9]+,)*(([a-z0-9]+){1});)?(group=([a-z0-9]+,)*(([a-z0-9]+){1});)?(level=[0-9]+;)?$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{2}/",
    isPumpable: false
  },
  {
    input: "/^[1-9][0-9]{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z0_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$/",
    isPumpable: false
  },
  {
    input:
      "/^((((((0[1-9])|(1\\d)|(2[0-8]))\\.((0[123456789])|(1[0-2])))|(((29)|(30))\\.((0[13456789])|(1[0-2])))|((31)\\.((0[13578])|(1[02]))))\\.\\d{4})|((29)\\.(02)\\.\\d{2}(([02468][048])|([13579][26]))))(\\s((0\\d)|(1\\d)|(2[0-3]))\\:([0-5]\\d)\\:([0-5]\\d)\\.\\d{7})$/",
    isPumpable: false
  },
  {
    input: "/^(([0-9])|([0-2][0-9])|(3[0-1]))\\/(([1-9])|(0[1-9])|(1[0-2]))\\/(([0-9][0-9])|([1-2][0,9][0-9][0-9]))$/",
    isPumpable: false
  },
  {
    input:
      "/^(3[0-1]|2[0-9]|1[0-9]|0[1-9])(0[0-9]|1[0-9]|2[0-3])([0-5][0-9])\\sUTC\\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s[0-9]{2}$/",
    isPumpable: false
  },
  {
    input: '/"[^"\\r\\n]*"/',
    isPumpable: false
  },
  {
    input: "/^[A-Z]{1}-[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/(?=.*[A-Z]+.*)[A-Z0-9&%.\\/-]*/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^\\.{1}/",
    isPumpable: false
  },
  {
    input: "/^(\\d*\\s*\\-?\\s*\\d*)$/",
    isPumpable: false
  },
  {
    input:
      "/^(((\\+44\\s?|0044\\s?)?|(\\(?0))((2[03489]\\)?\\s?\\d{4}\\s?\\d{4})|(1[23456789]1\\)?\\s?\\d{3}\\s?\\d{4})|(1[23456789][234578][0234679]\\)?\\s?\\d{6})|(1[2579][0245][0467]\\)?\\s?\\d{5})|(11[345678]\\)?\\s?\\d{3}\\s?\\d{4})|(1[35679][234689]\\s?[46789][234567]\\)?\\s?\\d{4,5})|([389]\\d{2}\\s?\\d{3}\\s?\\d{4})|([57][0-9]\\s?\\d{4}\\s?\\d{4})|(500\\s?\\d{6})|(7[456789]\\d{2}\\s?\\d{6})))$/",
    isPumpable: false
  },
  {
    input: "/^0*(\\d{1,3}(\\.?\\d{3})*)\\-?([\\dkK])$/",
    isPumpable: false
  },
  {
    input: "/[0-9]{4}-([0][0-9]|[1][0-2])-([0][0-9]|[1][0-9]|[2][0-9]|[3][0-1])/",
    isPumpable: false
  },
  {
    input:
      "/^\\$?\\d{1,2}\\,\\d{3}?\\,\\d{3}?(\\.(\\d{2}))$|^\\$?\\d{1,3}?\\,\\d{3}?(\\.(\\d{2}))$|^\\$?\\d{1,3}?(\\.(\\d{2}))$/",
    isPumpable: false
  },
  {
    input:
      "/<ul>\\n<li>(?<type>document_name|url)=(?<doc>.*?)<li>.*?<ul>\\n(?:<li>(?<propName>.*?)\\n<li>(?<propValue>.*?))+<\\/ul>\\n<\\/ul>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(12, 60)}"
  },
  {
    input: '/(?<quote>["]?)(?<param>(?:\\k<quote>{2}|[^"]+)*)\\k<quote>[ ]+/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(([1-9])|(0[1-9])|(1[0-2]))\\/(([0-9])|([0-2][0-9])|(3[0-1]))\\/(([0-9][0-9])|([1-2][0,9][0-9][0-9]))\\s+(20|21|22|23|[01]\\d|\\d)(([:.][0-5]\\d){1,2})$/",
    isPumpable: false
  },
  {
    input: '/[ ]*=[ ]*[\\"]*cid[ ]*:[ ]*([^\\"<> ]+)/',
    isPumpable: false
  },
  {
    input: '/<img .+ src[ ]*=[ ]*\\"(.+)\\"/',
    isPumpable: false
  },
  {
    input: "/^-?\\d*(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/<img([^>]*[^\\/])>/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9]+(([_][a-zA-Z0-9])?[a-zA-Z0-9]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "0",
    suffix: "!"
  },
  {
    input:
      "/^((\\d{2}(([02468][048])|([13579][26]))[-]?((((0?[13578])|(1[02]))[-]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[-]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[-]?((0?[1-9])|([1-2][0-9])))))|(\\d{2}(([02468][1235679])|([13579][01345789]))[-]?((((0?[13578])|(1[02]))[-]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[-]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[-]?((0?[1-9])|(1[0-9])|(2[0-8]))))))(\\s((([0-1]?[0-9])|([2][0-3]))\\:([0-5][0-9])))?$/",
    isPumpable: false
  },
  {
    input: "/\\p{IsArabic}/",
    wasParseError: "{ParsingData.UnsupportedEscape(1, 112)}"
  },
  {
    input: "/(^\\d{5}$)|(^\\d{5}-\\d{4}$)/",
    isPumpable: false
  },
  {
    input: "/((<body)|(<BODY))([^>]*)>/",
    isPumpable: false
  },
  {
    input: "/^-?((([0-9]{1,3},)?([0-9]{3},)*?[0-9]{3})|([0-9]{1,3}))\\.[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^(\\$)?((\\d{1,5})|(\\d{1,3})(\\,\\d{3})*)(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/\\b[\\w]+[\\w.-][\\w]+@[\\w]+[\\w.-]\\.[\\w]{2,4}\\b/",
    isPumpable: false
  },
  {
    input: "/^((0[1-9])|(1[0-2]))\\/*((2011)|(20[1-9][1-9]))$/",
    isPumpable: false
  },
  {
    input: "/X-Spam-Level:\\s[*]{11}/",
    isPumpable: false
  },
  {
    input:
      "/^(?:[a-zA-Z0-9_'^&\\/+-])+(?:\\.(?:[a-zA-Z0-9_'^&\\/+-])+)*@(?:(?:\\[?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\]?)|(?:[a-zA-Z0-9-]+\\.)+(?:[a-zA-Z]){2,}\\.?)$/",
    isPumpable: false
  },
  {
    input: "/^([(][1-9]{2}[)] )?[0-9]{4}[-]?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: '/Password="(\\{.+\\}[0-9a-zA-Z]+[=]*|[0-9a-zA-Z]+)"/',
    isPumpable: false
  },
  {
    input: "/^((([+])?[1])?\\s{0,1}\\d{3}\\s{0,1}\\d{3}\\s{0,1}\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^([0]?[1-9]|[1][0-2]):([0-5][0-9]|[1-9]) [aApP][mM]$/",
    isPumpable: false
  },
  {
    input: "/^([0]?[1-9]|[1][0-2]|[2][0-3]):([0-5][0-9]|[1-9])$/",
    isPumpable: false
  },
  {
    input: "/^(1?(-?\\d{3})-?)?(\\d{3})(-?\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/[1-9][0-9]/",
    isPumpable: false
  },
  {
    input: "/^\\s*[a-zA-Z0-9&\\-\\.\\/,\\s]+\\s*$/",
    isPumpable: false
  },
  {
    input: "/(^(\\d{2}.\\d{3}.\\d{3}\\/\\d{4}-\\d{2})|(\\d{14})$)/",
    isPumpable: false
  },
  {
    input: "/((([7-9])(\\d{3})([-])(\\d{4}))|(([7-9])(\\d{7})))/",
    isPumpable: false
  },
  {
    input: "/(^(\\d{3}.\\d{3}.\\d{3}-\\d{2})|(\\d{11})$)/",
    isPumpable: false
  },
  {
    input: "/(^\\d{3,4}\\-\\d{4}$)|(^\\d{7,8}$)/",
    isPumpable: false
  },
  {
    input: "/(((0[123456789]|10|11|12)([\\/])(([1][9][0-9][0-9])|([2][0-9][0-9][0-9]))))/",
    isPumpable: false
  },
  {
    input:
      "/(((0[1-9]|[12][0-9]|3[01])([\\/])(0[13578]|10|12)([\\/])([1-2][0,9][0-9][0-9]))|(([0][1-9]|[12][0-9]|30)([\\/])(0[469]|11)([\\/])([1-2][0,9][0-9][0-9]))|((0[1-9]|1[0-9]|2[0-8])([\\/])(02)([\\/])([1-2][0,9][0-9][0-9]))|((29)(\\.|-|\\/)(02)([\\/])([02468][048]00))|((29)([\\/])(02)([\\/])([13579][26]00))|((29)([\\/])(02)([\\/])([0-9][0-9][0][48]))|((29)([\\/])(02)([\\/])([0-9][0-9][2468][048]))|((29)([\\/])(02)([\\/])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input: "/(^\\d{3,5}\\,\\d{2}$)|(^\\d{3,5}$)/",
    isPumpable: false
  },
  {
    input: "/^\\+?[a-z0-9](([-+.]|[_]+)?[a-z0-9]+)*@([a-z0-9]+(\\.|\\-))+[a-z]{2,6}$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input: "/^\\d{0,2}(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/\\\\red([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\\\green([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\\\blue([01]?\\d\\d?|2[0-4]\\d|25[0-5]);/",
    isPumpable: false
  },
  {
    input: "/^http\\:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(\\/\\S*)?$/",
    isPumpable: false
  },
  {
    input: "/^[http|ftp|wap|https]{3,5}:\\/\\/\\www\\.\\w*\\.[com|net]{2,3}$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z])(?=.*\\d)\\w{4,9}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(11)}"
  },
  {
    input: "/^([A-Z0-9]{5})$/",
    isPumpable: false
  },
  {
    input: "/(1[8,9]|20)[0-9]{2}/",
    isPumpable: false
  },
  {
    input: "/(refs|references|re|closes|closed|close|see|fixes|fixed|fix|addresses) #(\\d+)(( and |, | & | )#(\\d+))*/",
    isPumpable: false
  },
  {
    input:
      "/(((((0[1-9]|[12][0-9]|3[01])\\/(0[13578]|1[02]))|((0[1-9]|[12][0-9]|30)\\/(0[469]|11))|((0[1-9]|[1][0-9]|2[0-8]))\\/02)\\/([0-9]{3}[1-9]|[0-9]{2}[1-9][0-9]{1}|[0-9]{1}[1-9][0-9]{2}|[1-9][0-9]{3}) ((([0-1][0-9])|([2][0-3]))[:][0-5][0-9]$))|(29\\/02\\/(([0-9]{2})(0[48]|[2468][048]|[13579][26])|((0[48]|[2468][048]|[3579][26])00)) ((([0-1][0-9])|([2][0-3]))[:][0-5][0-9]$)))/",
    isPumpable: false
  },
  {
    input: "/\\b[^aeiou]+[aeiou][^aeiou]+\\b/",
    isPumpable: false
  },
  {
    input: "/^([0-9A-Za-z@.]{1,255})$/",
    isPumpable: false
  },
  {
    input:
      "/(À|Á|Â|Ã|Ä|Å|à|á|â|ã|ä|å|&#097;|&#065;|&#064;|&commat;|&alpha;|&#192;|&#193;|&#194;|&#195;|&#196;|&#197;|&Agrave;|&Aacute;|&Acirc;|&Atilde;|&Auml;|&Aring;|&#224;|&#225;|&#226;|&#227;|&#228;|&#229;|&agrave;|&aacute;|&acirc;|&atilde;|&auml;|&aring;)/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 195)}"
  },
  {
    input:
      "/(È|É|Ê|Ë|è|é|ê|ë|&#069;|&#101;|&#200;|&#201;|&#202;|&#203;|&Egrave;|&Eacute;|&Ecirc;|&Euml;|&#232;|&#233;|&#234;|&#235;|&egrave;|&eacute;|&ecirc;|&euml;)/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 195)}"
  },
  {
    input:
      "/(¡|Ì|Í|Î|Ï|ì|í|î|ï|&#033;|&#161;|&iexcl;|&#185;|&sup1;|&brvbar;|&Igrave;|&Iacute;|&Icirc;|&Iuml;|&igrave;|&iacute;|&iuml;|&#204;|&#205;|&#206;|&#207;|&#236;|&#237;|&#238;|&#239;|&#073;|&#105;)/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 194)}"
  },
  {
    input:
      "/(Ò|Ó|Ô|Õ|Ö|Ø|ð|ò|ó|ô|õ|ö|ø|&#048;|&#079;|&#111;|&#210;|&#211;|&#212;|&#213;|&#214;|&#216;|&Ograve;|&Oacute;|&Ocirc;|&Otilde;|&Ouml;|&Oslash;|&#242;|&#243;|&#244;|&#245;|&ograve;|&oacute;|&ocirc;|&otilde;|&ouml;|&oslash;)/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 195)}"
  },
  {
    input:
      "/(Ù|Ú|Û|Ü|ù|ú|û|ü|µ|&#085;|&#117;|&#181;|&micro;|&#217;|&#218;|&#219;|&#220;|&Ugrave;|&Uacute;|&Ucirc;|&Uuml;|&#249;|&#250;|&#251;&#252;|&ugrave;|&uacute;|&ucirc;|&uuml;)/",
    wasParseError: "{ParsingData.NonAsciiInput(1, 195)}"
  },
  {
    input: "/.*[\\$Ss]pecia[l1]\\W[Oo0]ffer.*/",
    isPumpable: false
  },
  {
    input: "/.*[Vv][Ii1]agr.*/",
    isPumpable: false
  },
  {
    input: "/.*[Oo0][Ee][Mm].*/",
    isPumpable: false
  },
  {
    input: "/.*\\$AVE|\\$ave.*/",
    isPumpable: false
  },
  {
    input: "/.*[Pp]re[Ss\\$]cr[iI1]pt.*/",
    isPumpable: false
  },
  {
    input: "/.*[Pp]en[Ii1][\\$s].*/",
    isPumpable: false
  },
  {
    input: "/^[-+]?\\d+(\\.\\d+)?|[-+]?\\.\\d+?$/",
    isPumpable: false
  },
  {
    input: "/^(\\d|,)*\\d*$/",
    isPumpable: false
  },
  {
    input:
      "/\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])T([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:.\\d{7})?[+|-](0[0-9]|1[0-2]):(00|15|30|45)/",
    isPumpable: false
  },
  {
    input: "/^[^-]{1}?[^\\\"\\']*$/",
    isPumpable: false
  },
  {
    input: "/([^a-zA-Z0-9])/",
    isPumpable: false
  },
  {
    input: "/(?![A-Z](\\d)\\1{5,})(^[A-Z]{1,3}(\\d{6}|\\d{9})$)|(^\\d{9}[A-Z][0-9|A-Z]?$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/^(0[1-9]|1[0-2])\\/((0[1-9]|2\\d)|3[0-1])\\/(19\\d\\d|200[0-3])$/",
    isPumpable: false
  },
  {
    input: "/^((\\+)?(\\d{2}[-]))?(\\d{10}){1}?$/",
    isPumpable: false
  },
  {
    input: "/^((\\+)?(\\d{2})[-])?(([\\(])?((\\d){3,5})([\\)])?[-])|(\\d{3,5})(\\d{5,8}){1}?$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z](?:(?:(?:\\w[\\.\\_]?)*)\\w)+)([a-zA-Z0-9])$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "0_",
    suffix: ""
  },
  {
    input: "/^[a-zA-Z]([a-zA-Z[._][\\d]])*[@][a-zA-Z[.][\\d]]*[.][a-z[.][\\d]]*/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^([a-zA-Z0-9])+(([a-zA-Z0-9\\s])+[_-\\/\\/&a-zA-Z0-9]([a-zA-Z0-9\\s])+)*([a-zA-Z0-9])+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "\\x090\\x09\\x0900\\x09",
    suffix: ""
  },
  {
    input:
      "/^((31(?!\\ (Apr(il)?|June?|(Sept|Nov)(ember)?)))|((30|29)(?!\\ Feb(ruary)?))|(29(?=\\ Feb(ruary)?\\ (((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))|(0?[1-9])|1\\d|2[0-8])\\ (Jan(uary)?|Feb(ruary)?|Ma(r(ch)?|y)|Apr(il)?|Ju((ly?)|(ne?))|Aug(ust)?|Oct(ober)?|(Sept|Nov|Dec)(ember)?)\\ ((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input:
      "/\\b((?<![\"'>])(?:https?://)?(?<![-@>])(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])\\.)+(?:com|org|net|gov|mil|biz|info|name|aero|mobi|jobs|museum|[A-Z]{2})(?:/[-A-Z0-9\\/_.]+)?(?:\\?[-A-Z0-9&\\._%=,]+)?(?!['\"<]))\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(3)}"
  },
  {
    input:
      "/^(ht|f)tp(s?)\\:\\/\\/[a-zA-Z0-9\\-\\._]+(\\.[a-zA-Z0-9\\-\\._]+){2,}(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\'\\/\\\\\\+&%\\$#_]*)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "https://a.a.-",
    pumpable: ".-.-",
    suffix: "!"
  },
  {
    input:
      "/(^(3[01]|[12][0-9]|0?[1-9])\\s{1}(Jan|Mar|May|Jul|Aug|Oct|Dec)\\s{1}((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(30|[12][0-9]|0?[1-9])\\s{1}(Apr|Jun|Sep|Nov)\\s{1}((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(2[0-8]|1[0-9]|0?[1-9])\\s{1}(Feb)\\s{1}((1[8-9]\\d{2})|([2-9]\\d{3}))$)|(^(29)\\s{1}(Feb)\\s{1}([2468][048]00)$)|(^(29)\\s{1}(Feb)\\s{1}([3579][26]00)$)|(^(29)\\s{1}(Feb)\\s{1}([1][89][0][48])$)|(^(29)\\s{1}(Feb)\\s{1}([2-9][0-9][0][48])$)|(^(29)\\s{1}(Feb)\\s{1}([1][89][2468][048])$)|(^(29)\\s{1}(Feb)\\s{1}([2-9][0-9][2468][048])$)|(^(29)\\s{1}(Feb)\\s{1}([1][89][13579][26])$)|(^(29)\\s{1}(Feb)\\s{1}([\\/])([2-9][0-9][13579][26])$)/",
    isPumpable: false
  },
  {
    input: "/^([1-9]+[0-9]*|\\d*[.,]\\d)$/",
    isPumpable: false
  },
  {
    input:
      "/^([_a-zA-Z0-9-]+\\.[_a-zA-Z0-9-]*)\\@((([a-zA-Z0-9-]{2,255})\\.(ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|di|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|in|io|iq|ir|is|it|jo|jm|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|an|nc|ne|nf|ng|ni|nl|no|np|nr|nt|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sq|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zr|zw|arpa|arts|biz|com|edu|firm|gov|info|int|mil|nato|net|nom|org|rec|store|web))|((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])))$/",
    isPumpable: false
  },
  {
    input: '/^(([a-zA-Z]\\:)|(\\\\))(\\\\{1}|((\\\\{1})[^\\\\]([^/:*?<>"|]*))+)$/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\!",
    pumpable: "\\|\\]",
    suffix: '"'
  },
  {
    input:
      "/(?n:^(?=\\d)((?<month>(0?[13578])|1[02]|(0?[469]|11)(?!.31)|0?2(?(.29)(?=.29.((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(16|[2468][048]|[3579][26])00))|(?!.3[01])))(?<sep>[-.\\/])(?<day>0?[1-9]|[12]\\d|3[01])\\k<sep>(?<year>(1[6-9]|[2-9]\\d)\\d{2})(?(?=\\x20\\d)\\x20|$))?(?<time>((0?[1-9]|1[012])(:[0-5]\\d){0,2}(?i:\\x20[AP]M))|([01]\\d|2[0-3])(:[0-5]\\d){1,2})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 110)}"
  },
  {
    input:
      "/^(^(100{1,1}$)|^(100{1,1}\\.[0]+?$))|(^([0]*\\d{0,2}$)|^([0]*\\d{0,2}\\.(([0][1-9]{1,1}[0]*)|([1-9]{1,1}[0]*)|([0]*)|([1-9]{1,2}[0]*)))$)$/",
    isPumpable: false
  },
  {
    input: "/((\\d|([a-f]|[A-F])){2}:){5}(\\d|([a-f]|[A-F])){2}/",
    isPumpable: false
  },
  {
    input: "/(?<!\\\\)\\[(\\\\\\[|\\\\\\]|[^\\[\\]]|(?<!\\\\)\\[.*(?<!\\\\)\\])*(?<!\\\\)\\]/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(\\+1 )?\\d{3} \\d{3} \\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\+44\\s\\(0\\)\\s\\d{2}\\s\\d{4}\\s\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\+353\\(0\\)\\s\\d\\s\\d{3}\\s\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\/\\/\\*[\\d\\D]*?\\*\\/\\//",
    isPumpable: false
  },
  {
    input: "/^(((\\+{1})|(0{2}))98|(0{1}))9[1-9]{1}\\d{8}\\Z$/",
    isPumpable: false
  },
  {
    input: "/[v,V,(\\\\/)](\\W|)[i,I,1,l,L](\\W|)[a,A,@,(\\/\\\\)](\\W|)[g,G](\\W|)[r,R](\\W|)[a,A,@,(\\/\\\\))]/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^0$|^[1-9][0-9]*$|^[1-9][0-9]{0,2}(,[0-9]{3})$/",
    isPumpable: false
  },
  {
    input:
      "/^(429496729[0-6]|42949672[0-8]\\d|4294967[01]\\d{2}|429496[0-6]\\d{3}|42949[0-5]\\d{4}|4294[0-8]\\d{5}|429[0-3]\\d{6}|42[0-8]\\d{7}|4[01]\\d{8}|[1-3]\\d{9}|[1-9]\\d{8}|[1-9]\\d{7}|[1-9]\\d{6}|[1-9]\\d{5}|[1-9]\\d{4}|[1-9]\\d{3}|[1-9]\\d{2}|[1-9]\\d|\\d)$/",
    isPumpable: false
  },
  {
    input: "/<[\\w\\\"\\ '\\#\\* \\=\\',\\.\\\\\\(\\)\\/\\-\\$\\{\\}\\[\\]\\|\\*\\?\\+\\^\\&\\:\\%\\;\\!]+>/",
    isPumpable: false
  },
  {
    input: "/((19|20)[\\d]{2}\\/[\\d]{6}\\/[\\d]{2})/",
    isPumpable: false
  },
  {
    input:
      "/[\\s]a[\\s]|[\\s]about[\\s]|[\\s]an[\\s]|[\\s]are[\\s]|[\\s]as[\\s]|[\\s]at[\\s]|[\\s]be[\\s]|[\\s]by[\\s]|[\\s]for[\\s]|[\\s]from[\\s]|[\\s]how[\\s]|[\\s]in[\\s]|[\\s]is[\\s]|[\\s]it[\\s]|[\\s]of[\\s]|[\\s]on[\\s]|[\\s]or[\\s]|[\\s]that[\\s]|[\\s]the[\\s]|[\\s]this[\\s]|[\\s]to[\\s]|[\\s]was[\\s]|[\\s]what[\\s]|[\\s]when[\\s]|[\\s]where[\\s]|[\\s]who[\\s]|[\\s]will[\\s]|[\\s]with[\\s]|[\\s]the[\\s]|[\\s]www[\\s]/",
    isPumpable: false
  },
  {
    input: "/(^0[87][23467]((\\d{7})|( |-)((\\d{3}))( |-)(\\d{4})|( |-)(\\d{7})))/",
    isPumpable: false
  },
  {
    input: "/[0](\\d{9})|([0](\\d{2})( |-)((\\d{3}))( |-)(\\d{4}))|[0](\\d{2})( |-)(\\d{7})/",
    isPumpable: false
  },
  {
    input:
      "/(((\\d{2}((0[13578]|1[02])(0[1-9]|[12]\\d|3[01])|(0[13456789]|1[012])(0[1-9]|[12]\\d|30)|02(0[1-9]|1\\d|2[0-8])))|([02468][048]|[13579][26])0229))(( |-)(\\d{4})( |-)(\\d{3})|(\\d{7}))/",
    isPumpable: false
  },
  {
    input:
      "/[0](\\d{9})|([0](\\d{2})( |-|)((\\d{3}))( |-|)(\\d{4}))|[0](\\d{2})( |-|)(\\d{7})|(\\+|00|09)(\\d{2}|\\d{3})( |-|)(\\d{2})( |-|)((\\d{3}))( |-|)(\\d{4})/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/\\/\\w+?\\s\\w+?\\(([\\w\\s=]+,*|[\\w\\s=]+|(?R))*\\);\\//",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(35, 82)}"
  },
  {
    input:
      '/^(([A-Za-z][A-Za-z0-9.+]*?){1,}?)(,\\s?([^/\\\\:*?"<>|]*((,\\s?(Version=(\\d\\.?){1,4}|Culture=(neutral|\\w{2}-\\w{2})|PublicKeyToken=[a-f0-9]{16})(,\\s?)?){3}|))){0,1}$/',
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      '/^(?<Assembly>(?<AssemblyName>[^\\W/\\\\:*?"<>|,]+)(?:(?:,\\s?(?:(?<Version>Version=(?<VersionValue>(?:\\d{1,2}\\.?){1,4}))|(?<Culture>Culture=(?<CultureValue>neutral|\\w{2}-\\w{2}))|(?<PublicKeyToken>PublicKeyToken=(?<PublicKeyTokenValue>[A-Fa-f0-9]{16})))(?:,\\s?)?){3}|))$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      '/^(?<Namespace>(?:[\\w][\\w\\d]*\\.?)*)\\.(?<Class>[\\w][\\w\\d<>]*(?:(?:\\+[\\w][\\w\\d<>]*)+|))(?:|,\\W?(?<Assembly>(?<AssemblyName>[^\\W/\\\\:*?"<>|]+)(?:$|(?:,\\W?(?:(?<Version>Version=(?<VersionValue>(?:\\d{1,2}\\.?){1,4}))|(?<Culture>Culture=(?<CultureValue>neutral|\\w{2}-\\w{2}))|(?<PublicKeyToken>PublicKeyToken=(?<PublicKeyTokenValue>[A-Fa-f0-9]{16})))(?:,\\W?)?){3})))$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^([a-zA-Z0-9]+[._-])*[a-zA-Z0-9]+@(([a-zA-Z0-9]+|([a-zA-Z0-9]+[.-])+)[a-zA-Z0-9]+\\.[a-zA-Z]{2,4}|([a-zA-Z]\\.com))$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\+{1}|00)\\s{0,1}([0-9]{3}|[0-9]{2})\\s{0,1}\\-{0,1}\\s{0,1}([0-9]{2}|[1-9]{1})\\s{0,1}\\-{0,1}\\s{0,1}([0-9]{8}|[0-9]{7})/",
    isPumpable: false
  },
  {
    input: "/\\/[^]\\/m/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(1)?-?\\(?\\s*([0-9]{3})\\s*\\)?\\s*-?([0-9]{3})\\s*-?\\s*([0-9]{4})\\s*/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*[0-9]){7}[0-9a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*[2-9])([a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*[0-9]){2}([a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*[2-9])([a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*[0-9]){6}[0-9a-zA-Z,#\\/ \\.\\(\\)\\-\\+\\*]*$/",
    isPumpable: false
  },
  {
    input: "/^([A-PR-UWYZ0-9][A-HK-Y0-9][AEHMNPRTVXY0-9]?[ABEHMNPRVWXY0-9]? {1,2}[0-9][ABD-HJLN-UW-Z]{2}|GIR 0AA)$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]*)+(,[0-9]+)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "0",
    suffix: ""
  },
  {
    input: "/(?=(.*\\d.*){2,})(?=(.*[a-zA-Z].*){6,})/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)*/",
    isPumpable: false
  },
  {
    input: "/https?:\\/\\/[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)*\\/\\S*/",
    isPumpable: false
  },
  {
    input:
      "/[A-Za-z0-9!#$%&'*+\\-\\/=?^_`{|}~]+(?:\\.[A-Za-z0-9!#$%&'*+\\-\\/=?^_`{|}~]+)*@[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)*/",
    isPumpable: false
  },
  {
    input:
      "/^(((19|20)(([0][48])|([2468][048])|([13579][26]))|2000)[\\-](([0][13578]|[1][02])[\\-]([012][0-9]|[3][01])|([0][469]|11)[\\-]([012][0-9]|30)|02[\\-]([012][0-9]))|((19|20)(([02468][1235679])|([13579][01345789]))|1900)[\\-](([0][13578]|[1][02])[\\-]([012][0-9]|[3][01])|([0][469]|11)[\\-]([012][0-9]|30)|02[\\-]([012][0-8])))$/",
    isPumpable: false
  },
  {
    input:
      "/^(^(([0-9A-F]{1,4}(((:[0-9A-F]{1,4}){5}::[0-9A-F]{1,4})|((:[0-9A-F]{1,4}){4}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,1})|((:[0-9A-F]{1,4}){3}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,2})|((:[0-9A-F]{1,4}){2}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,3})|(:[0-9A-F]{1,4}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,4})|(::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,5})|(:[0-9A-F]{1,4}){7}))$|^(::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,6})$)|^::$)|^((([0-9A-F]{1,4}(((:[0-9A-F]{1,4}){3}::([0-9A-F]{1,4}){1})|((:[0-9A-F]{1,4}){2}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,1})|((:[0-9A-F]{1,4}){1}::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,2})|(::[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,3})|((:[0-9A-F]{1,4}){0,5})))|([:]{2}[0-9A-F]{1,4}(:[0-9A-F]{1,4}){0,4})):|::)((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{0,2})\\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{0,2})$$/",
    isPumpable: false
  },
  {
    input: "/^\\+[0-9]{1,3}\\([0-9]{3}\\)[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/([^\\.\\?\\!]*)[\\.\\?\\!]/",
    isPumpable: false
  },
  {
    input: "/(([0-1][0-9])|([2][0-3])):([0-5][0-9]):([0-5][0-9])/",
    isPumpable: false
  },
  {
    input: "/^(9|2{1})+([1-9]{1})+([0-9]{7})$/",
    isPumpable: false
  },
  {
    input: "/^(\\+48\\s+)?\\d{3}(\\s*|\\-)\\d{3}(\\s*|\\-)\\d{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^\\$?([1-9][0-9]{3,}(\\.\\d{2})?|(\\d{1,3}\\,\\d{3}|\\d{1,3}\\,\\d{3}(\\.\\d{2})?)|(\\d{1,3}\\,\\d{3}|\\d{1,3}\\,\\d{3}\\,\\d{3}(\\.\\d{2})?)*)?$/",
    isPumpable: false
  },
  {
    input: "/^(([-\\w$%&'*+\\/=?^_`{|}~.]+)@(([-a-zA-Z0-9_]+\\.)*)([-a-zA-Z0-9]+\\.)([a-zA-Z0-9]{2,7}))?$/",
    isPumpable: false
  },
  {
    input:
      "/^(([0]?[1-9]|[1][0-2])[\\/|\\-|\\.]([0-2]\\d|[3][0-1]|[1-9])[\\/|\\-|\\.]([2][0])?\\d{2}\\s+((([0][0-9]|[1][0-2]|[0-9])[\\:|\\-|\\.]([0-5]\\d)\\s*([aApP][mM])?)|(([0-1][0-9]|[2][0-3]|[0-9])[\\:|\\-|\\.]([0-5]\\d))))$/",
    isPumpable: false
  },
  {
    input: "/^(([8]))$|^((([0-7]))$|^((([0-7])).?((25)|(50)|(5)|(75)|(0)|(00))))$/",
    isPumpable: false
  },
  {
    input:
      "/^([a-zA-Z][a-zA-Z0-9+-.]*):((\\/\\/(((([a-zA-Z0-9\\-._~!$&'()*+,;=':]|(%[0-9a-fA-F]{2}))*)@)?((\\[((((([0-9a-fA-F]{1,4}:){6}|(::([0-9a-fA-F]{1,4}:){5})|(([0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){4})|((([0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){3})|((([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){2})|((([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:)|((([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::))((([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}))|(([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5])))))|((([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4})|((([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::))|(v[0-9a-fA-F]+\\.[a-zA-Z0-9\\-._~!$&'()*+,;=':]+))\\])|(([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5]))\\.([0-9]|(1[0-9]{2})|(2[0-4][0-9])|(25[0-5])))|(([a-zA-Z0-9\\-._~!$&'()*+,;=']|(%[0-9a-fA-F]{2}))*))(:[0-9]*)?)((\\/([a-zA-Z0-9\\-._~!$&'()*+,;=':@]|(%[0-9a-fA-F]{2}))*)*))|(\\/?(([a-zA-Z0-9\\-._~!$&'()*+,;=':@]|(%[0-9a-fA-F]{2}))+(\\/([a-zA-Z0-9\\-._~!$&'()*+,;=':@]|(%[0-9a-fA-F]{2}))*)*)?))(\\?(([a-zA-Z0-9\\-._~!$&'()*+,;=':@\\/?]|(%[0-9a-fA-F]{2}))*))?((#(([a-zA-Z0-9\\-._~!$&'()*+,;=':@\\/?]|(%[0-9a-fA-F]{2}))*)))?$/",
    isPumpable: false
  },
  {
    input: "/[-'a-zA-Z]/",
    isPumpable: false
  },
  {
    input: '/(?<word>([\\w]*))(?<prep>([\\,\\.\\!\\?\\-\\:\\;\\""\\(\\)])?)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/(?<street>((\\d+\\-)?[?-?\\.]* )*)(?<IsStreet>((?????)|(????????)|(??-?)|(?-?)|(??-?)|(???????)|(???[ \\.]?)|(???(?:\\.)?)|(?(?:\\.)?)|(??\\.)|(???(?:\\.)?)|(??(?:\\.)?))) *(?<street2>[?-?]{2,} )?(?:?\\.?)?(?<home>\\d+[?-?]?)([ -\\/?]+(???)?(?<building>\\d+)[ -\\/](?<flat>\\d+))*([ -\\/](??\\.? ?)?(?<flat>\\d+))?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/((0)+(\\.[1-9](\\d)?))|((0)+(\\.(\\d)[1-9]+))|(([1-9]+(0)?)+(\\.\\d+)?)|(([1-9]+(0)?)+(\\.\\d+)?)/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/((8|\\+7)-?)?\\(?\\d{3,5}\\)?-?\\d{1}-?\\d{1}-?\\d{1}-?\\d{1}-?\\d{1}((-?\\d{1})?-?\\d{1})?/",
    isPumpable: false
  },
  {
    input: "/([^\\.]*?(\\w+(???|????))[^\\.]*?\\.+)\\s+/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(14, 63)}"
  },
  {
    input: "/^([A-Z0-9?.+-])+([,]([A-Z0-9?.+-])+)*$/",
    isPumpable: false
  },
  {
    input: "/^((00|\\+)49)?(0?[2-9][0-9]{1,})$/",
    isPumpable: false
  },
  {
    input: "/^((00|\\+)49)?(0?1[5-7][0-9]{1,})$/",
    isPumpable: false
  },
  {
    input: "/[1-8][0-9]{2}[0-9]{5}/",
    isPumpable: false
  },
  {
    input: "/^[01]?[- .]?\\(?[2-9]\\d{2}\\)?[- .]?\\d{3}[- .]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-zÀ-ÖØ-öø-ÿ '\\-\\.]{1,22}$/",
    wasParseError: "{ParsingData.NonAsciiInput(8, 195)}"
  },
  {
    input:
      "/^[abceghjklmnprstvxyABCEGHJKLMNPRSTVXY][0-9][abceghjklmnprstvwxyzABCEGHJKLMNPRSTVWXYZ] {0,1}[0-9][abceghjklmnprstvwxyzABCEGHJKLMNPRSTVWXYZ][0-9]$/",
    isPumpable: false
  },
  {
    input: "/^((?=[^\\d])(?=^*[^0-9]$)(?!.*')(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\\s))?(?=.*[^\\d]$).{8,15}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/^(0\\.|([1-9]([0-9]+)?)\\.){3}(0|([1-9]([0-9]+)?)){1}$/",
    isPumpable: false
  },
  {
    input:
      '/(?i)^(((\\\\\\\\(\\?\\\\(UNC\\\\)?)?)([A-Z]:\\\\|([^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.\\s][^\\\\\\/\\:\\*\\?\\"\\<\\>\\|]+[^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.\\s]\\\\){2}))|[A-Z]:\\\\)([^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\s][^\\\\\\/\\:\\*\\?\\"\\<\\>\\|]+[^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\s]\\\\)*([^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.\\s][^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.]+[^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.\\s])(\\.[^\\\\\\/\\:\\*\\?\\"\\<\\>\\|\\.\\s]+)*?$/',
    isPumpable: false
  },
  {
    input:
      "/^((((\\u0660?[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663[\\u0660\\u0661])[\\.\\-\\/](\\u0660?[\\u0661\\u0663\\u0665\\u0667\\u0668]|\\u0661[\\u0660\\u0662])[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660?[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663\\u0660)[\\.\\-\\/](\\u0660?[\\u0661\\u0663\\u0664\\u0665\\u0666\\u0667\\u0668\\u0669]|\\u0661[\\u0660\\u0661\\u0662])[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660?[\\u0661-\\u0669]|\\u0661[\\u0660-\\u0669]|\\u0662[\\u0660-\\u0668])[\\.\\-\\/]\\u0660?\\u0662[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|(\\u0662\\u0669[\\.\\-\\/]\\u0660?\\u0662[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?(\\u0660[\\u0664\\u0668]|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0661\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])|((\\u0661\\u0666|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])\\u0660\\u0660)|\\u0660\\u0660)))|(((\\u0660[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663[\\u0660\\u0661])(\\u0660[\\u0661\\u0663\\u0665\\u0667\\u0668]|\\u0661[\\u0660\\u0662])((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663\\u0660)(\\u0660[\\u0661\\u0663\\u0664\\u0665\\u0666\\u0667\\u0668\\u0669]|\\u0661[\\u0660\\u0661\\u0662])((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660[\\u0661-\\u0669]|\\u0661[\\u0660-\\u0669]|\\u0662[\\u0660-\\u0668])\\u0660\\u0662((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|(\\u0662\\u0669\\u0660\\u0662((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?(\\u0660[\\u0664\\u0668]|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0661\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])|((\\u0661\\u0666|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])\\u0660\\u0660)|\\u0660\\u0660))))$/",
    wasParseError: "{ParsingData.UnsupportedEscape(6, 117)}"
  },
  {
    input:
      "/^((((\\u0660?[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663[\\u0660\\u0661])[\\.\\-\\/](\\u0660?[\\u0661\\u0663\\u0665\\u0667\\u0668]|\\u0661[\\u0660\\u0662])[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660?[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663\\u0660)[\\.\\-\\/](\\u0660?[\\u0661\\u0663\\u0664\\u0665\\u0666\\u0667\\u0668\\u0669]|\\u0661[\\u0660\\u0661\\u0662])[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660?[\\u0661-\\u0669]|\\u0661[\\u0660-\\u0669]|\\u0662[\\u0660-\\u0668])[\\.\\-\\/]\\u0660?\\u0662[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|(\\u0662\\u0669[\\.\\-\\/]\\u0660?\\u0662[\\.\\-\\/]((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?(\\u0660[\\u0664\\u0668]|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0661\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])|((\\u0661\\u0666|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])\\u0660\\u0660)|\\u0660\\u0660)))|(((\\u0660[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663[\\u0660\\u0661])(\\u0660[\\u0661\\u0663\\u0665\\u0667\\u0668]|\\u0661[\\u0660\\u0662])((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660[\\u0661-\\u0669]|[\\u0661\\u0662][\\u0660-\\u0669]|\\u0663\\u0660)(\\u0660[\\u0661\\u0663\\u0664\\u0665\\u0666\\u0667\\u0668\\u0669]|\\u0661[\\u0660\\u0661\\u0662])((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|((\\u0660[\\u0661-\\u0669]|\\u0661[\\u0660-\\u0669]|\\u0662[\\u0660-\\u0668])\\u0660\\u0662((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?[\\u0660-\\u0669]{2}))|(\\u0662\\u0669\\u0660\\u0662((\\u0661[\\u0666-\\u0669]|[\\u0662-\\u0669][\\u0660-\\u0669])?(\\u0660[\\u0664\\u0668]|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0661\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])|((\\u0661\\u0666|[\\u0662\\u0664\\u0666\\u0668][\\u0660\\u0664\\u0668]|[\\u0663\\u0665\\u0667\\u0669][\\u0662\\u0666])\\u0660\\u0660)|\\u0660\\u0660)))|(((0?[1-9]|[12]\\d|3[01])[\\.\\-\\/](0?[13578]|1[02])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|[12]\\d|30)[\\.\\-\\/](0?[13456789]|1[012])[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|((0?[1-9]|1\\d|2[0-8])[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?\\d{2}))|(29[\\.\\-\\/]0?2[\\.\\-\\/]((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00)))|(((0[1-9]|[12]\\d|3[01])(0[13578]|1[02])((1[6-9]|[2-9]\\d)?\\d{2}))|((0[1-9]|[12]\\d|30)(0[13456789]|1[012])((1[6-9]|[2-9]\\d)?\\d{2}))|((0[1-9]|1\\d|2[0-8])02((1[6-9]|[2-9]\\d)?\\d{2}))|(2902((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)|00))))$/",
    wasParseError: "{ParsingData.UnsupportedEscape(6, 117)}"
  },
  {
    input: "/^[+-]?\\d+(\\,\\d{2})? *?$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+((\\s|\\-)[a-zA-Z]+)?$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z]+((((\\-)|(\\s))[a-zA-Z]+)?(,(\\s)?(((j|J)|(s|S))(r|R)(\\.)?|II|III|IV))?)?$/",
    isPumpable: false
  },
  {
    input: "/^(?=.*[a-zA-Z].*[a-zA-Z])(?=.*\\d.*\\d)[a-zA-Z0-9]{6,20}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3})$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9-\\,\\s]{2,64})$/",
    isPumpable: false
  },
  {
    input: "/\\$(\\d)*\\d/",
    isPumpable: false
  },
  {
    input: "/\\bCOPY\\b\\s*\\b(\\w*(-)?\\w*)*\\b/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/^([_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.(([0-9]{1,3})|([a-zA-Z]{2,})))(;[ ]?[_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.(([0-9]{1,3})|([a-zA-Z]{2,})))*$/",
    isPumpable: false
  },
  {
    input:
      "/^((([A-PR-UWYZ](\\d([A-HJKSTUW]|\\d)?|[A-HK-Y]\\d([ABEHMNPRVWXY]|\\d)?))\\s*(\\d[ABD-HJLNP-UW-Z]{2})?)|GIR\\s*0AA)$/",
    isPumpable: false
  },
  {
    input: "/^(0|1)+$/",
    isPumpable: false
  },
  {
    input: "/^((0?[1-9])|(([1|2]\\d)|(3[0|1])))(\\/|-)((0?[1-9])|(1[0|1|2]))(\\/|-)(((19|20)\\d\\d)|(\\d\\d))/",
    isPumpable: false
  },
  {
    input:
      "/(^\\s*(?<firstname>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<middlename>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<lastname>(st\\.?\\s+)?\\w+[^, ]*)(?:(,| ))*\\s+(?<suffix>\\w+\\S*)\\s*$)|(^\\s*(?<firstname>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<lastname>(st\\.?\\s+)?\\w+\\S*)\\s+(?<suffix>(jr)|(sr)|(ii)|(iii)||(iv)|(v)|(vi)|(vii)|(viii))\\s*$)|(^\\s*(?<firstname>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<middlename>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<lastname>(st\\.?\\s+)?\\w+\\S*)\\s*$)|(^\\s*(?<firstname>(?!st\\.?\\s+)\\w+\\S*)\\s+(?<lastname>(st\\.?\\s+)?\\w+\\S*)\\s*$)|(^\\s*(?<lastname>(st\\.?\\s+)?\\w+\\S*)\\s*$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input: "/>(?:(?<t>[^<]*))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/^([a-z0-9]{32})$/",
    isPumpable: false
  },
  {
    input: "/\\/^(\\d{1,2})(\\/)(\\d{1,2})(\\/)(\\d{4})(T|\\s{1,2})(([0-1][0-9])|(2[0-3])):([0-5][0-9])+$\\/;/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(85, 59)}"
  },
  {
    input:
      "/(GB-?)?([1-9][0-9]{2}\\ ?[0-9]{4}\\ ?[0-9]{2})|([1-9][0-9]{2}\\ ?[0-9]{4}\\ ?[0-9]{2}\\ ?[0-9]{3})|((GD|HA)[0-9]{3})/",
    isPumpable: false
  },
  {
    input: "/(IE-?)?[0-9][0-9A-Z\\+\\*][0-9]{5}[A-Z]/",
    isPumpable: false
  },
  {
    input: "/(LT-?)?([0-9]{9}|[0-9]{12})/",
    isPumpable: false
  },
  {
    input: "/(NL-?)?[0-9]{9}B[0-9]{2}/",
    isPumpable: false
  },
  {
    input:
      "/((0|1[0-9]{0,2}|2[0-9]?|2[0-4][0-9]|25[0-5]|[3-9][0-9]?)\\.){3}(0|1[0-9]{0,2}|2[0-9]?|2[0-4][0-9]|25[0-5]|[3-9][0-9]?)/",
    isPumpable: false
  },
  {
    input:
      "/(0[289][0-9]{2})|([1345689][0-9]{3})|(2[0-8][0-9]{2})|(290[0-9])|(291[0-4])|(7[0-4][0-9]{2})|(7[8-9][0-9]{2})/",
    isPumpable: false
  },
  {
    input: "/([ABCEGHJKLMNPRSTVXY][0-9][ABCEGHJKLMNPRSTVWXYZ])\\ ?([0-9][ABCEGHJKLMNPRSTVWXYZ][0-9])/",
    isPumpable: false
  },
  {
    input:
      "/((0[13-7]|1[1235789]|[257][0-9]|3[0-35-9]|4[0124-9]|6[013-79]|8[0124-9]|9[0-5789])[0-9]{3}|10([2-9][0-9]{2}|1([2-9][0-9]|11[5-9]))|14([01][0-9]{2}|715))/",
    isPumpable: false
  },
  {
    input: "/(([A-Z]{1,2}[0-9][0-9A-Z]?)\\ ([0-9][A-Z]{2}))|(GIR\\ 0AA)/",
    isPumpable: false
  },
  {
    input: "/((EE|EL|DE|PT)-?)?[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/((FI|HU|LU|MT|SI)-?)?[0-9]{8}/",
    isPumpable: false
  },
  {
    input: "/((PL|SK)-?)?[0-9]{10}/",
    isPumpable: false
  },
  {
    input: "/((IT|LV)-?)?[0-9]{11}/",
    isPumpable: false
  },
  {
    input: "/(SE-?)?[0-9]{12}/",
    isPumpable: false
  },
  {
    input: "/(BE-?)?0?[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/(CY-?)?[0-9]{8}[A-Z]/",
    isPumpable: false
  },
  {
    input: "/(CZ-?)?[0-9]{8,10}/",
    isPumpable: false
  },
  {
    input: "/(DK-?)?([0-9]{2}\\ ?){3}[0-9]{2}/",
    isPumpable: false
  },
  {
    input: "/(ES-?)?([0-9A-Z][0-9]{7}[A-Z])|([A-Z][0-9]{7}[0-9A-Z])/",
    isPumpable: false
  },
  {
    input: "/(FR-?)?[0-9A-Z]{2}\\ ?[0-9]{9}/",
    isPumpable: false
  },
  {
    input: "/(([A-Za-z0-9+\\/]{4})*([A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{2}==)?){1}/",
    isPumpable: false
  },
  {
    input: "/&#([0-9]{1,5}|x[0-9a-fA-F]{1,4});/",
    isPumpable: false
  },
  {
    input: "/((\\+?1)(\\ \\.-)?)?\\([2-9][0-9]{2}|\\([2-9][0-9]{2}\\))(\\ \\.-)?[0-9]{3}(\\ \\.-)?[0-9]{4}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|(Nov|Dec)(ember)?)/",
    isPumpable: false
  },
  {
    input: "/(Mo(n(day)?)?|Tu(e(sday)?)?|We(d(nesday)?)?|Th(u(rsday)?)?|Fr(i(day)?)?|Sa(t(urday)?)?|Su(n(day)?)?)/",
    isPumpable: false
  },
  {
    input: "/(?<group5>[0-9]{5})-?(?<group4>[0-9]{4})?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input:
      "/^(1|1(\\s|\\s?-\\s?|\\s?\\.\\s?|\\s?\\/\\s?))?((\\(?[2-9]{1}[\\d]{2}\\)?(\\s|\\s?-\\s?|\\s?\\.\\s?|\\s?\\/\\s?)?))?(\\d{3})(\\s|\\s?-\\s?|\\s?\\.\\s?|\\s?\\/\\s?)?(\\d{4})$/",
    isPumpable: false
  },
  {
    input:
      "/^[-\\w'+*$^&%=~!?{}#|\\/`]{1}([-\\w'+*$^&%=~!?{}#|`.]?[-\\w'+*$^&%=~!?{}#|`]{1}){0,31}[-\\w'+*$^&%=~!?{}#|`]?@(([a-zA-Z0-9]{1}([-a-zA-Z0-9]?[a-zA-Z0-9]{1}){0,31})\\.{1})+([a-zA-Z]{2}|[a-zA-Z]{3}|[a-zA-Z]{4}|[a-zA-Z]{6}){1}$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^@a.",
    pumpable: "0000.",
    suffix: ""
  },
  {
    input:
      "/<\\/?(a|abbr|acronym|address|applet|area|b|base|basefont|bdo|big|blockquote|body|br|button|caption|center|cite|code|col|colgroup|dd|del|dir|div|dfn|dl|dt|em|fieldset|font|form|frame|frameset|h[1-6]|head|hr|html|i|iframe|img|input|ins|isindex|kbd|label|legend|li|link|map|menu|meta|noframes|noscript|object|ol|optgroup|option|p|param|pre|q|s|samp|script|select|small|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|xmp)\\b((\\\"[^\\\"]*\\\"|\\'[^\\']*\\')*|[^\\\"\\'>])*>/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      '/<(/)?(a|abbr|acronym|address|applet|area|b|base|basefont|bdo|big|blockquote|body|br|button|caption|center|cite|code|col|colgroup|dd|del|dir|div|dfn|dl|dt|em|fieldset|font|form|frame|frameset|h[1-6]|head|hr|html|i|iframe|img|input|ins|isindex|kbd|label|legend|li|link|map|menu|meta|noframes|noscript|object|ol|optgroup|option|p|param|pre|q|s|samp|script|select|small|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|xmp){1}(\\s(\\"[^\\"]*\\"*|[^>])*)*>/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "<u",
    pumpable: '\\x09"',
    suffix: ""
  },
  {
    input: "/(\\+1|\\+|1)|([^0-9])/",
    isPumpable: false
  },
  {
    input: "/(?i:[aeiou]+)\\B/",
    isPumpable: false
  },
  {
    input: "/(^[0-9]{1,8}|(^[0-9]{1,8}\\.{0,1}[0-9]{1,2}))$/",
    isPumpable: false
  },
  {
    input: "/^((0[1-9])|(1[0-2]))$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]{0,1})([0-9]{1})(\\.[0-9])?$/",
    isPumpable: false
  },
  {
    input: "/[-+]((0[0-9]|1[0-3]):([03]0|45)|14:00)/",
    isPumpable: false
  },
  {
    input:
      "/\\b(?:AB|ALB|Alta|alberta|BC|CB|British Columbia|LB|Labrador|MB|Man|Manitoba|N[BLTSU]|Nfld|NF|Newfoundland|NWT|Northwest Territories|Nova Scotia|New Brunswick|Nunavut|ON|ONT|Ontario|PE|PEI|IPE|Prince Edward Island|QC|PC|QUE|QU|Quebec|SK|Sask|Saskatchewan|YT|Yukon|Yukon Territories)\\b/",
    isPumpable: false
  },
  {
    input: "/^[^#]([^ ]+ ){6}[^ ]+$/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?<Feet>\\d+)[ ]*(?:'|ft)){0,1}[ ]*(?<Inches>\\d*(?![\\/\\w])){0,1}(?:[ ,\\-]){0,1}(?<Fraction>(?<FracNum>\\d*)\\/(?<FracDem>\\d*)){0,1}(?<Decimal>\\.\\d*){0,1}(?:\\x22| in))|(?:(?<Feet>\\d+)[ ]*(?:'|ft)[ ]*){1}/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input: "/^((\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*)\\s*[,]{0,1}\\s*)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a-a@a.0",
    pumpable: "a@0.0.00.0-0A@0.0.00.0.0",
    suffix: "\\x00"
  },
  {
    input: "/(\\<!--\\s*.*?((--\\>)|$))/",
    isPumpable: false
  },
  {
    input: "/(\\<\\?php\\s+.*?((\\?\\>)|$))/",
    isPumpable: false
  },
  {
    input:
      "/[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+\\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:[A-Z]{2}|com|org|net|gov|biz|info|name|aero|biz|info|jobs|museum)\\b/",
    isPumpable: false
  },
  {
    input: "/^([1-9]|1[0-2]|0[1-9]){1}(:[0-5][0-9][aApP][mM]){1}$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9_\\s-]+$/",
    isPumpable: false
  },
  {
    input:
      "/^((([\\+][\\s]{0,1})|([0]{2}[\\s-]{0,1}))([358]{3})([\\s-]{0,1})|([0]{1}))(([1-9]{1}[0-9]{0,1})([\\s-]{0,1})([0-9]{2,4})([\\s-]{0,1})([0-9]{2,4})([\\s-]{0,1}))([0-9]{0,3}){1}$/",
    isPumpable: false
  },
  {
    input: "/^([1-9]|(0|1|2)[0-9]|30)(\\/|-)([1-9]|1[0-2]|0[1-9])(\\/|-)(14[0-9]{2})$/",
    isPumpable: false
  },
  {
    input: "/^[2-7]{1}[0-9]{3}$/",
    isPumpable: false
  },
  {
    input:
      "/^(-?\\$?([1-9]\\d{0,2}(,\\d{3})*|[1-9]\\d*|0|)(.\\d{1,2})?|\\(\\$?([1-9]\\d{0,2}(,\\d{3})*|[1-9]\\d*|0|)(.\\d{1,2})?\\))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^((?!000)(?!666)([0-6]\\d{2}|7[0-2][0-9]|73[0-3]|7[5-6][0-9]|77[0-1]))(\\s|\\-)((?!00)\\d{2})(\\s|\\-)((?!0000)\\d{4})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input:
      "/^(\\d)?[ ]*[\\(\\.\\-]?(\\d{3})[\\)\\.\\-]?[ ]*(\\d{3})[\\.\\- ]?(\\d{4})[ ]*(x|ext\\.?)?[ ]*(\\d{1,7})?$/",
    isPumpable: false
  },
  {
    input: "/^([0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\\w]*[0-9a-zA-Z]\\.)+[a-zA-Z]{2,9})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "00",
    suffix: ""
  },
  {
    input:
      "/^[a-zA-Z0-9ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝßàáâãäåæçèéêëìíîïñòóôõöøùúûüýÿ\\.\\,\\-\\/\\']+[a-zA-Z0-9ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝßàáâãäåæçèéêëìíîïñòóôõöøùúûüýÿ\\.\\,\\-\\/\\' ]+$/",
    wasParseError: "{ParsingData.NonAsciiInput(11, 195)}"
  },
  {
    input: "/^[A-Z0-9\\\\-\\\\&-]{5,12}$/",
    isPumpable: false
  },
  {
    input: "/^((\\+44\\s?\\d{4}|\\(?\\d{5}\\)?)\\s?\\d{6})|((\\+44\\s?|0)7\\d{3}\\s?\\d{6})$/",
    isPumpable: false
  },
  {
    input: "/^(net.tcp\\:\\/\\/|(ht|f)tp(s?)\\:\\/\\/)\\S+/",
    isPumpable: false
  },
  {
    input:
      "/^(?:(?:\\(|)0|\\+27|27)(?:1[12345678]|2[123478]|3[1234569]|4[\\d]|5[134678])(?:\\) | |-|)\\d{3}(?: |-|)\\d{4}$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/[^0-9]((\\(?(\\+420|00420)\\)?( |-)?)?([0-9]{3} ?(([0-9]{3} ?[0-9]{3})|([0-9]{2} ?[0-9]{2} ?[0-9]{2})))|([0-9]{3}-(([0-9]{3}-[0-9]{3})|([0-9]{2}-[0-9]{2}-[0-9]{2}))))[^0-9|\\/]/",
    isPumpable: false
  },
  {
    input: "/^(([1-9]{1}[0-9]{0,5}([.]{1}[0-9]{0,2})?)|(([0]{1}))([.]{1}[0-9]{0,2})?)$/",
    isPumpable: false
  },
  {
    input: "/^(([0-2]*[0-9]+[0-9]+)\\.([0-2]*[0-9]+[0-9]+)\\.([0-2]*[0-9]+[0-9]+)\\.([0-2]*[0-9]+[0-9]+))$/",
    isPumpable: false
  },
  {
    input: "/^(\\{|\\[|\\().+(\\}|\\]|\\)).+$/",
    isPumpable: false
  },
  {
    input: "/^\\s*-?(\\d*\\.)?([0-2])?[0-9]:([0-5])?[0-9]:([0-5])?[0-9](\\.[0-9]{1,7})?\\s*$/",
    isPumpable: false
  },
  {
    input: "/(([a-z']?[a-z' ]*)|([a-z][\\.])?([a-z][\\.]))/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{4} {0,1}[A-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/((\\d{0}[0-9]|\\d{0}[1]\\d{0}[0-2])(\\:)\\d{0}[0-5]\\d{0}[0-9](\\:)\\d{0}[0-5]\\d{0}[0-9]\\s(AM|PM))/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{2})?((\\([0-9]{2})\\)|[0-9]{2})?([0-9]{3}|[0-9]{4})(\\-)?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(((((((0?[13578])|(1[02]))[\\.\\-\\/]?((0?[1-9])|([12]\\d)|(3[01])))|(((0?[469])|(11))[\\.\\-\\/]?((0?[1-9])|([12]\\d)|(30)))|((0?2)[\\.\\-\\/]?((0?[1-9])|(1\\d)|(2[0-8]))))[\\.\\-\\/]?(((19)|(20))?([\\d][\\d]))))|((0?2)[\\.\\-\\/]?(29)[\\.\\-\\/]?(((19)|(20))?(([02468][048])|([13579][26])))))$/",
    isPumpable: false
  },
  {
    input:
      "/\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/",
    isPumpable: false
  },
  {
    input: "/^[-]?[0-9]*\\.?[0-9]?[0-9]?[0-9]?[0-9]?/",
    isPumpable: false
  },
  {
    input: "/[^(\\&)](\\w*)+(\\=)[\\w\\d ]*/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "!",
    pumpable: "0",
    suffix: ""
  },
  {
    input: "/\\/^(?:(?:1\\d?\\d|[1-9]?\\d|2[0-4]\\d|25[0-5])\\.){3}(?:1\\d?\\d|[1-9]?\\d|2[0-4]\\d|25[0-5])$\\//",
    isPumpable: false
  },
  {
    input: "/BV_SessionID=@@@@0106700396.1206001747@@@@&BV_EngineID=ccckadedjddehggcefecehidfhfdflg.0/",
    isPumpable: false
  },
  {
    input:
      "/^((\\d{2}(([02468][048])|([13579][26]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])))))|(\\d{2}(([02468][1235679])|([13579][01345789]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|(1[0-9])|(2[0-8]))))))(\\s(((0?[1-9])|(1[0-2]))\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])\\s))([AM|PM|am|pm]{2,2})))?$/",
    isPumpable: false
  },
  {
    input:
      "/^((((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|([1-2][0-9]))))[\\-\\/\\s]?\\d{2}(([02468][048])|([13579][26])))|(((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|(1[0-9])|(2[0-8]))))[\\-\\/\\s]?\\d{2}(([02468][1235679])|([13579][01345789]))))(\\s(((0?[1-9])|(1[0-2]))\\:([0-5][0-9])((\\s)|(\\:([0-5][0-9])\\s))([AM|PM|am|pm]{2,2})))?$/",
    isPumpable: false
  },
  {
    input:
      "/qr\\/(Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\\sHampshire|New\\sJersey|New\\sMexico|New\\sYork|North\\sCarolina|North\\sDakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\\sIsland|South\\sCarolina|South\\sDakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\\sVirginia|Wisconsin|Wyoming)\\//",
    isPumpable: false
  },
  {
    input:
      "/((ht|f)tp(s?))(:((\\/\\/)(?!\\/)))(((w){3}\\.)?)([a-zA-Z0-9\\-_]+(\\.(com|edu|gov|int|mil|net|org|biz|info|name|pro|museum|co\\.uk)))(\\/(?!\\/))(([a-zA-Z0-9\\-_\\/]*)?)([a-zA-Z0-9])+\\.((jpg|jpeg|gif|png)(?!(\\w|\\W)))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(23)}"
  },
  {
    input: "/^(\\d{4})[.](0{0,1}[1-9]|1[012])[.](0{0,1}[1-9]|[12][0-9]|3[01])[.](\\d{2})$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]\\d$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1}\\.){0,1}\\d{1,3}\\,\\d{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^([Aa][LKSZRAEPlkszraep]|[Cc][AOTaot]|[Dd][ECec]|[Ff][LMlm]|[Gg][AUau]|[Hh][Ii]|[Ii][ADLNadln]|[Kk][SYsy]|[Ll][Aa]|[Mm][ADEHINOPSTadehinopst]|[Nn][CDEHJMVYcdehjmvy]|[Oo][HKRhkr]|[Pp][ARWarw]|[Rr][Ii]|[Ss][CDcd]|[Tt][NXnx]|[Uu][Tt]|[Vv][AITait]|[Ww][AIVYaivy])$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}\\s?(\\d{2})?(-)?([A-Z]{1}|\\d{1})?([A-Z]{1}|\\d{1}))$/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{2}\\s?(\\d{2})?(-)?([A-Z]{1}|\\d{1})?([A-Z]{1}|\\d{1})?( )?(\\d{4}))$/",
    isPumpable: false
  },
  {
    input: "/(?!.*([abcde]).*\\1)^[abcde]{5}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: '/\\S*?[\\["].*?[\\]"]|\\S+/',
    isPumpable: false
  },
  {
    input: "/(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.)|(^127\\.0\\.0\\.1)/",
    isPumpable: false
  },
  {
    input:
      "/(((0[1-9]|[12][0-9]|3[01])([.])(0[13578]|10|12)([.])([1-2][0,9][0-9][0-9]))|(([0][1-9]|[12][0-9]|30)([.])(0[469]|11)([.])([1-2][0,9][0-9][0-9]))|((0[1-9]|1[0-9]|2[0-8])([.])(02)([.])([1-2][0,9][0-9][0-9]))|((29)(\\.|-|\\/)(02)([.])([02468][048]00))|((29)([.])(02)([.])([13579][26]00))|((29)([.])(02)([.])([0-9][0-9][0][48]))|((29)([.])(02)([.])([0-9][0-9][2468][048]))|((29)([.])(02)([.])([0-9][0-9][13579][26])))/",
    isPumpable: false
  },
  {
    input:
      "/^(http:\\/\\/)?(www\\.)?[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?<gTLD>\\.(biz|com|edu|gov|info|int|mil|name|net|org|aero|asia|cat|coop|jobs|mobi|museum|pro|tel|travel|arpa|root))?(?(gTLD)(\\.(a[c-gil-oq-uwxz]|b[abd-jmnorstvwyz]|c[acdf-ik-oruvxyz]|d[ejkmoz]|e[ceghrstu]|f[ijkmor]|g[abd-ilmnp-tuwy]|h[kmnrtu]|i[delmnoq-t]|j[emop]|k[eghimnprwyz]|l[abcikr-uvy]|m[acdeghk-z]|n[acefgilopruzc]|om|p[ae-hk-nrstwy]|qa|r[eosuw]|s[a-eg-ortuvyz]|t[cdfghj-prtvwz]|u[agksyz]|v[aceginu]|w[fs]|y[etu]|z[amw]))?|(\\.(a[c-gil-oq-uwxz]|b[abd-jmnorstvwyz]|c[acdf-ik-oruvxyz]|d[ejkmoz]|e[ceghrstu]|f[ijkmor]|g[abd-ilmnp-tuwy]|h[kmnrtu]|i[delmnoq-t]|j[emop]|k[eghimnprwyz]|l[abcikr-uvy]|m[acdeghk-z]|n[acefgilopruzc]|om|p[ae-hk-nrstwy]|qa|r[eosuw]|s[a-eg-ortuvyz]|t[cdfghj-prtvwz]|u[agksyz]|v[aceginu]|w[fs]|y[etu]|z[amw])))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(54, 60)}"
  },
  {
    input: "/(?:[0-9]{4}-){3}[0-9]{4})/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(((^\\s*)*\\S+\\s+)|(\\S+)){1,5}/",
    isPumpable: false
  },
  {
    input:
      '/(<div\\sclass="res(\\sindent)?">.*?)(<a\\s.*?href="(?<URL>.*?)".*?>)(?<Title>.*?</div>)((?<Abstract><div\\sclass="abstr">.*?</div>)(?<greenURL><span\\sclass=url>.*?</span>).*?</div>)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(50, 60)}"
  },
  {
    input: '/((?<=,\\s*\\")([^\\"]*|([^\\"]*\\"\\"[^""]*\\"\\"[^\\"]*)+)(?=\\"\\s*,))|((?<=,)[^,\\"]*(?=,))/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[1-9][0-9]{3}[ ]?(([a-rt-zA-RT-Z]{2})|([sS][^dasDAS]))$/",
    isPumpable: false
  },
  {
    input:
      "/http:\\/\\/\\([a-zA-Z0-9_\\-]\\+\\(\\.[a-zA-Z0-9_\\-]\\+\\)\\+\\)\\+:\\?[0-9]\\?\\(\\/*[a-zA-Z0-9_\\-#]*\\.*\\)*?\\?\\(&*[a-zA-Z0-9;_+\\/.\\-%]*-*=*[a-zA-Z0-9;_+\\/.\\-%]*-*\\)*/",
    isPumpable: false
  },
  {
    input: "/^\\d{10}$/",
    isPumpable: false
  },
  {
    input: "/^[\\u0600-\\u06ff\\s]+$|[\\u0750-\\u077f\\s]+$|[\\ufb50-\\ufc3f\\s]+$|[\\ufe70-\\ufefc\\s]+$|^$/",
    wasParseError: "{ParsingData.UnsupportedEscape(3, 117)}"
  },
  {
    input: "/^[5,6]\\d{7}|^$/",
    isPumpable: false
  },
  {
    input: "/[a-zà-ïò-öù-ü]+$/",
    wasParseError: "{ParsingData.NonAsciiInput(4, 195)}"
  },
  {
    input: "/\\d[\\d\\,\\.]+/",
    isPumpable: false
  },
  {
    input: "/^(\\+86)(13[0-9]|145|147|15[0-3,5-9]|18[0,2,5-9])(\\d{8})$/",
    isPumpable: false
  },
  {
    input: "/^(\\+)?([9]{1}[2]{1})?-? ?(\\()?([0]{1})?[1-9]{2,4}(\\))?-? ??(\\()?[1-9]{4,7}(\\))?$/",
    isPumpable: false
  },
  {
    input: "/^[ABCEGHJKLMNPRSTVXYabceghjklmnprstvxy]{1}\\d{1}[A-Za-z]{1}[ ]{0,1}\\d{1}[A-Za-z]{1}\\d{1}$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-1]([\\s-.\\/\\\\])?)?(\\(?[2-9]\\d{2}\\)?|[2-9]\\d{3})([\\s-./\\\\])?(\\d{3}([\\s-./\\\\])?\\d{4}|[a-zA-Z0-9]{7})$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-1]([\\s-.\\/\\\\])?)?(\\(?[2-9]\\d{2}\\)?|[2-9]\\d{3})([\\s-./\\\\])?([0-9]{3}([\\s-./\\\\])?[0-9]{4}|[a-zA-Z0-9]{7}|([0-9]{3}[-][a-zA-Z0-9]{4}))/",
    isPumpable: false
  },
  {
    input: "/^N[1-9][0-9]{0,4}$|^N[1-9][0-9]{0,3}[A-Z]$|^N[1-9][0-9]{0,2}[A-Z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^\\([0-9]{3}\\)[0-9]{3}(-)[0-9]{4}/",
    isPumpable: false
  },
  {
    input:
      "/((0[1-9])|(1[0-2]))\\/((0[1-9])|(1[0-9])|(2[0-9])|(3[0-1]))\\/\\(([1][9][0-9][0-9])|([2][0-9][0-9][0-9])))/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^\\d*\\.?(((5)|(0)|))?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^(\\-)?\\d*(\\.\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^(?<tipo>.{1,3})\\s+(?<endereco>.+),\\s+(?<numero>\\w{1,10})\\s*(?<complemento>.*)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      '/^(?<toplevel>[a-z]+)/(?<subtype>[a-z]+)(\\+(?<formattype>[a-z]+))?(; *?charset="?(?<charset>[a-z0-9\\-]+)"?)?$/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^[a-zA-Z]:\\\\(([\\w]|[\\u0621-\\u064A\\s])+\\\\)+([\\w]|[\\u0621-\\u064A\\s])+(.jpg|.JPG|.gif|.GIF|.BNG|.bng)$/",
    wasParseError: "{ParsingData.UnsupportedEscape(21, 117)}"
  },
  {
    input: "/^(eth[0-9]$)|(^eth[0-9]:[1-9]$)/",
    isPumpable: false
  },
  {
    input:
      "/\\b([\\d\\w\\.\\/\\+\\-\\?\\:]*)((ht|f)tp(s|)\\:\\/\\/|[\\d\\d\\d|\\d\\d]\\.[\\d\\d\\d|\\d\\d]\\.|www\\.|\\.tv|\\.ac|\\.com|\\.edu|\\.gov|\\.int|\\.mil|\\.net|\\.org|\\.biz|\\.info|\\.name|\\.pro|\\.museum|\\.co)([\\d\\w\\.\\/\\%\\+\\-\\=\\&\\?\\:\\\\\\\"\\'\\,\\|\\~\\;]*)\\b/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(?<value>([\\+-]?((\\d*\\.\\d+)|\\d+))(E[\\+-]?\\d+)?)( (?<prefix>[PTGMkmunpf])?(?<unit>[a-zA-Z]+)?)?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[a-z]+([a-z0-9-]*[a-z0-9]+)?(\\.([a-z]+([a-z0-9-]*[a-z0-9]+)?)+)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a",
    pumpable: ".aa0",
    suffix: "!"
  },
  {
    input:
      "/^\\$?(?(?=[0-9])[0-9]{1,5}:\\$?[0-9]{1,5}|[A-Za-z]{1,2}(?(?=:):\\$?[A-Za-z]{1,2}|(?(?!(\\$?[0-9])):\\/$[A-Za-z]{1,2}|\\$?[0-9]{1,5})(?(?=:):\\$?[A-Za-z]{1,2}\\$?[0-9]{1,5}|.)))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 40)}"
  },
  {
    input: "/^[\\w-]+(?:\\.[\\w-]+)*@(?:[\\w-]+\\.)+[a-zA-Z]{2,7}$/",
    isPumpable: false
  },
  {
    input: "/(?=^.{7,51}$)([A-Za-z]{1})([A-Za-z0-9!@#$%_\\^\\&\\*\\-\\.\\?]{5,49})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: '/^[^\\\\/:*?""<>|.][^\\\\/:*?""<>|]*(?<!\\.)(^[^\\\\/:*?""<>|]|$)|^$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(31)}"
  },
  {
    input: "/^(([0-9])|([0-2][0-9])|([3][0-1]))\\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\/\\d{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:((31\\/(Jan|Mar|May|Jul|Aug|Oct|Dec))|((([0-2]\\d)|30)\\/(Jan|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))|(([01]\\d|2[0-8])\\/Feb))|(29\\/Feb(?=\\/((1[6-9]|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00)))))\\/((1[6-9]|[2-9]\\d)\\d{2})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(137)}"
  },
  {
    input: "/(?<=(?:\\\\))[a-zA-Z0-9\\-\\s_]*(?=(?:\\.\\w*$))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/\\/#([1-9]){2}([1-9]){2}([1-9]){2}\\//",
    isPumpable: false
  },
  {
    input: '/((?:[^",]|(?:"(?:\\\\{2}|\\\\"|[^"])*?"))*)/',
    isPumpable: true,
    isVulnerable: true,
    prefix: '"',
    pumpable: "\\\\",
    suffix: ""
  },
  {
    input: "/&(?!amp;)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^[a-zA-Z]+(([\\'\\,\\.\\-][a-zA-Z])?[a-zA-Z]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "A",
    pumpable: "A",
    suffix: "!"
  },
  {
    input: "/^([\\+][0-9]{1,3}[\\.][0-9]{1,12})([x]?[0-9]{1,4}?)$/",
    isPumpable: false
  },
  {
    input:
      "/[du]{2}|[gu]{2}|[tu]{2}|[ds]{2}|[gs]{2}|[da]{2}|[ga]{2}|[ta]{2}|[dq]{2}|[gq]{2}|[tq]{2}|[DU]{2}|[GU]{2}|[TU]{2}|[DS]{2}|[GS]{2}|[DA]{2}|[GA]{2}|[TA]{2}|[DQ]{2}|[GQ]{2}|[TQ]{2}/",
    isPumpable: false
  },
  {
    input: "/$(\\n|\\r\\n)/",
    isPumpable: false
  },
  {
    input: "/\\.\\s|$(\\n|\\r\\n)/",
    isPumpable: false
  },
  {
    input:
      "/\\b(1(?!27\\.0\\.0\\.1)\\d{1,2}|2[0-4][0-9]|25[0-4]|\\d{1,2})\\.(?:\\d{1,3}\\.){2}(25[0-5]|2[0-4][0-9]|1\\d{2}|\\d{2}|[1-9])\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: '/[\\\\""=:;,](([\\w][\\w\\-\\.]*)\\.)?([\\w][\\w\\-]+)(\\.([\\w][\\w\\.]*))?\\\\sql\\d{1,3}[\\\\""=:;,]/',
    isPumpable: false
  },
  {
    input:
      '/[\\\\""=/>](25[0-4]|2[0-4][0-9]|1\\d{2}|\\d{2})\\.((25[0-4]|2[0-4][0-9]|1\\d{2}|\\d{1,2})\\.){2}(25[0-4]|2[0-4][0-9]|1\\d{2}|\\d{2}|[1-9])\\b[\\\\""=:;,/<]/',
    isPumpable: false
  },
  {
    input: "/^(([1-9]\\d{0,2}(\\,\\d{3})*|([1-9]\\d*))(\\.\\d{2})?)|([0]\\.(([0][1-9])|([1-9]\\d)))$/",
    isPumpable: false
  },
  {
    input: "/^([01]\\d|2[0123])([0-5]\\d){2}([0-99]\\d)$/",
    isPumpable: false
  },
  {
    input: "/^\\d{8,8}$|^[SC]{2,2}\\d{6,6}$/",
    isPumpable: false
  },
  {
    input: "/^\\w*[-]*\\w*\\\\\\w*$/",
    isPumpable: false
  },
  {
    input: "/^(([0-1]?[0-9])|([2][0-3])):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9]{1})|([0-1][0-9])|([1-2][0-3])):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^(([1-9]{1})|([0-1][1-2])|(0[1-9])|([1][0-2])):([0-5][0-9])(([aA])|([pP]))[mM]$/",
    isPumpable: false
  },
  {
    input: "/\\.txt$/",
    isPumpable: false
  },
  /*
  {
    input:
      "/^(?-i:A[DEFGILMNOQRSTUWZ]|B[ABDEFGHIJMNORSTVWYZ]|C[ACDFGHIKLMNORSUVXYZ]|D[EJKMOZ]|E[CEGHRST]|F[IJKMOR]|G[ABDEFHILMNPQRSTUWY]|H[KMNRTU]|I[DELNOQRST]|J[MOP]|K[EGHIMNPRWYZ]|L[ABCIKRSTUVY]|M[ACDGHKLMNOPQRSTUVWXYZ]|N[ACEFGILOPRUZ]|O[M]|P[AEFGHKLMNRSTWY]|QA|R[EOUW]|S[ABCDEGHIJKLMNORTVYZ]|T[CDFGHJKLMNORTVWZ]|U[AGMSYZ]|V[ACEGINU]|W[FS]|Y[ET]|Z[AMW])$/",
    isPumpable: false
  },*/
  {
    input: "/^-?\\d{1,3}\\.(\\d{3}\\.)*\\d{3},\\d\\d$|^-?\\d{1,3},\\d\\d$/",
    isPumpable: false
  },
  {
    input:
      "/^(([A-Za-z0-9\\!\\#\\$\\%\\&\\'\\*\\+\\-\\/\\=\\?\\^_\\`\\{\\|\\}\\~]+\\.*)*[A-Za-z0-9\\!\\#\\$\\%\\&\\'\\*\\+\\-\\/\\=\\?\\^_\\`\\{\\|\\}\\~]+@((\\w+\\-+)|(\\w+\\.))*\\w{1,63}\\.[a-zA-Z]{2,6})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "!!",
    suffix: ""
  },
  {
    input: "/^((Fred|Wilma)\\s+Flintstone|(Barney|Betty)\\s+Rubble)$/",
    isPumpable: false
  },
  {
    input: "/\\<script[^>]*>[\\w|\\t|\\r\\|\\W]*?<\\/script>/",
    isPumpable: false
  },
  {
    input: "/(^(((\\d)|(\\d\\d)|(\\d\\d\\d))(\\xA0|\\x20))*((\\d)|(\\d\\d)|(\\d\\d\\d))([,.]\\d*)?$)/",
    wasParseError: "{ParsingData.NonAsciiInput(26, 160)}"
  },
  {
    input:
      "/^((\\d(\\x20)\\d{2}(\\x20)\\d{2}(\\x20)\\d{2}(\\x20)\\d{3}(\\x20)\\d{3}((\\x20)\\d{2}|))|(\\d\\d{2}\\d{2}\\d{2}\\d{3}\\d{3}(\\d{2}|)))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[_a-z0-9-]+(\\.[_a-z0-9-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)+$/",
    isPumpable: false
  },
  {
    input: '/href\\s*=\\s*(?:(?:\\"(?<url>[^\\"]*)\\")|(?<url>[^\\s*] ))>(?<title>[^<]+)</\\w>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(21, 60)}"
  },
  {
    input: "/<(?<tag>.*).*>(?<text>.*)<\\/\\k<tag>>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/(^(?=.*\\S).*\\n)*/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/^(?<BRACE>\\{)?[a-fA-F\\d]{8}-(?:[a-fA-F\\d]{4}-){3}[a-fA-F\\d]{12}(?<-BRACE>\\})?(?(BRACE)^.)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^[2-9]{1}[0-9]{1}((?<!1)[1]|[0]|[2-9]){1}\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(18)}"
  },
  {
    input:
      "/^[1-4]\\d{3}\\/((0?[1-6]\\/((3[0-1])|([1-2][0-9])|(0?[1-9])))|((1[0-2]|(0?[7-9]))\\/(30|([1-2][0-9])|(0?[1-9]))))$/",
    isPumpable: false
  },
  {
    input: "/^((0[1-9]|1[0-9]|2[0-4])([0-5]\\d){2})$/",
    isPumpable: false
  },
  {
    input: "/^(\\+[1-9][0-9]*(\\([0-9]*\\)|-[0-9]*-))?[0]?[1-9][0-9\\- ]*$/",
    isPumpable: false
  },
  {
    input: "/[1-9][0-9]{3}[ ]?(([a-rt-zA-RT-Z][a-zA-Z])|([sS][bce-rt-xBCE-RT-X]))/",
    isPumpable: false
  },
  {
    input: "/(\\{\\\\f\\d*)\\\\([^;]+;)/",
    isPumpable: false
  },
  {
    input: "/\\d{1,3}.?\\d{0,3}\\s[a-zA-Z]{2,30}\\s[a-zA-Z]{2,15}/",
    isPumpable: false
  },
  {
    input: "/^\\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\\}$/",
    isPumpable: false
  },
  {
    input: "/^(0?[1-9]|1[0-2])(\\:)([0-5][0-9])(\\:)([0-5][0-9]) (AM|PM)$/",
    isPumpable: false
  },
  {
    input:
      "/^((0?[2])\\/(0?[1-9]|[1-2][0-9])|(0?[469]|11)\\/(0?[1-9]|[1-2][0-9]|30)|(0?[13578]|1[02])\\/(0?[1-9]|[1-2][0-9]|3[0-1]))\\/([1][9][0-9]{2}|[2-9][0-9]{3})$/",
    isPumpable: false
  },
  {
    input: "/^[2-9][0-8]\\d[2-9]\\d{6}$/",
    isPumpable: false
  },
  {
    input: "/^((\\d{5})|(\\d{5}-\\d{4})|([A-CEGHJ-NPR-TV-Z]\\d[A-CEGHJ-NPR-TV-Z]\\s\\d[A-CEGHJ-NPR-TV-Z]\\d))$/",
    isPumpable: false
  },
  {
    input:
      "/^((0?[2])\\/(0?[1-9]|[1-2][0-9])|(0?[469]|11)\\/(0?[1-9]|[1-2][0-9]|30)|(0?[13578]|1[02])\\/(0?[1-9]|[1-2][0-9]|3[0-1]))\\/([1][9][0-9]{2}|[2-9][0-9]{3}) (00|0?[1-9]|1[0-9]|2[0-3])\\:([0-5][0-9])\\:([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input: "/^(00|0?[1-9]|1[0-9]|2[0-3])\\:([0-5][0-9])\\:([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]|[a-z]|[0-9])([A-Z]|[a-z]|[0-9]|([A-Z]|[a-z]|[0-9]|(%|&|'|\\+|\\-|@|_|\\.|\\ )[^%&'\\+\\-@_\\.\\ ]|\\.$|([%&'\\+\\-@_\\.]\\ [^\\ ]|\\ [%&'\\+\\-@_\\.][^%&'\\+\\-@_\\.])))+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "Aa",
    pumpable: "0",
    suffix: "\\x00"
  },
  {
    input: "/^([1-9]|0[1-9]|1[0-2]):([0-5][0-9])$/",
    isPumpable: false
  },
  {
    input:
      "/^(?<prov>10)(?<tipo>(AV))?-(?<tomo>\\d{1,4})-(?<folio>\\d{1,5})|^(?<prov>[1-9])(?<tipo>(AV))?-(?<tomo>\\d{1,4})-(?<folio>\\d{1,5})|^(?<tipo>(E|N|PE))-(?<tomo>\\d{1,4})-(?<folio>\\d{1,5})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: "/^([a-zA-Z].*|[1-9].*)\\.(((j|J)(p|P)(g|G))|((g|G)(i|I)(f|F)))$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z][\\w\\.-]*[a-zA-Z0-9]@[a-zA-Z0-9][\\w\\.-]*[a-zA-Z0-9]\\.[a-zA-Z][a-zA-Z\\.]*[a-zA-Z]$/",
    isPumpable: false
  },
  {
    input: "/\\\\(?(\\\\d{4})\\\\)?[- ]?(\\\\d{5})[- ]?(\\\\d{6})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 40)}"
  },
  {
    input:
      "/\\b(((0[13578]|1[02])[\\/\\.-]?(0[1-9]|[12]\\d|3[01])[\\/\\.-]?(19|20)?(\\d{2}))|(0[13456789]|1[012])[\\/\\.-]?(0[1-9]|[12]\\d|30)[\\/\\.-]?(19|20)?(\\d{2}))|(02[\\/\\.-]?(0[1-9]|1\\d|2[0-8])[\\/\\.-]?(19|20)?(\\d{2}))|(02[\\/\\.-]?29[\\/\\.-]?(19|20)?((0[48]|[2468][048]|[13579][26])|(00)))\\b/",
    isPumpable: false
  },
  {
    input: "/(^\\d{1,3}$)|(\\d{1,3})\\.?(\\d{0,0}[0,5])/",
    isPumpable: false
  },
  {
    input: '/"([^\\\\"]|\\\\.)*"/',
    isPumpable: false
  },
  {
    input: "/(.|[\\r\\n]){1,5}/",
    isPumpable: false
  },
  {
    input: "/^(.|\\r|\\n){1,10}$/",
    isPumpable: false
  },
  {
    input: "/^(([a-zA-Z]:)|(\\\\{2}\\w+)\\$?)(\\\\(\\w[\\w].*))+(.pdf)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a:\\a0",
    pumpable: "\\pq\\pq",
    suffix: ""
  },
  {
    input: "/\\.(?i:)(?:jpg|gif)$/",
    isPumpable: false
  },
  {
    input: "/\\/[a-zA-Z]\\//",
    isPumpable: false
  },
  {
    input: "/([Cc][Hh][Aa][Nn][Dd][Aa][Nn].*?)/",
    isPumpable: false
  },
  {
    input: "/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/",
    isPumpable: false
  },
  {
    input: "/[0-9]*\\.?[0-9]*[1-9]/",
    isPumpable: false
  },
  {
    input: "/^\\d*[1-9]\\d*$/",
    isPumpable: false
  },
  {
    input: "/['`~!@#&$%^&*()-_=+{}|?><,.:;{}\\\"\\\\/\\\\[\\\\]]/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^(([+-]?)(?=\\d|\\.\\d)\\d*(\\.\\d*)?([Ee]([+-]?([12]?\\d\\d?|30[0-8])))?)?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(9)}"
  },
  {
    input: "/^(0)$|^([1-9][0-9]*)$/",
    isPumpable: false
  },
  {
    input: "/^[-|\\+]?[0-9]{1,3}(\\,[0-9]{3})*$|^[-|\\+]?[0-9]+$/",
    isPumpable: false
  },
  {
    input:
      "/^(((\\+?64\\s*[-\\.]?[3-9]|\\(?0[3-9]\\)?)\\s*[-\\.]?\\d{3}\\s*[-\\.]?\\d{4})|((\\+?64\\s*[-\\.\\(]?2\\d{1}[-\\.\\)]?|\\(?02\\d{1}\\)?)\\s*[-\\.]?\\d{3}\\s*[-\\.]?\\d{3,5})|((\\+?64\\s*[-\\.]?[-\\.\\(]?800[-\\.\\)]?|[-\\.\\(]?0800[-\\.\\)]?)\\s*[-\\.]?\\d{3}\\s*[-\\.]?(\\d{2}|\\d{5})))$/",
    isPumpable: false
  },
  {
    input: "/^\\s*(?<signedNumber>(\\+|\\-){0,1}((\\d*(\\.\\d+))|(\\d*)){1})(?<unit>((in)|(cm)|(mm)|(pt)){0,1})\\s*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/Password=(?<Password>.*);.*=(?<Info>.*);.*=(?<User>.*);.*=(?<Catalog>.*);.*=(?<Data>.*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(11, 60)}"
  },
  {
    input: "/(^(p[\\s|\\.|,]*|^post[\\s|\\.]*)(o[\\s|\\.|,]*|office[\\s|\\.]*))|(^box[.|\\s]*\\d+)/",
    isPumpable: false
  },
  {
    input:
      "/^[_a-zA-Z0-9-]+(\\.[_a-zA-Z0-9-]+)*@(?!co.uk)[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*\\.(([0-9]{1,3})|([a-zA-Z]{2,3})|(aero|coop|info|museum|name))$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(35)}"
  },
  {
    input:
      "/^(?:(?=[02468][048]00|[13579][26]00|[0-9][0-9]0[48]|[0-9][0-9][2468][048]|[0-9][0-9][13579][26])\\d{4}(?:(-|)(?:(?:00[1-9]|0[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-6])|(?:01|03|05|07|08|10|12)(?:\\1(?:0[1-9]|[12][0-9]|3[01]))?|(?:04|06|09|11)(?:\\1(?:0[1-9]|[12][0-9]|30))?|02(?:\\1(?:0[1-9]|[12][0-9]))?|W(?:0[1-9]|[1-4][0-9]|5[0-3])(?:\\1[1-7])?))?)$|^(?:(?![02468][048]00|[13579][26]00|[0-9][0-9]0[48]|[0-9][0-9][2468][048]|[0-9][0-9][13579][26])\\d{4}(?:(-|)(?:(?:00[1-9]|0[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-5])|(?:01|03|05|07|08|10|12)(?:\\2(?:0[1-9]|[12][0-9]|3[01]))?|(?:04|06|09|11)(?:\\2(?:0[1-9]|[12][0-9]|30))?|(?:02)(?:\\2(?:0[1-9]|1[0-9]|2[0-8]))?|W(?:0[1-9]|[1-4][0-9]|5[0-3])(?:\\2[1-7])?))?)$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input:
      "/^\\+(((i(?'id'.*?))|(m(?'modified'\\d+))|(?'retr'r)|(s(?'size'\\d+))|(?'cwd'\\/)|(up(?'up'\\d{3}))),)*\\t(?'name'.*?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(9, 39)}"
  },
  {
    input: "/^(\\+27|27)?(\\()?0?[87][23467](\\))?( |-|\\.|_)?(\\d{3})( |-|\\.|_)?(\\d{4})/",
    isPumpable: false
  },
  {
    input: "/^[a-z0-9][a-z0-9_\\.-]{0,}[a-z0-9]@[a-z0-9][a-z0-9_\\.-]{0,}[a-z0-9][\\.][a-z0-9]{2,4}$/",
    isPumpable: false
  },
  {
    input: "/((mailto\\:|(news|(ht|f)tp(s?))\\:\\/\\/){1}\\S+)/",
    isPumpable: false
  },
  {
    input: "/^((100)|(\\d{0,2}))$/",
    isPumpable: false
  },
  {
    input: "/<a\\s*.*?href\\s*=\\s*['\"](?!http:\\/\\/).*?>(.*?)<\\/a>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(23)}"
  },
  {
    input:
      "/(^0?[1-9]|^1[0-2])\\/(0?[1-9]|[1-2][0-9]|3[0-1])\\/(19|20)?[0-9][0-9](\\s(((0?[0-9]|1[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?)|((0?[0-9]|1[0-2]):[0-5][0-9](:[0-5][0-9])?\\s(AM|PM))))?$/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?<Feet>\\d+)[ ]*\\'){0,1}[ ]*(?<WholeInches>\\d*(?![\\/\\w])){0,1}(?:[ ,\\-]){0,1}(?<Fraction>\\d*\\/\\d*){0,1}(?<Decimal>\\.\\d*){0,1}\\\")|(?:(?<Feet>\\d+)[ ]*\\'[ ]*){1}/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input: "/^[a-zA-Z]+(\\.[a-zA-Z]+)+$/",
    isPumpable: false
  },
  {
    input: "/^((2[0-5][0-5]|1[\\d][\\d]|[\\d][\\d]|[\\d])\\.){3}(2[0-5][0-5]|1[\\d][\\d]|[\\d][\\d]|[\\d])$/",
    isPumpable: false
  },
  {
    input: "/^([\\w\\._-]){3,}\\@([\\w\\-_.]){3,}\\.(\\w){2,4}$/",
    isPumpable: false
  },
  {
    input: "/^\\<(\\w){1,}\\>(.){0,}([\\<\\/]|[\\<])(\\w){1,}\\>$/",
    isPumpable: false
  },
  {
    input: "/^(.)+\\.(jpg|jpeg|JPG|JPEG)$/",
    isPumpable: false
  },
  {
    input: "/^(\\w+=[^\\s,=]+,)*(\\w+=[^\\s,=]+,?)?$/",
    isPumpable: false
  },
  {
    input:
      "/(?:(?:(?<=[\\s^,(])\\*(?=\\S)(?!_)(?<bold>.+?)(?<!_)(?<=\\S)\\*(?=[\\s$,.?!]))|(?:(?<=[\\s^,(])_(?=\\S)(?!\\*)(?<underline>.+?)(?<!\\*)(?<=\\S)_(?=[\\s$,.?!]))|(?:(?<=[\\s^,(])(?:\\*_|_\\*)(?=\\S)(?<boldunderline>.+?)(?<=\\S)(?:\\*_|_\\*)(?=[\\s$,.?!])))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(33, 60)}"
  },
  {
    input: "/^[A-Z]{1}\\d{7}$/",
    isPumpable: false
  },
  {
    input:
      "/^\\d{1,6}\\040([A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,})$|^\\d{1,6}\\040([A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,})$|^\\d{1,6}\\040([A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,})$/",
    isPumpable: false
  },
  {
    input: "/\\(\\d{3}\\)\\040\\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\(714|760|949|619|909|951|818|310|323|213|323|562|626\\)\\040\\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input: "/714|760|949|619|909|951|818|310|323|213|323|562|626-\\d{3}-\\d{4}/",
    isPumpable: false
  },
  {
    input: "/\\d{6}/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,5}(\\.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/(?!^0*$)(?!^0*\\.0*$)^\\d{1,5}(\\.\\d{1,2})?$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/\\/(00356)?(99|79|77|21|27|22|25)[0-9]{6}\\/g/",
    wasParseError: "{ParsingData.UnsupportedGlobalModifier(40, 103)}"
  },
  {
    input: "/(?<=[\\?&])[^=&]+(?=[&]|$)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/[a-z0-9]+([-+._][a-z0-9]+){0,2}@.*?(\\.(a(?:[cdefgilmnoqrstuwxz]|ero|(?:rp|si)a)|b(?:[abdefghijmnorstvwyz]iz)|c(?:[acdfghiklmnoruvxyz]|at|o(?:m|op))|d[ejkmoz]|e(?:[ceghrstu]|du)|f[ijkmor]|g(?:[abdefghilmnpqrstuwy]|ov)|h[kmnrtu]|i(?:[delmnoqrst]|n(?:fo|t))|j(?:[emop]|obs)|k[eghimnprwyz]|l[abcikrstuvy]|m(?:[acdeghklmnopqrstuvwxyz]|il|obi|useum)|n(?:[acefgilopruz]|ame|et)|o(?:m|rg)|p(?:[aefghklmnrstwy]|ro)|qa|r[eosuw]|s[abcdeghijklmnortuvyz]|t(?:[cdfghjklmnoprtvwz]|(?:rav)?el)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])\\b){1,2}/",
    isPumpable: false
  },
  {
    input: "/^[0-9A-Za-z_ ]+(.[jJ][pP][gG]|.[gG][iI][fF])$/",
    isPumpable: false
  },
  {
    input: "/^\\$?\\d+(\\.(\\d{2}))?$/",
    isPumpable: false
  },
  {
    input: "/<script[\\s\\S]*?<\\/script([\\s\\S]*?)>/",
    isPumpable: false
  },
  {
    input: "/^(\\+|-)?(\\d\\.\\d{1,6}|[1-8]\\d\\.\\d{1,6}|90\\.0{1,6})$/",
    isPumpable: false
  },
  {
    input: "/^(\\+|-)?(\\d\\.\\d{1,6}|[1-9]\\d\\.\\d{1,6}|1[1-7]\\d\\.\\d{1,6}|180\\.0{1,6})$/",
    isPumpable: false
  },
  {
    input: "/((^(?<property>\\S+):)|(\\s(?<property>)))(?<value>.*)\\n/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(5, 60)}"
  },
  {
    input: "/^[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}$/",
    isPumpable: false
  },
  {
    input:
      "/(((http|https):\\/\\/)?(([a-zA-Z0-9]+\\.[a-zA-Z0-9\\-]+(\\.[a-zA-Z]+){1,2})|((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])))+(:[1-9][0-9]*)?)+((\\/([a-zA-Z0-9_\\-\\%\\~\\+]+)?)*)?(\\.([a-zA-Z0-9_]+))?(\\?([a-zA-Z0-9_\\-]+\\=[a-z-A-Z0-9_\\-\\%\\~\\+]+)?(\\&([a-zA-Z0-9_\\-]+\\=[a-z-A-Z0-9_\\-\\%\\~\\+]+)?)*)?/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      '/"{0,2}(?:(?:\\\\\\\\(?:\\w+)\\\\(?:\\w+\\$?)|(?:[A-Z]):)(?:\\\\(?:[^\\\\:*?"\'<>|\\r\\n]+))+|(?:[^\\\\:*?"\'<>|\\r\\n]+))\\.exe"?\\ (?<commandstring>(?:[^\\r\\n]*(?=")|[^\\r\\n]*))/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(111, 60)}"
  },
  {
    input:
      "/^v=spf1[ \\t]+[+?~-]?(?:(?:all)|(?:ip4(?:[:][0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})?(?:\\/[0-9]{1,2})?)|(?:ip6(?:[:]([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})?(?:\\/[0-9]{1,2})?)|(?:a(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)?(?:\\/[0-9]{1,2})?)|(?:mx(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)?(?:\\/[0-9]{1,2})?)|(?:ptr(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:exists(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:include(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:redirect(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:exp(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|)(?:(?:[ \\t]+[+?~-]?(?:(?:all)|(?:ip4(?:[:][0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})?(?:\\/[0-9]{1,2})?)|(?:ip6(?:[:]([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})?(?:\\/[0-9]{1,2})?)|(?:a(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)?(?:\\/[0-9]{1,2})?)|(?:mx(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+)?(?:\\/[0-9]{1,2})?)|(?:ptr(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:exists(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:include(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:redirect(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|(?:exp(?:[:][A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+))|))*)?$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(((\\+44)? ?(\\(0\\))? ?)|(0))( ?[0-9]{3,4}){3}/",
    isPumpable: false
  },
  {
    input:
      "/^public\\b\\s+?\\w+?\\s+?(?<propertyname>\\w+)[^{]+?{[\\s\\S]*?get\\s*?{[\\s\\S]*?}[\\s\\S]*?(?:set??[\\s\\S]*?{[\\s\\S]*?})?[\\s\\S]*?}$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(23, 60)}"
  },
  {
    input:
      '/<asp:requiredfieldvalidator(\\s*\\w+\\s*=\\s*\\"?\\s*\\w+\\s*\\"?\\s*)+\\s*>\\s*<\\/asp:requiredfieldvalidator>/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "<asp:requiredfieldvalidatora =0",
    pumpable: " a=\\x090",
    suffix: ""
  },
  {
    input:
      "/\\b((([\"'/,&%\\:\\(\\)\\$\\+\\-\\*\\w\\000-\\032])|(-*\\d+\\.\\d+[%]*))+[\\s]+)+\\b[\\w\"',%\\(\\)]+[.!?](['\"\\s]|$)/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: "/^([\\(]{1}[0-9]{3}[\\)]{1}[ |\\-]{0,1}|^[0-9]{3}[\\-| ])?[0-9]{3}(\\-| ){1}[0-9]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(((0?[1-9]|1\\d|2[0-8])|(0?[13456789]|1[012])\\/(29|30)|(0?[13578]|1[02])\\/31)\\/(0?[1-9]|1[012])\\/(19|[2-9]\\d)\\d{2}|0?29\\/0?2\\/((19|[2-9]\\d)(0[48]|[2468][048]|[13579][26])|(([2468][048]|[3579][26])00)))$/",
    isPumpable: false
  },
  {
    input:
      "/^([1-9]{1}[\\d]{0,2}(\\,[\\d]{3})*(\\.[\\d]{0,2})?|[1-9]{1}[\\d]{0,}(\\.[\\d]{0,2})?|0(\\.[\\d]{0,2})?|(\\.[\\d]{1,2})?)$/",
    isPumpable: false
  },
  {
    input: "/^([1-9][0-9]?|100)%$/",
    isPumpable: false
  },
  {
    input: "/^([\\(]{1}[0-9]{3}[\\)]{1}[\\.| |\\-]{0,1}|^[0-9]{3}[\\.|\\-| ]?)?[0-9]{3}(\\.|\\-| )?[0-9]{4}$/",
    isPumpable: false
  },
  {
    input: "/^(0?[1-9]|1[012])$/",
    isPumpable: false
  },
  {
    input: "/^([12]?[0-9]|3[01])$/",
    isPumpable: false
  },
  {
    input: "/^((18[5-9][0-9])|((19|20)[0-9]{2})|(2100))$/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*(?<sign>[+-]?)(?:0*?)(?<abs_value>(?:(?:[1-9]\\d*)|0)?(?:(?<=\\d)\\.|\\.(?=\\d))(?:(?:(?:\\d*[1-9])|0)?)?|(?:(?:[1-9]\\d*)|0)?)(?:0*)\\s*$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/(\\w+?@\\w+?\\x2E.+)/",
    isPumpable: false
  },
  {
    input: "/Last.*?(\\d+.?\\d*)/",
    isPumpable: false
  },
  {
    input: "/^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\\s).{4,8}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^(GIR ?0AA|(?:[A-PR-UWYZ](?:\\d|\\d{2}|[A-HK-Y]\\d|[A-HK-Y]\\d\\d|\\d[A-HJKSTUW]|[A-HK-Y]\\d[ABEHMNPRV-Y])) ?\\d[ABD-HJLNP-UW-Z]{2})$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{2})(00[1-9]|0[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-6])$/",
    isPumpable: false
  },
  {
    input: "/^([0-1]?\\d|2[0-3])([:]?[0-5]\\d)?([:]?|[0-5]\\d)?\\s?(A|AM|P|p|a|PM|am|pm|pM|aM|Am|Pm)?$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\d{5}((|-)-\\d{4})?)|([A-Za-z]\\d[A-Za-z][\\s\\.\\-]?(|-)\\d[A-Za-z]\\d)|[A-Za-z]{1,2}\\d{1,2}[A-Za-z]? \\d[A-Za-z]{2}$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^0?[0-9]?[0-9]$|^(100)$/",
    isPumpable: false
  },
  {
    input:
      "/^((unit|u|)\\s*)?(?<unit>\\d*\\w?)?(\\s+|\\/)?(?<streetNo>\\d+(\\-\\d+)?)\\s+(?<streetName>\\w+)\\s+(?<streetType>\\w+)\\s+(?<suburb>\\w+(\\s+\\w+)?)\\s+(?<state>\\w+)\\s+(?<postcode>\\d{4})$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^\\d{1,3}((\\.\\d{1,3}){3}|(\\.\\d{1,3}){5})$/",
    isPumpable: false
  },
  {
    input: "/^\\d{4}(\\/|-)([0][1-9]|[1][0-2])(\\/|-)([0][1-9]|[1-2][0-9]|[3][0-1])$/",
    isPumpable: false
  },
  {
    input: "/^([2-9])(\\d{2})(-?|\\040?)(\\d{4})( ?|\\040?)(\\d{1,4}?|\\040?)$/",
    isPumpable: false
  },
  {
    input: "/^([8-9])([1-9])(\\d{2})(-?|\\040?)(\\d{4})$/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Za-z]{6}[0-9lmnpqrstuvLMNPQRSTUV]{2}[abcdehlmprstABCDEHLMPRST]{1}[0-9lmnpqrstuvLMNPQRSTUV]{2}[A-Za-z]{1}[0-9lmnpqrstuvLMNPQRSTUV]{3}[A-Za-z]{1})|([0-9]{11})$/",
    isPumpable: false
  },
  {
    input:
      "/^[0-9a-zA-Z]+([0-9a-zA-Z]*[-._+])*[0-9a-zA-Z]+@[0-9a-zA-Z]+([-.][0-9a-zA-Z]+)*([0-9a-zA-Z]*[.])[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input: "/^[A-z]?\\d{8}[A-z]$/",
    isPumpable: false
  },
  {
    input: '/(?<cmd>^"[^"]*"|\\S*) *(?<prm>.*)?/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(?<Year>(?:\\d{4}|\\d{2}))-(?<Month>\\d{1,2})-(?<Day>\\d{1,2})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/\\b[A-Z-[DFIOQUWZ]]\\d[A-Z-[DFIOQU]]\\ +\\d[A-Z-[DFIOQU]]\\d\\b/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^[-+]?([0-9]{1,3}[,]?)?([0-9]{3}[,]?)*[.]?[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{5}([- \\/]?[0-9]{4})?$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1,2})(\\s?(H|h)?)(:([0-5]\\d))?$/",
    isPumpable: false
  },
  {
    input:
      "/([A-Z]|[a-z])|\\/|\\?|\\-|\\+|\\=|\\&|\\%|\\$|\\#|\\@|\\!|\\||\\\\|\\}|\\]|\\[|\\{|\\;|\\:|\\'|\\\"|\\,|\\.|\\>|\\<|\\*|([0-9])|\\(|\\)|\\s/",
    isPumpable: false
  },
  {
    input: "/(\\<(.*?)\\>)(.*?)(\\<\\/(.*?)\\>)/",
    isPumpable: false
  },
  {
    input:
      "/\\b ?(a|A)ppoint(s|ing|ment(s)?|ed)?| ?(J|j)oin(s|ed|ing)| ?(R)?recruit(s|ed|ing(s)?)?| (H|h)(is|er)(on)? dut(y|ies)?| ?(R)?replace(s|d|ment)?| (H)?hire(s|d)?| ?(P|p)romot(ed|es|e|ing)?| ?(D|d)esignate(s|d)| (N)?names(d)?| (his|her)? (P|p)osition(ed|s)?| re(-)?join(ed|s)|(M|m)anagement Changes|(E|e)xecutive (C|c)hanges| reassumes position| has appointed| appointment of| was promoted to| has announced changes to| will be headed| will succeed| has succeeded| to name| has named| was promoted to| has hired| bec(a|o)me(s)?| (to|will) become| reassumes position| has been elevated| assumes the additional (role|responsibilit(ies|y))| has been elected| transferred| has been given the additional| in a short while| stepp(ed|ing) down| left the company| (has)? moved| (has)? retired| (has|he|she)? resign(s|ing|ed)| (D|d)eceased| ?(T|t)erminat(ed|s|ing)| ?(F|f)ire(s|d|ing)| left abruptly| stopped working| indict(ed|s)| in a short while| (has)? notified| will leave| left the| agreed to leave| (has been|has)? elected| resignation(s)?/",
    isPumpable: false
  },
  {
    input: "/\\b([A-Za-z0-9]+)(-|_|\\.)?(\\w+)?@\\w+\\.(\\w+)?(\\.)?(\\w+)?(\\.)?(\\w+)?\\b/",
    isPumpable: false
  },
  {
    input: "/\\b([A-Za-z0-9]+)( )([A-Za-z0-9]+)\\b/",
    isPumpable: false
  },
  {
    input: "/\\b([A-Za-z]+) +\\1\\b/",
    isPumpable: false
  },
  {
    input: "/\\b([0-9]+) +\\1\\b/",
    isPumpable: false
  },
  {
    input: "/\\b([A-Za-z0-9]+) +\\1\\b/",
    isPumpable: false
  },
  {
    input: "/\\b([A-Za-z0-9]+) +\\1\\b   replacement string--->$1/",
    isPumpable: false
  },
  {
    input: "/(\\n\\r)   replacement string---->\\n/",
    isPumpable: false
  },
  {
    input: "/^[ \\t]+|[ \\t]+$/",
    isPumpable: false
  },
  {
    input:
      "/^([\\.\\\"\\'-\\/ \\(\\/)\\s\\[\\]\\\\\\,\\<\\>\\;\\:\\{\\}]?)([0-9]{3})([\\.\\\"\\'-\\/\\(\\/)\\s\\[\\]\\\\\\,\\<\\>\\;\\:\\{\\}]?)([0-9]{3})([\\,\\.\\\"\\'-\\/\\(\\/)\\s\\[\\]\\\\\\<\\>\\;\\:\\{\\}]?)([0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/^[^a-zA-Z0-9]+$/",
    isPumpable: false
  },
  {
    input: "/^(http(s)?\\:\\/\\/\\S+)\\s/",
    isPumpable: false
  },
  {
    input:
      "/[\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0A\\x0B\\x0C\\x0D\\x0E\\x0F\\x1C\\x1D\\x1E\\x1F\\x60\\x80\\x8A\\x8C\\x8E\\x9A\\x9C\\x9E\\x9F\\xA7\\xAE\\xB1\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7\\xC8\\xC9\\xCA\\xCB\\xCC\\xCD\\xCE\\xCF\\xD0\\xD1\\xD2\\xD3\\xD4\\xD5\\xD6\\xD8\\xD9\\xDA\\xDB\\xDC\\xDD\\xDE\\xDF\\xE0\\xE1\\xE2\\xE3\\xE4\\xE5\\xE6\\xE7\\xE8\\xE9\\xEA\\xEB\\xEC\\xED\\xEE\\xEF\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5\\xF6\\xF8\\xF9\\xFA\\xFB\\xFC\\xFD\\xFE\\xFF\\u0060\\u00A2\\u00A3\\u00A4\\u00A5\\u00A6\\u00A7\\u00A8\\u00A9\\u00AA\\u00AB\\u00AC\\u00AE\\u00AF\\u00B0\\u00B1\\u00B2\\u00B3\\u00B4\\u00B5\\u00B7\\u00B9\\u00BA\\u00BB\\u00BC\\u00BD\\u00BE\\u00BF\\u00C0\\u00C1\\u00C2\\u00C3\\u00C4\\u00C5\\u00C6\\u00C7\\u00C8\\u00C9\\u00CA\\u00CB\\u00CC\\u00CD\\u00CE\\u00CF\\u00D0\\u00D1\\u00D2\\u00D3\\u00D4\\u00D5\\u00D6\\u00D8\\u00D9\\u00DA\\u00DB\\u00DC\\u00DD\\u00DE\\u00DF\\u00E0\\u00E1\\u00E2\\u00E3\\u00E4\\u00E5\\u00E6\\u00E7\\u00E8\\u00E9\\u00EA\\u00EB\\u00EC\\u00ED\\u00EE\\u00EF\\u00F0\\u00F1\\u00F2\\u00F3\\u00F4\\u00F5\\u00F6\\u00F8\\u00F9\\u00FA\\u00FB\\u00FC\\u00FD\\u00FE\\u00FF\\u0100\\u0101\\u0102\\u0103\\u0104\\u0105\\u0106\\u0107\\u0108\\u0109\\u010A\\u010B\\u010C\\u010D\\u010E\\u010F\\u0110\\u0111\\u0112\\u0113\\u0114\\u0115\\u0116\\u0117\\u0118\\u0119\\u011A\\u011B\\u011C\\u011D\\u011E\\u011F\\u0120\\u0121\\u0122\\u0123\\u0124\\u0125\\u0126\\u0127\\u0128\\u0129\\u012A\\u012B\\u012C\\u012D\\u012E\\u012F\\u0130\\u0131\\u0132\\u0133\\u0134\\u0135\\u0136\\u0137\\u0138\\u0139\\u013A\\u013B\\u013C\\u013D\\u013E\\u013F\\u0140\\u0141\\u0142\\u0143\\u0144\\u0145\\u0146\\u0147\\u0148\\u0149\\u014A\\u014B\\u014C\\u014D\\u014E\\u014F\\u0150\\u0151\\u0152\\u0153\\u0154\\u0155\\u0156\\u0157\\u0158\\u0159\\u015A\\u015B\\u015C\\u015D\\u015E\\u015F\\u0160\\u0161\\u0162\\u0163\\u0164\\u0165\\u0166\\u0167\\u0168\\u0169\\u016A\\u016B\\u016C\\u016D\\u016E\\u016F\\u0170\\u0171\\u0172\\u0173\\u0174\\u0175\\u0176\\u0177\\u0178\\u0179\\u017A\\u017B\\u017C\\u017D\\u017E\\u017F\\u0180\\u0181\\u0182\\u0183\\u0184\\u0185\\u0186\\u0187\\u0188\\u0189\\u018A\\u018B\\u018C\\u018D\\u018E\\u018F\\u0190\\u0191\\u0192\\u0193\\u0194\\u0195\\u0196\\u0197\\u0198\\u0199\\u019A\\u019B\\u019C\\u019D\\u019E\\u019F\\u01A0\\u01A1\\u01A2\\u01A3\\u01A4\\u01A5\\u01A6\\u01A7\\u01A8\\u01A9\\u01AA\\u01AB\\u01AC\\u01AD\\u01AE\\u01AF\\u01B0\\u01B1\\u01B2\\u01B3\\u01B4\\u01B5\\u01B6\\u01B7\\u01B8\\u01B9\\u01BA\\u01BB\\u01BC\\u01BD\\u01BE\\u01BF\\u01C0\\u01C1\\u01C2\\u01C4\\u01C5\\u01C6\\u01C7\\u01C8\\u01C9\\u01CA\\u01CB\\u01CC\\u01CD\\u01CE\\u01CF\\u01D0\\u01D2\\u01D3\\u01D4\\u01D5\\u01D6\\u01D7\\u01D8\\u01D9\\u01DA\\u01DB\\u01DC\\u01DD\\u01DE\\u01DF\\u01E0\\u01E1\\u01E2\\u01E3\\u01E4\\u01E5\\u01E6\\u01E7\\u01E8\\u01E9\\u01EA\\u01EB\\u01EC\\u01ED\\u01EE\\u01EF\\u01F0\\u01F1\\u01F2\\u01F3\\u01F4\\u01F5\\u01FA\\u01FB\\u01FC\\u01FD\\u01FE\\u01FF\\u0200\\u0201\\u0202\\u0203\\u0204\\u0205\\u0206\\u0207\\u0208\\u0209\\u020A\\u020B\\u020C\\u020D\\u020E\\u020F\\u0210\\u0211\\u0212\\u0213\\u0214\\u0215\\u0216\\u0217\\u021E\\u0250\\u0252\\u0259\\u025A\\u025B\\u025C\\u025D\\u025E\\u025F\\u0260\\u0263\\u0264\\u0265\\u0266\\u0267\\u0268\\u0269\\u026B\\u026C\\u026D\\u026E\\u026F\\u0270\\u0271\\u0272\\u0273\\u0276\\u0277\\u0278\\u0279\\u027A\\u027B\\u027C\\u027D\\u027E\\u027F\\u0281\\u0282\\u0283\\u0284\\u0285\\u0286\\u0287\\u0288\\u0289\\u028A\\u028B\\u028C\\u028D\\u028E\\u028F\\u0290\\u0291\\u0292\\u0293\\u0294\\u0295\\u0296\\u0297\\u0298\\u0299\\u029A\\u029B\\u029C\\u029D\\u029E\\u02A0\\u02A1\\u02A2\\u02A3\\u02A4\\u02A5\\u02A6\\u02A7\\u02A8\\u033D\\u033E\\u0342\\u0343\\u0344\\u0345\\u0386\\u0388\\u0389\\u038A\\u038C\\u038E\\u038F\\u0390\\u0393\\u0394\\u0398\\u039E\\u039F\\u03A0\\u03A3\\u03A6\\u03A8\\u03A9\\u03AA\\u03AB\\u03AC\\u03AD\\u03AE\\u03AF\\u03B0\\u03B1\\u03B2\\u03B3\\u03B4\\u03B5\\u03B6\\u03B7\\u03B8\\u03B9\\u03BA\\u03BB\\u03BC\\u03BE\\u03BF\\u03C0\\u03C1\\u03C2\\u03C3\\u03C4\\u03C5\\u03C6\\u03C7\\u03C8\\u03C9\\u03CA\\u03CB\\u03CC\\u03CD\\u03CE\\u03D0\\u03D1\\u03D2\\u03D3\\u03D4\\u03D5\\u03D6\\u03E0\\u03E2\\u03E3\\u03E4\\u03E5\\u03E6\\u03E7\\u03EE\\u03EF\\u03F0\\u03F1\\u0403\\u0404\\u0407\\u0409\\u040A\\u040B\\u040C\\u040E\\u040F\\u0411\\u0414\\u0416\\u0418\\u0419\\u041A\\u041B\\u041C\\u041D\\u041E\\u041F\\u0424\\u0427\\u0428\\u0429\\u042A\\u042B\\u042C\\u042D\\u042E\\u042F\\u0431\\u0432\\u0433\\u0434\\u0435\\u0436\\u0437\\u0438\\u0439\\u043A\\u043B\\u043F\\u0444\\u0448\\u0449\\u044A\\u044B\\u044C\\u044D\\u044E\\u044F\\u0451\\u0452\\u0453\\u0454\\u0457\\u0459\\u045A\\u045B\\u045C\\u045E\\u045F\\u0460\\u0461\\u0462\\u0463\\u0464\\u0465\\u0466\\u0467\\u0468\\u0469\\u046A\\u046B\\u046C\\u046D\\u046E\\u046F\\u0470\\u0471\\u0472\\u0473\\u0476\\u0477\\u0478\\u047/",
    wasParseError: "{ParsingData.NonAsciiInput(85, 128)}"
  },
  {
    input: "/<(.|\\n)*?>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<",
    pumpable: "\\x0a",
    suffix: ""
  },
  {
    input: "/\\b([A-Za-z]+) +(\\1\\b)/",
    isPumpable: false
  },
  {
    input: "/[^a-zA-Z0-9]+/",
    isPumpable: false
  },
  {
    input:
      "/^(http|https|ftp)\\:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(:[a-zA-Z0-9]*)?\\/?([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~])*[^\\.\\,\\)\\(\\s]$/",
    isPumpable: false
  },
  {
    input: "/\\b[A-Za-z]{2}(?=([0-9]*[1-9]){1,})\\d{1,5}\\b/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(13)}"
  },
  {
    input: "/\\/\\*[\\d\\D]*?\\*\\//",
    isPumpable: false
  },
  {
    input: "/^#?([a-f]|[A-F]|[0-9]){3}(([a-f]|[A-F]|[0-9]){3})?$/",
    isPumpable: false
  },
  {
    input: "/(AUX|PRN|NUL|COM\\d|LPT\\d)+\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^(([^\\.\\-\\,a-wy-z]([\\(]?(\\+|[x])?\\d+[\\)]?)?[\\s\\.\\-\\,]?([\\(]?\\d+[\\)]?)?[\\s\\.\\-\\,]?(\\d+[\\s\\.\\-\\,]?)+[^\\.\\-\\,a-z])|((\\+|[x])?\\d+))$\\/i/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "x0",
    pumpable: "00",
    suffix: ","
  },
  {
    input: "/^(3(([0-5][0-9]{0,2})|60))|([1-2][0-9]{2})|(^[1-9]$)|(^[1-9]{2}$)$/",
    isPumpable: false
  },
  {
    input: "/^[\\.\\wæøå-]+@([a-zæøå0-9]+([\\.-]{0,1}[a-zæøå0-9]+|[a-zæøå0-9]?))+\\.[a-z]{2,6}$/",
    wasParseError: "{ParsingData.NonAsciiInput(6, 195)}"
  },
  {
    input: "/(\\[[Ii][Mm][Gg]\\])(\\S+?)(\\[\\/[Ii][Mm][Gg]\\])/",
    isPumpable: false
  },
  {
    input: "/^((192\\.168\\.0\\.)(1[7-9]|2[0-9]|3[0-2]))$/",
    isPumpable: false
  },
  {
    input: "/(\\S*)+(\\u007C)+(\\S*)/",
    wasParseError: "{ParsingData.UnsupportedEscape(8, 117)}"
  },
  {
    input: "/^(\\d{3}-\\d{2}-\\d{4})|(\\d{3}\\d{2}\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{4})-((0[1-9])|(1[0-2]))-(0[1-9]|[12][0-9]|3[01])$/",
    isPumpable: false
  },
  {
    input:
      "/^[0-3]{1}[0-9]{1}[ ]{1}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec){1}[ ]{1}[0-9]{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^((29-02-(19|20)(([02468][048])|([13579][26])))|(31-((0[13578])|(1[02]))|(30-((0[13456789])|(1[0-2])))|(29-((0[13456789])|(1[0-2])))|(((0[1-9]|)|(1[0-9])|(2[0-8]))-((0[1-9])|(1[0-2])))-((19|20)[0-9][0-9])))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/(?<=<embed\\s[^<>]*?src\\s*?=\\s*?\\x22)[^<>]*?(?=\\x22[^<>]*?>)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(?<=<param(?=[^<>]*?name\\s*=\\s*\\x22movie\\x22)[^<>]*?value\\s*=\\s*\\x22)[^<>]*?(?=\\x22[^<>]*?>)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/\\A((?:[01]{0,1}\\d)|(?:[2][0123])):([012345]\\d):([012345]\\d)(.\\d{1,3})?([Z]|(?:[+-]?(?:[01]{0,1}\\d)|(?:[2][0123])):([012345]\\d))\\Z/",
    isPumpable: false
  },
  {
    input: "/\\A-?(\\d{4,})-(\\d{2})-(\\d{2})([Z]|(?:[+-]?(?:[01]\\d)|(?:[2][0123])):(?:[012345]\\d))\\Z/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\_\\-]+[a-zA-Z0-9\\.\\_\\-]*@([a-zA-Z0-9\\_\\-]+\\.)+([a-zA-Z]{2,4}|travel|museum)$/",
    isPumpable: false
  },
  {
    input: "/%[\\-\\+0\\s\\#]{0,1}(\\d+){0,1}(\\.\\d+){0,1}[hlI]{0,1}[cCdiouxXeEfgGnpsS]{1}/",
    isPumpable: false
  },
  {
    input: "/\\b[1-9]\\d{3}\\ +[A-Z]{2}\\b/",
    isPumpable: false
  },
  {
    input: "/(?<Day>[0-3][0-9]|[1-9])\\/(?<Month>[1-9]|1[0-2]|0[1-9])\\/(?<Year>[12]\\d{3}|\\d{2})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/(?<Day>[1-9]|[0-3][0-9])\\/(?<Month>[01][012]|[1-9]|0[1-9])\\/(?<Year>[12]\\d{3}|\\d{2})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^(([+]|00)39)?((3[1-6][0-9]))(\\d{7})$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9][\\w-]*@[a-zA-Z0-9][\\w-\\.]*\\.[a-zA-Z0-9][\\w-]*$/",
    isPumpable: false
  },
  {
    input: "/^-?([1-8]?[0-9]\\.{1}\\d{1,6}$|90\\.{1}0{1,6}$)/",
    isPumpable: false
  },
  {
    input: "/^-?((([1]?[0-7][0-9]|[1-9]?[0-9])\\.{1}\\d{1,6}$)|[1]?[1-8][0]\\.{1}0{1,6}$)/",
    isPumpable: false
  },
  {
    input: "/^[A-Z]+[A-Z0-9,\\x5F]*$/",
    isPumpable: false
  },
  {
    input: "/^(?!0,?\\d)([0-9]{2}[0-9]{0,}(\\.[0-9]{2}))$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/@([_a-zA-Z]+)/",
    isPumpable: false
  },
  {
    input:
      "/^(http\\:\\/\\/){1}(((www\\.){1}([a-zA-Z0-9\\-]*\\.){1,}){1}|([a-zA-Z0-9\\-]*\\.){1,10}){1}([a-zA-Z]{2,6}\\.){1}([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&%\\$#\\=~])*/",
    isPumpable: false
  },
  {
    input:
      "/((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)\\:\\/\\/([a-zA-Z0-9\\.\\-]+(\\:[a-zA-Z0-9\\.&%\\$\\-]+)*@){0,1}((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]+\\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(:[0-9]{2,5}[^:]){0,1}(\\/(\\s+|$|[a-zA-Z0-9\\.\\,\\?\\'\\\\\\+&%\\$#\\=~_\\-]+)){0,1})/",
    isPumpable: false
  },
  {
    input: "/^([\\w]+@([\\w]+\\.)+[a-zA-Z]{2,9}(\\s*;\\s*[\\w]+@([\\w]+\\.)+[a-zA-Z]{2,9})*)$/",
    isPumpable: false
  },
  {
    input: "/\\w{5,255}/",
    isPumpable: false
  },
  {
    input: "/((0[1-9])|(1[0-2]))\\/(([0-9])|([0-2][0-9])|(3[0-1]))\\/\\d{2}/",
    isPumpable: false
  },
  {
    input: "/\\$?GP[a-z]{3,},([a-z0-9\\.]*,)+([a-z0-9]{1,2}\\*[a-z0-9]{1,2})/",
    isPumpable: false
  },
  {
    input:
      "/^(http(s?):\\/\\/)(www.)?(\\w|-)+(\\.(\\w|-)+)*((\\.[a-zA-Z]{2,3})|\\.(aero|coop|info|museum|name))+(\\/)?$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9][a-zA-Z0-9-_.]{2,8}[a-zA-Z0-9]$/",
    isPumpable: false
  },
  {
    input: "/^(\\+27|27)?(\\()?0?([7][1-9]|[8][2-4])(\\))?( |-|\\.|_)?(\\d{3})( |-|\\.|_)?(\\d{4})/",
    isPumpable: false
  },
  {
    input: "/(^-?\\d{0,14})+(\\.\\d{0,18})?)/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: '/"[A-Za-z0-9]{3}"/',
    isPumpable: false
  },
  {
    input:
      "/^[\\\\(]{0,1}([0-9]){3}[\\\\)]{0,1}[ ]?([^0-1]){1}([0-9]){2}[ ]?[-]?[ ]?([0-9]){4}[ ]*((x){0,1}([0-9]){1,5}){0,1}$/",
    isPumpable: false
  },
  {
    input: "/^[\\w]+[-\\.\\w]*@[-\\w]+\\.[a-z]{2,6}(\\.[a-z]{2,6})?$/",
    isPumpable: false
  },
  {
    input: "/[a-z]{3,4}s?:\\/\\/[-\\w.]+(\\/[-.\\w%&=?]+)*/",
    isPumpable: false
  },
  {
    input: "/http:\\/\\/[^\\/]*\\//",
    isPumpable: false
  },
  {
    input: "/(([A-Za-z0-9_\\\\-]+\\\\.?)*)[A-Za-z0-9_\\\\-]+\\\\.[A-Za-z0-9_\\\\-]{2,6}/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input: '/name.matches("a-z")/',
    isPumpable: false
  },
  {
    input: "/(^[a-fA-F]+[+-]?$)/",
    isPumpable: false
  },
  {
    input: "/\\d{5,12}|\\d{1,10}\\.\\d{1,10}\\.\\d{1,10}|\\d{1,10}\\.\\d{1,10}/",
    isPumpable: false
  },
  {
    input: "/[0-9]{4}[A-Z]{2}/",
    isPumpable: false
  },
  {
    input: "/(?:\\([2-9][0-8]\\d\\)\\ ?|[2-9][0-8]\\d[\\-\\ \\.\\/]?)[2-9]\\d{2}[- \\.\\/]?\\d{4}\\b/",
    isPumpable: false
  },
  {
    input: "/^(?([0-1])[0-1][0-9]|2[0-3])\\:[0-5][0-9]$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 40)}"
  },
  {
    input: "/^([0-9a-f]{4}\\.[0-9a-f]{4}\\.[0-9a-f]{4})$/",
    isPumpable: false
  },
  {
    input: "/<a.*? href=[\"|'].*\\?(?<query>.*?)[\"|'].*?>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(22, 60)}"
  },
  {
    input:
      "/^([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])([Z]|\\.[0-9]{4}|[-|\\+]([0-1][0-9]|2[0-3]):([0-5][0-9]))?$/",
    isPumpable: false
  },
  {
    input:
      "/^((1[6789]|[2-9][0-9])[0-9]{2}-(0[13578]|1[02])-(0[1-9]|[12][0-9]|3[01]))$|^((1[6789]|[2-9][0-9])[0-9]{2}-(0[469]|11)-(0[1-9]|[12][0-9]|30))$|^((16|[248][048]|[3579][26])00)|(1[6789]|[2-9][0-9])(0[48]|[13579][26]|[2468][048])-02-(0[1-9]|1[0-9]|2[0-9])$|^(1[6789]|[2-9][0-9])[0-9]{2}-02-(0[1-9]|1[0-9]|2[0-8])$/",
    isPumpable: false
  },
  {
    input:
      "/^[-]?((1[6789]|[2-9][0-9])[0-9]{2}-(0[13578]|1[02])-(0[1-9]|[12][0-9]|3[01]))T([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])([Z]|\\.[0-9]{4}|[-|\\+]([0-1][0-9]|2[0-3]):([0-5][0-9]))?$|^[-]?((1[6789]|[2-9][0-9])[0-9]{2}-(0[469]|11)-(0[1-9]|[12][0-9]|30))T([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])([Z]|\\.[0-9]{4}|[-|\\+]([0-1][0-9]|2[0-3]):([0-5][0-9]))?$|^[-]?((16|[248][048]|[3579][26])00)|(1[6789]|[2-9][0-9])(0[48]|[13579][26]|[2468][048])-02-(0[1-9]|1[0-9]|2[0-9])T([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])([Z]|\\.[0-9]{4}|[-|\\+]([0-1][0-9]|2[0-3]):([0-5][0-9]))?$|^[-]?(1[6789]|[2-9][0-9])[0-9]{2}-02-(0[1-9]|1[0-9]|2[0-8])T([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])([Z]|\\.[0-9]{4}|[-|\\+]([0-1][0-9]|2[0-3]):([0-5][0-9]))?$/",
    isPumpable: false
  },
  {
    input: "/(?:[a-z]{3},\\s+)?(\\d{1,2})\\s+([a-z]{3})\\s+(\\d{4})\\s+([01][0-9]|2[0-3])\\:([0-5][0-9])/",
    isPumpable: false
  },
  {
    input: "/^(\\d{3,})\\s?(\\w{0,5})\\s([a-zA-Z]{2,30})\\s([a-zA-Z]{2,15})\\.?\\s?(\\w{0,5})$/",
    isPumpable: false
  },
  {
    input: "/'`.*?((http|ftp|https):\\/\\/[\\w#$&+,\\/:;=?@.-]+)[^\\w#$&+,\\/:;=?@.-]*?`i'/",
    isPumpable: false
  },
  {
    input:
      "/^((((31\\/(0?[13578]|1[02]))|((29|30)\\/(0?[1,3-9]|1[0-2])))\\/(1[6-9]|[2-9]\\d)?\\d{2})|(29\\/0?2\\/(((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))|(0?[1-9]|1\\d|2[0-8])\\/((0?[1-9])|(1[0-2]))\\/((1[6-9]|[2-9]\\d)?\\d{2})) (20|21|22|23|[0-1]?\\d):([0-5]?)\\d$/",
    isPumpable: false
  },
  {
    input: "/(\\d{3}\\-\\d{2}\\-\\d{4})/",
    isPumpable: false
  },
  {
    input: "/((?!^[0-4])^(\\d+))$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/((\\d{1,6}\\-\\d{1,6})|(\\d{1,6}\\\\\\d{1,6})|(\\d{1,6})(\\/)(\\d{1,6})|(\\w{1}\\-?\\d{1,6})|(\\w{1}\\s\\d{1,6})|((P\\.?O\\.?\\s)((BOX)|(Box))(\\s\\d{1,6}))|((([R]{2})|([H][C]))(\\s\\d{1,6}\\s)((BOX)|(Box))(\\s\\d{1,6}))?)$/",
    isPumpable: false
  },
  {
    input: "/^http:\\/\\/\\\\.?video\\\\.google+\\\\.\\\\w{2,3}/videoplay\\\\?docid=[\\\\w-]{19}/",
    isPumpable: false
  },
  {
    input: "/(?<HTML><a[^>]*href\\s*=\\s*[\\\"\\']?(?<HRef>[^\"'>\\s]*)[\\\"\\']?[^>]*>(?<Title>[^<]+|.*?)?</a\\s*>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/<script.*\\/*>|<\\/script>|<[a-zA-Z][^>]*=['\"]+javascript:\\w+.*['\"]+>|<\\w+[^>]*\\son\\w+=.*[ /]*>/",
    isPumpable: false
  },
  {
    input: "/<\\?xml.*<\\/note>/",
    isPumpable: false
  },
  {
    input: "/^(b|B)(f|F)(p|P)(o|O)(\\s*||\\s*C(\\/|)O\\s*)[0-9]{1,4}/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^(b|B)(f|F)(p|P)(o|O)(\\s|\\sC\\/O\\s)[0-9]{1,4}/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{1,2}[0-9A-Za-z]{1,2}[ ]?[0-9]{0,1}[A-Za-z]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]{2}[0-9]{6}[A-Za-z]{1}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{4},?)+$/",
    isPumpable: false
  },
  {
    input: "/^[\\+\\-]?[0-9]+([\\,\\.][0-9]+)?$/",
    isPumpable: false
  },
  {
    input: "/[0-9]{4}\\s*[a-zA-Z]{2}/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]{1,}[a-z]{1,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,}[A-Z]{0,}[a-z]{0,})$/",
    isPumpable: false
  },
  {
    input: "/^[+-]?([0-9]*\\.?[0-9]+|[0-9]+\\.?[0-9]*)([eE][+-]?[0-9]+)?$/",
    isPumpable: false
  },
  {
    input:
      "/^[^\\~\\`\\!\\@\\#\\$\\%\\^\\&\\*\\(\\)\\-\\_\\=\\+\\\\\\|\\[\\]\\{\\}\\;\\:\\\"\\'\\,\\<\\.\\/\\>\\?\\s](([a-zA-Z0-9]*[-_\\.\\/]?[a-zA-Z0-9]{1,})*)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "\\x00",
    pumpable: "0a",
    suffix: "!"
  },
  {
    input: "/('(?:(?:\\\\'|[^'])*)'|NULL)/",
    isPumpable: false
  },
  {
    input:
      "/(\\(0\\d\\d\\)\\s\\d{3}[\\s-]+\\d{4})|(0\\d\\d[\\s-]+\\d{3}[\\s-]+\\d{4})|(0\\d{9})|(\\+\\d\\d\\s?[\\(\\s]\\d\\d[\\)\\s]\\s?\\d{3}[\\s-]?\\d{4})/",
    isPumpable: false
  },
  {
    input:
      "/<(\\s*\\/?\\s*)\\w+?(\\s*(([\\w-]+=\"[^\"]*?\")|([\\w-]+='[^']*?')|([\\w-]+=[^'\"<>\\s]+)))*(\\s*/?\\s*)>/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "<0",
    pumpable: ' a=""-=\'\'-=\\x00AA=""',
    suffix: ""
  },
  {
    input: "/[A-Z][a-zA-Z]+ [A-Z][a-zA-Z]+/",
    isPumpable: false
  },
  {
    input: "/^\\$\\d{1,3}(,?\\d{3})*(\\.\\d{2})?$/",
    isPumpable: false
  },
  {
    input: "/(?!000)(?!666)^([0-8]\\d{2})(\\d{2})(\\d{4})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/(^[A-Za-z])|(\\s)([A-Za-z])/",
    isPumpable: false
  },
  {
    input: "/^(\\d{5})$|^([a-zA-Z]\\d[a-zA-Z]( )?\\d[a-zA-Z]\\d)$/",
    isPumpable: false
  },
  {
    input: "/[:;]{1}[-~+o]?[(<\\[]+/",
    isPumpable: false
  },
  {
    input: "/[:]{1}[-~+o]?[)>]+/",
    isPumpable: false
  },
  {
    input:
      "/^\\$([0]|([1-9]\\d{1,2})|([1-9]\\d{0,1},\\d{3,3})|([1-9]\\d{2,2},\\d{3,3})|([1-9],\\d{3,3},\\d{3,3}))([.]\\d{1,2})?$|^\\(\\$([0]|([1-9]\\d{1,2})|([1-9]\\d{0,1},\\d{3,3})|([1-9]\\d{2,2},\\d{3,3})|([1-9],\\d{3,3},\\d{3,3}))([.]\\d{1,2})?\\)$|^(\\$)?(-)?([0]|([1-9]\\d{0,6}))([.]\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^(1[89]|[2-9]\\d)$/",
    isPumpable: false
  },
  {
    input: "/^[\\+\\-]?\\d+(,\\d+)?$/",
    isPumpable: false
  },
  {
    input: "/^(0?[1-9]|1[012])\\/([012][0-9]|[1-9]|3[01])\\/([12][0-9]{3})$/",
    isPumpable: false
  },
  {
    input: "/[^A-Za-z0-9_@\\.]|@{2,}|\\.{5,}/",
    isPumpable: false
  },
  {
    input: "/^(Function|Sub)(\\s+[\\w]+)\\([^\\(\\)]*\\)/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1,3},)?(\\d{3},)+\\d{3}(\\.\\d*)?$|^(\\d*)(\\.\\d*)?$/",
    isPumpable: false
  },
  {
    input: '/^(?!^(PRN|AUX|CLOCK\\$|NUL|CON|COM\\d|LPT\\d|\\..*)(\\..+)?$)[^\\x00-\\x1f\\\\?*<>:\\;|\\"/]+$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/^.*[_A-Za-z0-9]+[\\t ]+[\\*&]?[\\t ]*[_A-Za-z0-9](::)?[_A-Za-z0-9:]+[\\t ]*\\(( *[ \\[\\]\\*&A-Za-z0-9_]+ *,? *)*\\).*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a aa(",
    pumpable: " [",
    suffix: ""
  },
  {
    input: "/^((67\\d{2})|(4\\d{3})|(5[1-5]\\d{2})|(6011))-?\\s?\\d{4}-?\\s?\\d{4}-?\\s?\\d{4}|3[4,7]\\d{13}$/",
    isPumpable: false
  },
  {
    input: "/^((67\\d{2})|(4\\d{3})|(5[1-5]\\d{2})|(6011))(-?\\s?\\d{4}){3}|(3[4,7])\\d{2}-?\\s?\\d{6}-?\\s?\\d{5}$/",
    isPumpable: false
  },
  {
    input: "/^[a-z\\.]*\\s?([a-z\\-\\']+\\s)+[a-z\\-\\']+$/",
    isPumpable: false
  },
  {
    input: "/((\\s*([^,{]+)\\s*,?\\s*)*?){((\\s*([^:]+)\\s*:\\s*([^;]+?)\\s*;\\s*)*?)}/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(25)}"
  },
  {
    input: "/(^[a-zA-Z0-9]+:\\/\\/)/",
    isPumpable: false
  },
  {
    input: "/(?:\\/\\*[\\w\\W]*?\\*\\/|\\/\\/[^\\n]*?$|\\#[^\\n]*?$)/",
    isPumpable: false
  },
  {
    input:
      "/(^|\\s|\\()((([1-9]){1}|([0][1-9]){1}|([1][012]){1}){1}[\\/-]((2[0-9]){1}|(3[01]){1}|([01][1-9]){1}|([1-9]){1}){1}[\\/-](((19|20)([0-9][0-9]){1}|([0-9][0-9]){1})){1}(([\\s|\\)|:])|(^|\\s|\\()((([0-9]){1}|([0][1-9]){1}|([1][012]){1}){1}[\\/-](([11-31]){1}|([01][1-9]){1}|([1-9]){1}){1}[\\/-](((19|20)([0-9][0-9]){1}|([0-9][0-9]){1})){1}(([\\s|\\)|:|$|\\>])){1}){1}){1}){1}/",
    isPumpable: false
  },
  {
    input: "/(\\w(\\s)?)+/",
    isPumpable: false
  },
  {
    input: "/^([V|E|J|G|v|e|j|g])([0-9]{5,8})$/",
    isPumpable: false
  },
  {
    input: "/^0[0-9]{3}-[0-9]{7}$/",
    isPumpable: false
  },
  {
    input: "/[+-]?+(?>\\d++\\.?+\\d*+|\\d*+\\.?+\\d++)/",
    wasParseError: "{ParsingData.UnsupportedPossessiveQuantifier(5)}"
  },
  {
    input: "/((?:\\d+\\.){1,5})/",
    isPumpable: false
  },
  {
    input: "/(?<!^)(?=[A-Z])/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/^((((((((jan(uary)?)|(mar(ch)?)|(may)|(july?)|(aug(ust)?)|(oct(ober)?)|(dec(ember)?)) ((3[01])|29))|(((apr(il)?)|(june?)|(sep(tember)?)|(nov(ember)?)) ((30)|(29)))|(((jan(uary)?)|(feb(ruary)?|(mar(ch)?)|(apr(il)?)|(may)|(june?)|(july?)|(aug(ust)?)|(sep(tember)?)|(oct(ober)?)|(nov(ember)?)|(dec(ember)?))) (2[0-8]|(1\\d)|(0?[1-9])))),? )|(((((1[02])|(0?[13578]))[\\.\\-\\/]((3[01])|29))|(((11)|(0?[469]))[\\.\\-\\/]((30)|(29)))|(((1[0-2])|(0?[1-9]))[\\.\\-\\/](2[0-8]|(1\\d)|(0?[1-9]))))[\\.\\-\\/])|(((((3[01])|29)[ \\-\\.\\/]((jan(uary)?)|(mar(ch)?)|(may)|(july?)|(aug(ust)?)|(oct(ober)?)|(dec(ember)?)))|(((30)|(29))[ \\.\\-\\/]((apr(il)?)|(june?)|(sep(tember)?)|(nov(ember)?)))|((2[0-8]|(1\\d)|(0?[1-9]))[ \\.\\-\\/]((jan(uary)?)|(feb(ruary)?|(mar(ch)?)|(apr(il)?)|(may)|(june?)|(july?)|(aug(ust)?)|(sep(tember)?)|(oct(ober)?)|(nov(ember)?)|(dec(ember)?)))))[ \\-\\.\\/])|((((3[01])|29)((jan)|(mar)|(may)|(jul)|(aug)|(oct)|(dec)))|(((30)|(29))((apr)|(jun)|(sep)|(nov)))|((2[0-8]|(1\\d)|(0[1-9]))((jan)|(feb)|(mar)|(apr)|(may)|(jun)|(jul)|(aug)|(sep)|(oct)|(nov)|(dec)))))(((175[3-9])|(17[6-9]\\d)|(1[89]\\d{2})|[2-9]\\d{3})|\\d{2}))|((((175[3-9])|(17[6-9]\\d)|(1[89]\\d{2})|[2-9]\\d{3})|\\d{2})((((1[02])|(0[13578]))((3[01])|29))|(((11)|(0[469]))((30)|(29)))|(((1[0-2])|(0[1-9]))(2[0-8]|(1\\d)|(0[1-9])))))|(((29feb)|(29[ \\.\\-\\/]feb(ruary)?[ \\.\\-\\/])|(feb(ruary)? 29,? ?)|(0?2[\\.\\-\\/]29[\\.\\-\\/]))((((([2468][048])|([3579][26]))00)|(17((56)|([68][048])|([79][26])))|(((1[89])|([2-9]\\d))(([2468][048])|([13579][26])|(0[48]))))|(([02468][048])|([13579][26]))))|(((((([2468][048])|([3579][26]))00)|(17((56)|([68][048])|([79][26])))|(((1[89])|([2-9]\\d))(([2468][048])|([13579][26])|(0[48]))))|(([02468][048])|([13579][26])))(0229)))$/",
    isPumpable: false
  },
  {
    input: "/^((Bob)|(John)|(Mary)).*$(?<!White)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(25)}"
  },
  {
    input: "/^[0-9]{4}\\s{0,2}[a-zA-z]{2}$/",
    isPumpable: false
  },
  {
    input:
      "/^(?i:(?<local_part>[a-z0-9!#$%^&*{}'`+=-_|\\/?]+(?:\\.[a-z0-9!#$%^&*{}'`+=-_|\\/?]+)*)@(?<labels>[a-z0-9]+\\z?.*[a-z0-9-_]+)*(?<tld>\\.[a-z0-9]{2,}))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input: "/^([A-Za-z0-9]+[A-Za-z0-9-_]*\\.)*(([A-Za-z0-9]+[A-Za-z0-9-_]*){3,}\\.)+([A-Za-z0-9]{2,4}\\.?)+)$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^[1-9]{1}[0-9]{0,2}([\\.\\,]?[0-9]{3})*$/",
    isPumpable: false
  },
  {
    input: "/^([+]39)?((38[{8,9}|0])|(34[{7-9}|0])|(36[6|8|0])|(33[{3-9}|0])|(32[{8,9}]))([\\d]{7})$/",
    isPumpable: false
  },
  {
    input: "/^(LDAP:\\/\\/([\\w]+\\/)?(CN=['\\w\\s\\-\\&]+,)*(OU=['\\w\\s\\-\\&]+,)*(DC=['\\w\\s\\-\\&]+[,]*)+)$/",
    isPumpable: false
  },
  {
    input:
      "/^(([A-Z]{1}[a-z]+([\\-][A-Z]{1}[a-z]+)?)([ ]([A-Z]\\.)){0,2}[ ](([A-Z]{1}[a-z]*)|([O]{1}[\\']{1}[A-Z][a-z]{2,}))([ ](Jr\\.|Sr\\.|IV|III|II))?)$/",
    isPumpable: false
  },
  {
    input: "/if(!isValidURL($_POST['url']){ echo \"do something\"; }/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(29)}"
  },
  {
    input: "/^1?[1-2]$|^[1-9]$|^[1]0$/",
    isPumpable: false
  },
  {
    input: "/^[\\w\\W]{1,1500}$/",
    isPumpable: false
  },
  /*
  {
    input: "/^(?n:(?<Apellidos>(?-i:[A-Z]\\'?(\\w+?|\\.)\\ ??){1,4})?[\\s,\\s]*(?<Nombres>(?-i:[A-Z]\\'?(\\w+?|\\.)\\ ??){1,4})?)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 110)}"
  },
  */
  {
    input: "/(?=^.{6,51}$)([A-Za-z]{1})([A-Za-z0-9!@#$%_\\^\\&\\*\\-\\.\\?]{5,49})$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/\\d{5}\\-\\d{3}/",
    isPumpable: false
  },
  {
    input: "/^[0-9]*$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{1,2},([0-9]{2},)*[0-9]{3}|[0-9]+)$/",
    isPumpable: false
  },
  {
    input: "/[+-]*[0-9]+[,]*[0-9]*|[+-]*[0-9]*[,]+[0-9]*/",
    isPumpable: false
  },
  {
    input:
      "/^((CN=(['\\w\\d\\s\\-\\&\\.]+(\\\\/)*(\\\\,)*)+,\\s*)*(OU=(['\\w\\d\\s\\-\\&\\.]+(\\\\/)*(\\\\,)*)+,\\s*)*(DC=['\\w\\d\\s\\-\\&]+[,]*\\s*){1,}(DC=['\\w\\d\\s\\-\\&]+\\s*){1})$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: "OU=\\x09\\x09,",
    suffix: ""
  },
  {
    input: "/^[a-z0-9_.-]*@[a-z0-9-]+(.[a-z]{2,4})+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "@aaaa",
    pumpable: "aaaaaaa",
    suffix: "{"
  },
  {
    input: "/^\\s*(?i:)((1[0-2])|(0[1-9])|([123456789])):(([0-5][0-9])|([123456789]))\\s(am|pm)\\s*$/",
    isPumpable: false
  },
  {
    input: "/(^[0][2][1579]{1})(\\d{6,7}$)/",
    isPumpable: false
  },
  {
    input: "/^[-+]?(\\d?\\d?\\d?,?)?(\\d{3}\\,?)*$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?(\\d?\\d?\\d?,?)?(\\d{3}\\,?)*(\\.?\\d+)$/",
    isPumpable: false
  },
  {
    input:
      "/^((https|http):\\/\\/)?(www.)?(([a-zA-Z0-9\\-]{2,})\\.)+([a-zA-Z0-9\\-]{2,4})(\\/[\\w\\.]{0,})*((\\?)(([\\w\\%]{0,}=[\\w\\%]{0,}&?)|[\\w]{0,})*)?$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "https://wwwaaa.aa?",
    pumpable: "0",
    suffix: "!"
  },
  {
    input:
      "/((\"|')[a-z0-9\\/\\.\\?\\=\\&]*(\\.htm|\\.asp|\\.php|\\.jsp)[a-z0-9\\/\\.\\?\\=\\&]*(\"|'))|(href=*?[a-z0-9\\/\\.\\?\\=\\&\"']*)/",
    isPumpable: false
  },
  {
    input:
      "/^(sip|sips):.*\\@((\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|([a-zA-Z\\-\\.]+\\.[a-zA-Z]{2,5}))(:[\\d]{1,5})?([\\w\\-?\\@?\\;?\\,?\\=\\%\\&]+)?/",
    isPumpable: false
  },
  {
    input: "/(01*0|1)*/",
    isPumpable: false
  },
  {
    input: '/^["a-zA-Z0-9\\040]+$/',
    isPumpable: false
  },
  {
    input:
      '/^\\s*(([/-9!#-\'*+=?A-~-]+(?:\\.[/-9!#-\'*+=?A-~-]+)*|"(?:[^"\\r\\n\\\\]|\\\\.)*")@([A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?(?:\\.[A-Za-z][0-9A-Za-z-]*[0-9A-Za-z]?)*|\\[(?:[^\\[\\]\\r\\n\\\\]|\\\\.)*\\]))\\s*$/',
    isPumpable: true,
    isVulnerable: true,
    prefix: "A.A@A",
    pumpable: ".A0",
    suffix: "\\x00"
  },
  {
    input: "/^\\(0[1-9]{1}\\)[0-9]{8}$/",
    isPumpable: false
  },
  {
    input:
      '/((?:(?:"[^"]*")|(\'[^\\r]*)(\\r\\n)?)*)([\\s]*[,]|$) {CHANGED TO)(?<![\\"\\w\\d\\s])[\\s]*(?:"((?:[^\\"]|[\\"]{2})*)"|([\\w\\d\\s]+))[\\s]*(?=[\\,]|[\\r\\n]+|$)/',
    wasParseError: "{ParsingData.IncompleteRangeDefinition(48)}"
  },
  {
    input: "/^\\d?\\d'(\\d|1[01])?.?(\\d|1[01])\"$/",
    isPumpable: false
  },
  {
    input: "/^http\\:\\/\\/www.[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}\\/$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{4}[-\\s]{1}[\\d]{3}[-\\s]{1}[\\d]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{5}[-\\s]{1}[\\d]{3}[-\\s]{1}[\\d]{3}$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{5}[-\\s]{1}[\\d]{2}[-\\s]{1}[\\d]{2}[-\\s]{1}[\\d]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{5}[-\\s]{1}[\\d]{4}[-\\s]{1}[\\d]{2}$/",
    isPumpable: false
  },
  {
    input: "/^[\\d]{5}[-\\s]{1}[\\d]{2}[-\\s]{1}[\\d]{4}$/",
    isPumpable: false
  },
  {
    input: "/^[0-9]{1,15}(\\.([0-9]{1,2}))?$/",
    isPumpable: false
  },
  {
    input: "/^(\\d){2}-(\\d){2}-(\\d){2}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d){8}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d){7,8}$/",
    isPumpable: false
  },
  {
    input: "/^[^\\s]+$/",
    isPumpable: false
  },
  {
    input:
      "/([A-PR-UWYZa-pr-uwyz]([0-9]{1,2}|([A-HK-Ya-hk-y][0-9]|[A-HK-Ya-hk-y][0-9]([0-9]|[ABEHMNPRV-Yabehmnprv-y]))|[0-9][A-HJKS-UWa-hjks-uw]))/",
    isPumpable: false
  },
  {
    input:
      "/http[s]?:\\/\\/(www|[a-zA-Z]{2}-[a-zA-Z]{2})\\.facebook\\.com\\/(pages\\/[a-zA-Z0-9-]+\\/[0-9]+|[a-zA-Z0-9-]+)[\\/]?$/",
    isPumpable: false
  },
  {
    input: "/http:\\/\\/www\\.youtube\\.com.*v=(?'VideoID'[^&]*)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(30, 39)}"
  },
  {
    input: "/^http[s]?:\\/\\/twitter\\.com\\/(#!\\/)?[a-zA-Z0-9]{1,15}[\\/]?$/",
    isPumpable: false
  },
  {
    input: "/^(?!^(5|15|18|30)$)\\d+$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/(?:\\?=.*)?$/",
    isPumpable: false
  },
  {
    input: "/^~\\/(?:default\\.aspx)?(?:\\?=.*)?$/",
    isPumpable: false
  },
  {
    input: "/^UA-\\d+-\\d+$/",
    isPumpable: false
  },
  {
    input: "/^[1-9]{1,2}(.5)?$/",
    isPumpable: false
  },
  {
    input: "/^(udp|norm):\\/\\/(?:(?:25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)(?(?=\\.?\\d)\\.)){4}:\\d{1,6}$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(54, 40)}"
  },
  {
    input: "/:(6553[0-5]|655[0-2][0-9]\\d|65[0-4](\\d){2}|6[0-4](\\d){3}|[1-5](\\d){4}|[1-9](\\d){0,3})/",
    isPumpable: false
  },
  {
    input: "/(:(6553[0-5]|655[0-2][0-9]\\d|65[0-4](\\d){2}|6[0-4](\\d){3}|[1-5](\\d){4}|[1-9](\\d){0,3}))?/",
    isPumpable: false
  },
  {
    input:
      "/^(02\\d\\s?\\d{4}\\s?\\d{4})|((01|05)\\d{2}\\s?\\d{3}\\s?\\d{4})|((01|05)\\d{3}\\s?\\d{5,6})|((01|05)\\d{4}\\s?\\d{4,5})$/",
    isPumpable: false
  },
  {
    input: "/^(?<user>.+)@(?<domain>.+)$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/(?m)^(?<scheme>\\w+?:\\/\\/)?(?<path>(?:[\\w.%$\\-_+!*'(),=@]+\\/|\\b)+(?:[\\w.%$\\-_+!*'(),=@]*))(?<query>\\?(?:[\\w.%$\\-_+!*'(),=@]+=[\\w.%$\\-_+!*'(),=@]*&?)*)?(?<fragment>#[\\w\\.%$\\-_+!*'(),=@]*)?/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input: "/(?s)<tr[^>]*>(?<content>.*?)<\\/tr>/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(15, 60)}"
  },
  {
    input: "/[\\?&](?<name>[^&=]+)=(?<value>[^&=]+)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(7, 60)}"
  },
  {
    input:
      "/(?i)^(?:(?:METAR|SPECI)\\s*)*(?<ICAO>[\\w]{4})\\s*?(?<DateUTC>(?<DayOfMonth>\\d{0,2})(?<Hour>\\d{2})(?<Minutes>\\d{2}))Z{1}\\s*(?:[^\\r\\n])*/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(30, 60)}"
  },
  {
    input: '/(?i)(?s)<a[^>]+?href="?(?<url>[^"]+)"?>(?<innerHtml>.+?)</a\\s*>/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(25, 60)}"
  },
  {
    input: "/(?s)(?<=<a[^>]+?)(?<name>\\w+)=(?:[\"']?(?<value>[^\"'>]*)[\"']?)(?=.+?>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(19, 60)}"
  },
  {
    input: "/<!--[\\s\\S]*?--[ \\t\\n\\r]*>/",
    isPumpable: false
  },
  {
    input:
      "/^0(((1[0-9]{2}[ -]?[0-9]{3}[ -]?[0-9]{4})|(1[0-9]{3}[ -]?[0-9]{6})|(1[0-9]{4}[ -]?[0-9]{4,5}))|((1[0-9]1)|(11[0-9]))[ -]?[0-9]{3}[ -]?[0-9]{4}|(2[0-9][ -]?[0-9]{4}[ -]?[0-9]{4})|((20[ -]?[0-9]{4})|(23[ -]?[8,9][0-9]{3})|(24[ -]?7[0-9]{3})|(28[ -]?(25|28|37|71|82|90|92|95)[0-9]{2})|(29[ -]?2[0-9]))[ -]?[0-9]{4}|(7[4-9][0-9]{2}[ -]?[0-9]{6})|((3[0,3,4,7][0-9])[ -]?[0-9]{3}[ -]?[0-9]{4})|((5[5,6][ -]?[0-9]{4}[ -]?[0-9]{4})|(500[ -]?[0-9]{3}[ -]?[0-9]{4}))|(8[0247][0-9]{1}[ -]?[0-9]{3}[ -]?[0-9]{4})|(9[0-9]{2}[ -]?[0-9]{3}[ -]?[0-9]{4}))$/",
    isPumpable: false
  },
  {
    input: "/^([\\w-]+\\.)+[\\w-]+(\\/[\\w-.\\/?%&=]*)?$/",
    isPumpable: false
  },
  {
    input:
      "/\\/^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}([a-z0-9]|([a-z0-9][\\-]))+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$\\//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input:
      "/\\/^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$\\//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "a0",
    suffix: ""
  },
  {
    input:
      "/(http|https)\\:\\/\\/(([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})|([\\w\\-]+\\.)+(((af|ax|al|dz|as|ad|ao|ai|aq|ag|am|aw|au|at|az|bs|bh|bd|bb|by|be|bz|bj|bm|bt|bo|ba|bw|bv|br|io|bn|bg|bf|kh|cm|ca|cv|ky|cf|td|cl|cn|cx|cc|km|cg|cd|ck|cr|ci|hr|cu|cy|cz|dk|dj|dm|do|ec|eg|sv|gq|er|ee|et|fk|fo|fj|fi|fr|gf|pf|tf|ga|gm|ge|de|gh|gi|gr|gl|gd|gp|gu|gt| gg|gn|gw|gy|ht|hm|va|hn|hk|hu|is|id|ir|iq|ie|im|il|it|jm|jp|je|jo|kz|ke|ki|kp|kr|kw|kg|la|lv|lb|ls|lr|ly|li|lt|lu|mo|mk|mg|mw|my|mv|ml|mt|mh|mq|mr|yt|mx|fm|md|mc|mn|ms|ma|mz|mm|nr|np|nl|an|nc|nz|ni|ng|nu|nf|mp|no|om|pk|pw|ps|pa|pg|py|pe|ph|pn|pl|pt|qa|re|ro|ru|rw|sh|kn|lc|pm|vc|ws|sm|st|sa|sn|cs|sc|sl|sg|sk|si|sb|so|za|gs|es|lk|sd|sr|sj|sz|se|ch|sy|tw|tj|tz|th|tl|tg|tk|to|tt|tn|tr|tm|tc|tv|ug|ua|gb|us|um|uy|uz|vu|ve|vn|vg|vi|wf|eh|ye|zm|zw|uk|com|edu|gov|int|mil|net|org|biz|info|name|pro|aero|coop|museum|arpa|co|in|ne|bi|na|pr|ae|mu|ar))))(:[\\d]{1,4})?($|(\\/([a-zA-Z0-9\\.\\?=\\/#%&\\+-])*)*|\\/)/",
    isPumpable: true,
    isVulnerable: false
  },
  {
    input:
      "/([\\w\\-\\.]*)@(([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3})|([\\w\\-]+\\.)+(((af|ax|al|dz|as|ad|ao|ai|aq|ag|am|aw|au|at|az|bs|bh|bd|bb|by|be|bz|bj|bm|bt|bo|ba|bw|bv|br|io|bn|bg|bf|kh|cm|ca|cv|ky|cf|td|cl|cn|cx|cc|km|cg|cd|ck|cr|ci|hr|cu|cy|cz|dk|dj|dm|do|ec|eg|sv|gq|er|ee|et|fk|fo|fj|fi|fr|gf|pf|tf|ga|gm|ge|de|gh|gi|gr|gl|gd|gp|gu|gt| gg|gn|gw|gy|ht|hm|va|hn|hk|hu|is|id|ir|iq|ie|im|il|it|jm|jp|je|jo|kz|ke|ki|kp|kr|kw|kg|la|lv|lb|ls|lr|ly|li|lt|lu|mo|mk|mg|mw|my|mv|ml|mt|mh|mq|mr|yt|mx|fm|md|mc|mn|ms|ma|mz|mm|nr|np|nl|an|nc|nz|ni|ng|nu|nf|mp|no|om|pk|pw|ps|pa|pg|py|pe|ph|pn|pl|pt|qa|re|ro|ru|rw|sh|kn|lc|pm|vc|ws|sm|st|sa|sn|cs|sc|sl|sg|sk|si|sb|so|za|gs|es|lk|sd|sr|sj|sz|se|ch|sy|tw|tj|tz|th|tl|tg|tk|to|tt|tn|tr|tm|tc|tv|ug|ua|gb|us|um|uy|uz|vu|ve|vn|vg|vi|wf|eh|ye|zm|zw|uk|com|edu|gov|int|mil|net|org|biz|info|name|pro|aero|coop|museum|arpa|co|in|ne|bi|na|pr|ae|mu|ar)))?)/",
    isPumpable: false
  },
  {
    input: "/(?=^.{7,20}$)(?=.*\\d)(?=.*[a-zA-Z])(?!.*\\s)[0-9a-zA-Z*$-+?_&=!%{}\\/'.]*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[^]*\\[section\\][^\\[]*\\nkey=(.+)[^]*/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/^([+]39)?\\s?((313)|(32[03789])|(33[013456789])|(34[0256789])|(36[0368])|(37[037])|(38[0389])|(39[0123]))[\\s-]?([\\d]{7})$/",
    isPumpable: false
  },
  {
    input: "/&\\#x0*(0|1|2|3|4|5|6|7|8|B|C|E|F|10|11|12|13|14|15|16|17|18|19|1A|1B|1C|1D|1E|1F);/",
    isPumpable: false
  },
  {
    input: "/^\\.([rR]([aA][rR]|\\d{2})|(\\d{3})?)$/",
    isPumpable: false
  },
  {
    input:
      "/(?<STag><)[\\/\\?\\s]*(?<Prefix>\\w*:)*(?<TagName>\\w*)\\s*(?<Attributes>(?<Attribute>((?<AttributePrefix>\\w*)\\s*:\\s*)*(?<AttributeName>\\w*)\\s*=\\s*(?<AttributeValue>\"[^\"]*\"|'[^']*'|[^>\\s]*)\\s*)*)\\s*/?(?<ETag>>)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^0(6[045679][0469]){1}(\\-)?(1)?[^0\\D]{1}\\d{6}$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\'|\\\")?[a-zA-Z]+(?:\\-[a-zA-Z]+)?(?:s\\'|\\'[a-zA-Z]{1,2})?(?:(?:(?:\\,|\\.|\\!|\\?)?(?:\\2)?)|(?:(?:\\2)?(?:\\,|\\.|\\!|\\?)?))(?: (\\'|\\\")?[a-zA-Z]+(?:\\-[a-zA-Z]+)?(?:s\\'|\\'[a-zA-Z]{1,2})?(?:(?:(?:\\,|\\.|\\!|\\?)?(?:\\2|\\3)?)|(?:(?:\\2|\\3)?(?:\\,|\\.|\\!|\\?)?)))*)$/",
    wasParseError: "{ParsingData.InvalidBackreference(84)}"
  },
  {
    input: '/(\\"http:\\/\\/www\\.youtube\\.com\\/v\\/\\w{11}\\&rel\\=1\\")/',
    isPumpable: false
  },
  {
    input: '/(\\"http:\\/\\/video\\.google\\.com\\/googleplayer\\.swf\\?docId=\\d{19}\\&hl=[a-z]{2}\\")/',
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z]+(?:\\.)?(?: [a-zA-Z]+(?:\\.)?)*)$/",
    isPumpable: false
  },
  {
    input:
      "/^([^_][\\w\\d\\@\\-]+(?:s\\'|\\'[a-zA-Z]{1,2})?(?:\\,)?(?: [\\w\\d\\@\\-]+(?:s\\'|\\'[a-zA-Z]{1,2})?(?:\\,)?)*(?:\\.|\\!|\\?){0,3}[^\\s_])$/",
    isPumpable: false
  },
  {
    input: "/^((?:\\+|\\-|\\$)?(?:\\d+|\\d{1,3}(?:\\,\\d{3})*)(?:\\.\\d+)?(?:[a-zA-Z]{2}|\\%)?)$/",
    isPumpable: false
  },
  {
    input:
      "/^(http\\:\\/\\/(?:www\\.)?[a-zA-Z0-9]+(?:(?:\\-|_)[a-zA-Z0-9]+)*(?:\\.[a-zA-Z0-9]+(?:(?:\\-|_)[a-zA-Z0-9]+)*)*\\.[a-zA-Z]{2,4}(?:\\/)?)$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9]{4,18}?)$/",
    isPumpable: false
  },
  {
    input: "/^((?:\\/[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*(?:\\-[a-zA-Z0-9]+)*)+)$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*)$/",
    isPumpable: false
  },
  {
    input:
      "/^(10\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5]\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5]\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5])$/",
    isPumpable: false
  },
  {
    input: "/^(172\\.1[6-9]|2[0-9]|3[0-1|\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5]\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5])$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^(192\\.168\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5]\\.[0-9]|[1-9][0-9]|[1-2][0-5][0-5])$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\/(?:(?:(?:(?:[a-zA-Z0-9\\\\-_.!~*'():\\@&=+\\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\\\-_.!~*'():\\@&=+\\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*)(?:/(?:(?:(?:[a-zA-Z0-9\\\\-_.!~*'():\\@&=+\\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\\\\-_.!~*'():\\@&=+\\$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*))*))$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "/",
    pumpable: "/=!",
    suffix: "\\x00"
  },
  {
    input: "/^(1?(?: |\\-|\\.)?(?:\\(\\d{3}\\)|\\d{3})(?: |\\-|\\.)?\\d{3}(?: |\\-|\\.)?\\d{4})$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{5}(?:\\-\\d{4})?)$/",
    isPumpable: false
  },
  {
    input: "/^(00[1-9]|0[1-9][0-9]|[1-6][0-9][0-9]|7[0-6][0-9]|77[0-2]\\-\\d{2}\\-\\d{4})$/",
    isPumpable: false
  },
  {
    input:
      "/^(\\d{4}(?:(?:(?:\\-)?(?:00[1-9]|0[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-6]))?|(?:(?:\\-)?(?:1[0-2]|0[1-9]))?|(?:(?:\\-)?(?:1[0-2]|0[1-9])(?:\\-)?(?:0[1-9]|[12][0-9]|3[01]))?|(?:(?:\\-)?W(?:0[1-9]|[1-4][0-9]5[0-3]))?|(?:(?:\\-)?W(?:0[1-9]|[1-4][0-9]5[0-3])(?:\\-)?[1-7])?)?)$/",
    isPumpable: false
  },
  {
    input: "/^([0-2][0-4](?:(?:(?::)?[0-5][0-9])?|(?:(?::)?[0-5][0-9](?::)?[0-5][0-9](?:\\.[0-9]+)?)?)?)$/",
    isPumpable: false
  },
  {
    input: "/^(Randal (?:L\\.)? Schwartz|merlyn)$/",
    isPumpable: false
  },
  {
    input: "/^((?:\\?[a-zA-Z0-9_]+\\=[a-zA-Z0-9_]+)?(?:\\&[a-zA-Z0-9_]+\\=[a-zA-Z0-9_]+)*)$/",
    isPumpable: false
  },
  {
    input:
      "/^(http(?:s)?\\:\\/\\/[a-zA-Z0-9\\-]+(?:\\.[a-zA-Z0-9\\-]+)*\\.[a-zA-Z]{2,6}(?:\\/?|(?:\\/[\\w\\-]+)*)(?:\\/?|\\/\\w+\\.[a-zA-Z]{2,4}(?:\\?[\\w]+\\=[\\w\\-]+)?)?(?:\\&[\\w]+\\=[\\w\\-]+)*)$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z0-9]+[a-zA-Z0-9._%-]*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,4})$/",
    isPumpable: false
  },
  {
    input: "/^(http\\:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(?:\\/\\S*)?(?:[a-zA-Z0-9_])+\\.(?:jpg|jpeg|gif|png))$/",
    isPumpable: false
  },
  {
    input: "/(?:[a-zA-Z0-9]+(?:(?:_|\\-|\\.)[a-zA-Z0-9]+)*)/",
    isPumpable: false
  },
  {
    input: "/(?:[^0-9][a-zA-Z0-9]+(?:(?:\\-|\\.)[a-zA-Z0-9]+)*)/",
    isPumpable: false
  },
  {
    input:
      "/^(\\w{3,6}\\:\\/\\/[\\w\\-]+(?:\\.[\\w\\-]+)+(?:\\:\\d{2,4})*(?:\\/?|(?:\\/[\\w\\-]+)*)(?:\\/?|\\/\\w+\\.\\w{2,4}(?:\\?[\\w]+\\=[\\w\\-]+)?)?(?:\\&[\\w]+\\=[\\w\\-]+)*)$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\.\\s]{3,}$/",
    isPumpable: false
  },
  {
    input: "/^(\\d+|(\\d*\\.{1}\\d{1,2}){1})$/",
    isPumpable: false
  },
  {
    input: "/(?i:)(?<=\\.)\\D\\D(?:-\\D{2,3}?(?:-\\D\\D\\D\\D)?)?(?=.resx)/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(5)}"
  },
  {
    input: "/^1?[-\\. ]?(\\(\\d{3}\\)?[-\\. ]?|\\d{3}?[-\\. ]?)?\\d{3}?[-\\. ]?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^01[0-2]{1}[0-9]{8}/",
    isPumpable: false
  },
  {
    input: "/^((\\d)?(\\d{1})(\\.{1})(\\d)?(\\d{1})){1}$/",
    isPumpable: false
  },
  {
    input:
      "/[A-Za-z](\\.[A-Za-z0-9]|\\-[A-Za-z0-9]|_[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9])(\\.[A-Za-z0-9]|\\-[A-Za-z0-9]|_[A-Za-z0-9]|[A-Za-z0-9])*/",
    isPumpable: false
  },
  {
    input:
      "/^[A-Za-z0-9](\\.[\\w\\-]|[\\w\\-][\\w\\-])(\\.[\\w\\-]|[\\w\\-]?[\\w\\-]){0,30}[\\w\\-]?@[A-Za-z0-9\\-]{3,63}\\.[a-zA-Z]{2,6}$/",
    isPumpable: false
  },
  {
    input: "/<!--.*?-->/",
    isPumpable: false
  },
  {
    input:
      "/^(1(0|7|9)2?)\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$/",
    isPumpable: false
  },
  {
    input:
      "/(NOT)?(\\s*\\(*)\\s*(\\w+)\\s*(=|<>|<|>|LIKE|IN)\\s*(\\(([^\\)]*)\\)|'([^']*)'|(-?\\d*\\.?\\d+))(\\s*\\)*\\s*)(AND|OR)?/",
    isPumpable: false
  },
  {
    input: "/(^[1]$)|(^[1]+\\d*\\.+\\d*[1-5]$)/",
    isPumpable: false
  },
  {
    input: "/^(#){1}([a-fA-F0-9]){6}$/",
    isPumpable: false
  },
  {
    input: "/(?<zip5>^\\d{5})([\\- ]?(?<plus4>\\d{4})?$)/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^\\d{5}((-|\\s)?\\d{4})?$/",
    isPumpable: false
  },
  {
    input: "/^\\d{5}((\\-|\\s)?\\d{4})?$/",
    isPumpable: false
  },
  {
    input: "/^(\\([2-9]|[2-9])(\\d{2}|\\d{2}\\))(-|.|\\s)?\\d{3}(-|.|\\s)?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^\\(?(?<AreaCode>[2-9]\\d{2})(\\)?)(-|.|\\s)?(?<Prefix>[1-9]\\d{2})(-|.|\\s)?(?<Suffix>\\d{4})$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(6, 60)}"
  },
  {
    input: "/\\/http:\\\\/\\/(?:www.)?clipser\\.com\\/watch_video\\/([0-9a-z-_]+)/i/",
    isPumpable: false
  },
  {
    input: "/\\/http:\\/\\/(?:www\\.)?blip\\.tv\\/file\\/(\\d+).*\\//",
    isPumpable: false
  },
  {
    input: "/\\/\\\\(?<\\w+[^>]*\\son\\w+=.*[ \\/].?>(?:\\))?/i/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input: "/\\/http:\\\\/\\/\\.?video.google.\\w{2,3}\\/videoplay\\?docid=([a-z0-9-_]+)/i/",
    isPumpable: false
  },
  {
    input: "/^\\(?[\\d]{3}\\)?[\\s-]?[\\d]{3}[\\s-]?[\\d]{4}$/",
    isPumpable: false
  },
  {
    input:
      "/^(((25[0-5]|2[0-4][0-9]|19[0-1]|19[3-9]|18[0-9]|17[0-1]|17[3-9]|1[3-6][0-9]|12[8-9]|12[0-6]|1[0-1][0-9]|1[1-9]|[2-9][0-9]|[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))|(192\\.(25[0-5]|2[0-4][0-9]|16[0-7]|169|1[0-5][0-9]|1[7-9][0-9]|[1-9][0-9]|[0-9]))|(172\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|1[0-5]|3[2-9]|[4-9][0-9]|[0-9])))\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/",
    isPumpable: false
  },
  {
    input: "/\\/((\\d){2})?(\\s|-)?((\\d){2,4})?(\\s|-){1}((\\d){8})$\\//",
    isPumpable: false
  },
  {
    input: "/^(-|\\+)?(((100|((0|[1-9]{1,2})(\\.[0-9]+)?)))|(\\.[0-9]+))%?$/",
    isPumpable: false
  },
  {
    input: "/^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/",
    isPumpable: false
  },
  {
    input: "/^([a-zA-Z])[a-zA-Z_-]*[\\w_-]*[\\S]$|^([a-zA-Z])[0-9_-]*[\\S]$|^[a-zA-Z]*[\\S]$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{12},)+[0-9]{12}$|^([0-9]{12})$/",
    isPumpable: false
  },
  {
    input: '/^([a-zA-Z]\\:|\\\\)\\\\([^\\\\]+\\\\)*[^\\/:*?"<>|]+\\.htm(l)?$/',
    isPumpable: false
  },
  {
    input:
      "/^(3[0-1]|2[0-9]|1[0-9]|0[1-9])[\\s{1}|\\/|-](Jan|JAN|Feb|FEB|Mar|MAR|Apr|APR|May|MAY|Jun|JUN|Jul|JUL|Aug|AUG|Sep|SEP|Oct|OCT|Nov|NOV|Dec|DEC)[\\s{1}|\\/|-]\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^((25[0-4]|(2[0-4]|1[0-9]|[1-9]?)[0-9]\\.){3}(25[0-4]|(2[0-4]|1[0-9]|[1-9]?)[0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^\\d{4,}$|^[3-9]\\d{2}$|^2[5-9]\\d$/",
    isPumpable: false
  },
  {
    input:
      "/(?!^([0-9]+[-]?[0-9]+)$)(?!^([0-9]+[[\\\\s]*]?[0-9]+)$)^([0-9]+\\.?[0-9]+$|(^[-]?[0-9]+([[\\\\s]*]?)$)|^([-]?)[0-9]+\\.?[0-9]+([[\\\\s]*]?)|([0-9]+))$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/(?!^([0-9]+)([[\\\\s]*]?)$)(?!^([0-9]+)[[a-zA-Z]*]?([[\\\\s]*]?)$)^([_]?([a-zA-Z0-9]+)([[\\\\s]*]?))$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input:
      "/(-?(90[ :°d]*00[ :\\'\\'m]*00(\\.0+)?|[0-8][0-9][ :°d]*[0-5][0-9][ :\\'\\'m]*[0-5][0-9](\\.\\d+)?)[ :\\?\\\"s]*(N|n|S|s)?)[ ,]*(-?(180[ :°d]*00[ :\\'\\'m]*00(\\.0+)?|(1[0-7][0-9]|0[0-9][0-9])[ :°d]*[0-5][0-9][ :\\'\\'m]*[0-5][0-9](\\.\\d+)?)[ :\\?\\\"s]*(E|e|W|w)?)/",
    wasParseError: "{ParsingData.NonAsciiInput(9, 194)}"
  },
  {
    input: "/((X|x):-?(180(\\.0+)?|[0-1]?[0-7]?[0-9](\\.\\d+)?))([ ]|,)*((Y|y):-?(90(\\.0+)?|[0-8]?[0-9](\\.\\d+)?))/",
    isPumpable: false
  },
  {
    input: "/([0-1][0-9]|2[0-3]):[0-5][0-9]/",
    isPumpable: false
  },
  {
    input: "/^([0-9][,]?)*([0-9][0-9])$/",
    isPumpable: false
  },
  {
    input: "/\\/^\"|'+(.*)+\"$|'$//",
    isPumpable: true,
    isVulnerable: true,
    prefix: "'",
    pumpable: "(",
    suffix: ""
  },
  {
    input:
      "/^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])$/",
    isPumpable: false
  },
  {
    input: "/^([0-9]{0,5}|[0-9]{0,5}\\.[0-9]{0,3})$/",
    isPumpable: false
  },
  {
    input: "/^[-+]?[1-9]\\d*\\.?[0]*$/",
    isPumpable: false
  },
  {
    input: "/^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|11|12|10)-(19[0-9]{2})$/",
    isPumpable: false
  },
  {
    input:
      "/^([0-2]{0,1})([0-3]{1})(\\.[0-9]{1,2})?$|^([0-1]{0,1})([0-9]{1})(\\.[0-9]{1,2})?$|^-?(24)(\\.[0]{1,2})?$|^([0-9]{1})(\\.[0-9]{1,2})?$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\s|[0])\\.(\\d{0,2}\\s{0,2}))?$|^(\\.(\\d\\s){0,2})?$|^(\\s{0,4}[1]{0,1}\\.[0]{0,2}\\s{0,4})?$|^(\\s{0,4}[1]{0,1}\\s{0,4})?$|^(\\s{0,4}[0]{0,4}[1]{0,1}\\s{0,4})?$|^([0]{0,4}\\s{0,4})?$|^(\\s{0,3}[0]{0,3}\\.{1}\\d{0,2}\\s{0,2})?$/",
    isPumpable: false
  },
  {
    input: "/^(?:http|https):\\/\\/[\\w.\\-]+(?:\\.[\\w\\-]+)+[\\w\\-.,@?^=%&:;\\/~\\\\+#]+$/",
    isPumpable: false
  },
  {
    input:
      "/^((0?[13578]|10|12)(-|\\/)(([1-9])|(0[1-9])|([12])([0-9]?)|(3[01]?))(-|\\/)((19)([2-9])(\\d{1})|(20)([01])(\\d{1})|([8901])(\\d{1}))|(0?[2469]|11)(-|\\/)(([1-9])|(0[1-9])|([12])([0-9]?)|(3[0]?))(-|\\/)((19)([2-9])(\\d{1})|(20)([01])(\\d{1})|([8901])(\\d{1})))$/",
    isPumpable: false
  },
  {
    input: "/^\\d{2,6}-\\d{2}-\\d$/",
    isPumpable: false
  },
  {
    input: "/CZ\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|CZ\\d{22}/",
    isPumpable: false
  },
  {
    input: "/SK\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|SK\\d{22}/",
    isPumpable: false
  },
  {
    input: "/AD\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|AD\\d{22}/",
    isPumpable: false
  },
  {
    input: "/ES\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|ES\\d{22}/",
    isPumpable: false
  },
  {
    input: "/SE\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|SE\\d{22}/",
    isPumpable: false
  },
  {
    input: "/CH\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{1}|CH\\d{19}/",
    isPumpable: false
  },
  {
    input: "/DE\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{2}|DE\\d{20}/",
    isPumpable: false
  },
  {
    input: "/PL\\d{2}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}[ ]\\d{4}|PL\\d{26}/",
    isPumpable: false
  },
  {
    input: "/\\b(ht|f)tp[s]?:\\/\\/[^\\s\\n\\r\\t\\<\\>]+(?=[\\b\\s\\n\\r\\t\\<])/",
    wasParseError: "{ParsingData.UnsupportedEscape(38, 98)}"
  },
  {
    input: "/^(\\d{1.3}(\\.\\d{3})*|(\\d+))(\\,\\d{1})|(\\d{1.3}(\\.\\d{3})*|(\\d+))(\\,\\d{2})?$/",
    wasParseError: "{ParsingData.IncompleteRangeDefinition(4)}"
  },
  {
    input: "/^(\\d{1}|\\d{2}|\\d{3})(\\.\\d{3})*?$/",
    isPumpable: false
  },
  {
    input:
      "/(4\\d{12})|(((4|3)\\d{3})|(5[1-5]\\d{2})|(6011))(-?|\\040?)(\\d{4}(-?|\\040?)){3}|((3[4,7]\\d{2})((-?|\\040?)\\d{6}(-?|\\040?)\\d{5}))|(3[4,7]\\d{2})((-?|\\040?)\\d{4}(-?|\\040?)\\d{4}(-?|\\040?)\\d{3})|(3[4,7]\\d{1})(-?|\\040?)(\\d{4}(-?|\\040?)){3}|(30[0-5]\\d{1}|(36|38)\\d(2))((-?|\\040?)\\d{4}(-?|\\040?)\\d{4}(-?|\\040?)\\d{2})|((2131|1800)|(2014|2149))((-?|\\040?)\\d{4}(-?|\\040?)\\d{4}(-?|\\040?)\\d{3})/",
    isPumpable: false
  },
  {
    input: "/^ *([0-1]?[0-9]|[2][0-3]):[0-5][0-9] *(a|p|A|P)(m|M) *$/",
    isPumpable: false
  },
  {
    input:
      "/^\\s*((31([-\\/ ])((0?[13578])|(1[02]))\\3(\\d\\d)?\\d\\d)|((([012]?[1-9])|([123]0))([-\\/ ])((0?[13-9])|(1[0-2]))\\12(\\d\\d)?\\d\\d)|(((2[0-8])|(1[0-9])|(0?[1-9]))([-\\/ ])0?2\\22(\\d\\d)?\\d\\d)|(29([-\\/ ])0?2\\25(((\\d\\d)?(([2468][048])|([13579][26])|(0[48])))|((([02468][048])|([13579][26]))00))))\\s*$/",
    wasParseError: "{ParsingData.InvalidBackreference(189)}"
  },
  {
    input: "/^(\\d{3}|\\d{4})[-](\\d{5})$/",
    isPumpable: false
  },
  {
    input: "/(-\\d{1,} | \\d{1,} | \\d{1,}-\\d{1,} | \\d{1,}-)(,(-\\d{1,} | \\d{1,} | \\d{1,}-\\d{1,} | \\d{1,}))*/",
    isPumpable: false
  },
  {
    input: "/\\d\\d?\\d?\\.\\d\\d?\\d?\\.\\d\\d?\\d?\\.\\d\\d?\\d?/",
    isPumpable: false
  },
  {
    input:
      "/(http:\\/\\/|)(www\\.)?([^\\.]+)\\.(\\w{2}|(com|net|org|edu|int|mil|gov|arpa|biz|aero|name|coop|info|pro|museum))$/",
    wasParseError: "{Parsing.Parse_error}"
  },
  {
    input: "/^((\\(0?[1-9][0-9]\\))|(0?[1-9][0-9]))[ -.]?([1-9][0-9]{3})[ -.]?([0-9]{4})$/",
    isPumpable: false
  },
  {
    input: "/^(1\\s*[-\\/\\.]?)?(\\((\\d{3})\\)|(\\d{3}))\\s*([\\s-.\\/\\\\])?([0-9]*)([\\s-./\\\\])?([0-9]*)$/",
    isPumpable: false
  },
  {
    input: "/^(\\d{1,8}|(\\d{0,8}\\.{1}\\d{1,2}){1})$/",
    isPumpable: false
  },
  {
    input: "/^(a-z|A-Z|0-9)*[^#$%^&*()']*$/",
    isPumpable: false
  },
  {
    input: "/^\\$( )*\\d*(.\\d{1,2})?$/",
    isPumpable: false
  },
  {
    input: "/^\\d+\\x20*([pP][xXtT])?$/",
    isPumpable: false
  },
  {
    input: "/^[a-zA-Z0-9\\s]+$/",
    isPumpable: false
  },
  {
    input: "/href[ ]*=[ ]*('|\\\")([^\\\"'])*('|\\\")/",
    isPumpable: false
  },
  {
    input: "/^M{0,1}T{0,1}W{0,1}(TH){0,1}F{0,1}S{0,1}(SU){0,1}$/",
    isPumpable: false
  },
  {
    input: "/^(([0][0-9]|[1][0-2])|[0-9]):([0-5][0-9])( *)((AM|PM)|(A|P))$/",
    isPumpable: false
  },
  {
    input:
      "/^(?:[\\+]?[\\(]?([\\d]{1,3})[\\s\\-\\.\\)]+)?(?:[\\(]?([\\d]{1,3})[\\s\\-\\/\\)]+)([2-9][0-9\\s\\-\\.]{6,}[0-9])(?:[\\s\\D]+([\\d]{1,5}))?$/",
    isPumpable: false
  },
  {
    input:
      "/^(?<Date>.+\\s\\d+\\s\\d+\\:\\d+\\:\\d+).+\\:.+\\:(?<Traffic>.+)\\:(?<Rule>.+)\\:IN\\=(?<InboundInterface>.+)\\sOUT\\=(?<OutboundIntercace>.*?)\\s(?:MAC\\=(?<MacAddress>.+)\\s|)SRC\\=(?<Source>.+)\\sDST\\=(?<Destination>.+)\\sLEN\\=.+TOS\\=.+PROTO\\=(?<Protocol>.+)\\sSPT\\=(?<SourcePort>.+)\\sDPT\\=(?<DestinationPort>.+)\\s.+$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input: '/(?<=[-{1,2}|/])(?<name>[a-zA-Z0-9]*)[ |:|"]*(?<value>[\\w|.|?|=|&|+| |:|/|\\\\]*)(?=[ |"]|$)/',
    wasParseError: "{ParsingData.UnsupportedInlineModifier(17, 60)}"
  },
  {
    input: "/if\\s[(][A-Za-z]*\\s[=]\\s/",
    isPumpable: false
  },
  {
    input:
      "/\\b((https?|ftp|file):\\/\\/)?([a-z0-9](?:[-a-z0-9]*[a-z0-9])?\\.)+(com\\b|edu\\b|biz\\b|gov\\b|in(?:t|fo)\\b|mil\\b|net\\b|org\\b|[a-z][a-z]\\b)(:\\d+)?(\\/[-a-z0-9_:\\@&?=+,.!\\/~*'%\\$]*)*(?<![.,?!])(?!((?!(?:<a )).)*?(?:<\\/a>))(?!((?!(?:<!--)).)*?(?:-->))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(169)}"
  },
  {
    input: '/^[^\\\\\\/\\?\\*\\"\\>\\<\\:\\|]*$/',
    isPumpable: false
  },
  {
    input: "/<(?<!\\\\?|\\\\/)([^>]*)>\\\\r*\\\\n<\\\\/(?=br|hr|img|input|link|param)[^>]*>/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input:
      "/(^N\\/A$)|(^[-]?(\\d+)(\\.\\d{0,3})?$)|(^[-]?(\\d{1,3},(\\d{3},)*\\d{3}(\\.\\d{1,3})?|\\d{1,3}(\\.\\d{1,3})?)$)/",
    isPumpable: false
  },
  {
    input: '/<[^>]*name[\\s]*=[\\s]*"?[^\\w_]*"?[^>]*>/',
    isPumpable: false
  },
  {
    input: '/("[^"]*")|(\'[^\\r]*)(\\r\\n)?/',
    isPumpable: false
  },
  {
    input: "/^(?<nombre>\\D{4})(?<fechanac>\\d{6})(?<homoclave>.{1}\\D{1}\\d{1})?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^([A-Za-z\\-]+)\\s+(\\w+)\\s+([A-Za-z0-9_\\-\\.]+)\\s+([A-Za-z0-9_\\-\\.]+)\\s+(\\d+)\\s+(.{3} [0-9 ]{2} ([0-9][0-9]:[0-9][0-9]| [0-9]{4}))\\s+(.+)$/",
    isPumpable: false
  },
  {
    input:
      "/^((((31\\/(0?[13578]|1[02]))|((29|30)\\/(0?[1,3-9]|1[0-2])))\\/(1[6-9]|[2-9]\\d)?\\d{2})|(29\\/0?2\\/(((1[6-9]|[2-9]\\d)?(0[48]|[2468][048]|[13579][26])|((16|[2468][048]|[3579][26])00))))|(0?[1-9]|1\\d|2[0-8])\\/((0?[1-9])|(1[0-2]))\\/((1[6-9]|[2-9]\\d)?\\d{2})) (20|21|22|23|[0-1]?\\d):[0-5]?\\d:[0-5]?\\d$/",
    isPumpable: false
  },
  {
    input: '/<img[^>]* src=\\"([^\\"]*)\\"[^>]*>/',
    isPumpable: false
  },
  {
    input: "/^(\\d+(,\\d+)*)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "0",
    pumpable: "00",
    suffix: "!"
  },
  {
    input: "/^\\d{3}\\s?\\d{3}$/",
    isPumpable: false
  },
  {
    input: "/^.{0,0}/",
    isPumpable: false
  },
  {
    input: "/((\\(?\\d{2,5}\\)?)?(\\d|-| )?(15((\\d|-| ){6,13})))/",
    isPumpable: false
  },
  {
    input: "/^[A-Za-z]$/",
    isPumpable: false
  },
  {
    input: "/(^[1-9]$)|(^10$)/",
    isPumpable: false
  },
  {
    input: "/^([\\w\\-\\.]+)@((\\[([0-9]{1,3}\\.){3}[0-9]{1,3}\\])|(([\\w\\-]+\\.)+)([a-zA-Z]{2,4}))$/",
    isPumpable: false
  },
  {
    input:
      '/^(([-\\w \\.]+)|(""[-\\w \\.]+"") )?<([\\w\\-\\.]+)@((\\[([0-9]{1,3}\\.){3}[0-9]{1,3}\\])|(([\\w\\-]+\\.)+)([a-zA-Z]{2,4}))>$/',
    isPumpable: false
  },
  {
    input: "/([0-9]+\\.[0-9]*)|([0-9]*\\.[0-9]+)|([0-9]+)/",
    isPumpable: false
  },
  {
    input: '/\\s(?=([^"]*"[^"]*"[^"]*)*$|[^"]*$)/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(2)}"
  },
  {
    input: "/^http:\\/\\/\\w{0,3}.?youtube+\\.\\w{2,3}\\/watch\\?v=[\\w-]{11}/",
    isPumpable: false
  },
  {
    input:
      "/^((([a-zA-Z\\'\\.\\-]+)?)((,\\s*([a-zA-Z]+))?)|([A-Za-z0-9](([_\\.\\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\\.\\-]?[a-zA-Z0-9]+)*)\\.([A-Za-z]{2,})))(;{1}(((([a-zA-Z\\'\\.\\-]+){1})((,\\s*([a-zA-Z]+))?))|([A-Za-z0-9](([_\\.\\-]?[a-zA-Z0-9]+)*)@([A-Za-z0-9]+)(([\\.\\-]?[a-zA-Z0-9]+)*)\\.([A-Za-z]{2,})){1}))*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: ";aaA@0.AA",
    suffix: "!"
  },
  {
    input: "/^\\\\{2}[\\w-]+\\\\(([\\w-][\\w-\\s]*[\\w-]+[$$]?$)|([\\w-][$$]?$))/",
    isPumpable: false
  },
  {
    input: "/^\\d{1,2}((,)|(,25)|(,50)|(,5)|(,75)|(,0)|(,00))?$/",
    isPumpable: false
  },
  {
    input: "/(?:\\b\\w*(\\w\\w?)\\1{2,}\\w*\\b)/",
    isPumpable: false
  },
  {
    input:
      "/(?:\\b(([0-2]\\d|3[01])|\\d)\\.[ ]?(?:jan|feb|mar|apr|máj|jún|júl|aug|sep|okt|nov|dec|január\\w{0,2}|február\\w{0,2}|mar\\w{0,2}|apríl\\w{0,2}|máj\\w{0,2}|jún\\w{0,2}|júl\\w{0,2}|august\\w{0,2}|septemb\\w{0,2}|októb\\w{0,2}|novemb\\w{0,2}|decemb\\w{0,2})[ ][12][0-9]\\d\\d\\b)/",
    wasParseError: "{ParsingData.NonAsciiInput(51, 195)}"
  },
  {
    input: "/^[-+]?[0-9]\\d{0,2}(\\.\\d{1,2})?%?$/",
    isPumpable: false
  },
  {
    input:
      "/(([\\w]+:)?\\/\\/)?(([\\d\\w]|%[a-fA-f\\d]{2,2})+(:([\\d\\w]|%[a-fA-f\\d]{2,2})+)?@)?([\\d\\w][-\\d\\w]{0,253}[\\d\\w]\\.)+[\\w]{2,4}(:[\\d]+)?(\\/([-+_~.\\d\\w]|%[a-fA-f\\d]{2,2})*)*(\\?(&?([-+_~.\\d\\w]|%[a-fA-f\\d]{2,2})=?)*)?(#([-+_~.\\d\\w]|%[a-fA-f\\d]{2,2})*)?/",
    isPumpable: false
  },
  {
    input: "/^([^S]|S[^E]|SE[^P]).*/",
    isPumpable: false
  },
  {
    input:
      "/^((([!#$%&'*+\\-\\/=?^_`{|}~\\w])|([!#$%&'*+\\-\\/=?^_`{|}~\\w][!#$%&'*+\\-\\/=?^_`{|}~\\.\\w]{0,}[!#$%&'*+\\-\\/=?^_`{|}~\\w]))[@]\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*)$/",
    isPumpable: false
  },
  {
    input: "/(^\\([0]\\d{2}\\))(\\d{6,7}$)/",
    isPumpable: false
  },
  {
    input: "/(^\\d{2}\\.\\d{3}\\.\\d{3}\\/\\d{4}\\-\\d{2}$)/",
    isPumpable: false
  },
  {
    input: "/(^\\d{5}\\-\\d{3}$)/",
    isPumpable: false
  },
  {
    input:
      "/(([01][\\.\\- +]\\(\\d{3}\\)[\\.\\- +]?)|([01][\\.\\- +]\\d{3}[\\.\\- +])|(\\(\\d{3}\\) ?)|(\\d{3}[- \\.]))?\\d{3}[- \\.]\\d{4}/",
    isPumpable: false
  },
  {
    input:
      "/^([-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?[r]?|[-+]?((\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?)?[i]|[-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?[r]?[-+]((\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?)?[i])$/",
    isPumpable: false
  },
  {
    input:
      "/^((?<r>([-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?[r]?))|(?<i>([-+]?((\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?)?[i]))|(?<r>([-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?[r]?))(?<i>([-+]((\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?)?[i])))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(4, 60)}"
  },
  {
    input: "/^([-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+))$/",
    isPumpable: false
  },
  {
    input: "/^([-+]?(\\d+\\.?\\d*|\\d*\\.?\\d+)([Ee][-+]?[0-2]?\\d{1,2})?)$/",
    isPumpable: false
  },
  {
    input: "/^(?(^00000(|-0000))|(\\d{5}(|-\\d{4})))$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 40)}"
  },
  {
    input: "/^((\\d{1,3}(,\\d{3})*)|(\\d{1,3}))$/",
    isPumpable: false
  },
  {
    input: "/@{2}((\\S)+)@{2}/",
    isPumpable: false
  },
  {
    input: '/^([a-zA-Z]:\\\\)?[^\\x00-\\x1F"<>\\|:\\*\\?/]+\\.[a-zA-Z]{3,4}$/',
    isPumpable: false
  },
  {
    input:
      "/(^0[1-9]\\d{1}\\s\\d{4}\\s?\\d{4}$)|(^0[1-9]\\d{2}\\s\\d{3}\\s?\\d{4}$)|(^0[1-9]\\d{2}\\s\\d{4}\\s?\\d{3}$)|(^0[1-9]\\d{3}\\s\\d{3}\\s?\\d{2}$)|(^0[1-9]\\d{3}\\s\\d{3}\\s?\\d{3}$)|(^0[1-9]\\d{4}\\s\\d{3}\\s?\\d{2}$)|(^0[1-9]\\d{4}\\s\\d{2}\\s?\\d{3}$)|(^0[1-9]\\d{4}\\s\\d{2}\\s?\\d{2}$)/",
    isPumpable: false
  },
  {
    input: '/"\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}"/',
    isPumpable: false
  },
  {
    input: "/[DJF]{1}[0-9]{5,8}/",
    isPumpable: false
  },
  {
    input: "/^[+-]?\\d+(\\,\\d{3})*\\.?\\d*\\%?$/",
    isPumpable: false
  },
  {
    input: "/^\\d{3}-\\d{7}[0-6]{1}$/",
    isPumpable: false
  },
  {
    input: "/(^0.*[1-9]*)|(^860+)|(^8613)|(\\D)|([0-9])/",
    isPumpable: false
  },
  {
    input:
      "/(^4\\d{12}$)|(^4[0-8]\\d{14}$)|(^(49)[^013]\\d{13}$)|(^(49030)[0-1]\\d{10}$)|(^(49033)[0-4]\\d{10}$)|(^(49110)[^12]\\d{10}$)|(^(49117)[0-3]\\d{10}$)|(^(49118)[^0-2]\\d{10}$)|(^(493)[^6]\\d{12}$)/",
    isPumpable: false
  },
  {
    input:
      "/(^(5[0678])\\d{11,18}$)|(^(6[^0357])\\d{11,18}$)|(^(601)[^1]\\d{9,16}$)|(^(6011)\\d{9,11}$)|(^(6011)\\d{13,16}$)|(^(65)\\d{11,13}$)|(^(65)\\d{15,18}$)|(^(633)[^34](\\d{9,16}$))|(^(6333)[0-4](\\d{8,10}$))|(^(6333)[0-4](\\d{12}$))|(^(6333)[0-4](\\d{15}$))|(^(6333)[5-9](\\d{8,10}$))|(^(6333)[5-9](\\d{12}$))|(^(6333)[5-9](\\d{15}$))|(^(6334)[0-4](\\d{8,10}$))|(^(6334)[0-4](\\d{12}$))|(^(6334)[0-4](\\d{15}$))|(^(67)[^(59)](\\d{9,16}$))|(^(6759)](\\d{9,11}$))|(^(6759)](\\d{13}$))|(^(6759)](\\d{16}$))|(^(67)[^(67)](\\d{9,16}$))|(^(6767)](\\d{9,11}$))|(^(6767)](\\d{13}$))|(^(6767)](\\d{16}$))/",
    isPumpable: false
  },
  {
    input: "/^5[1-5]\\d{14}$/",
    isPumpable: false
  },
  {
    input: "/(^(6011)\\d{12}$)|(^(65)\\d{14}$)/",
    isPumpable: false
  },
  {
    input: "/(^3[47])((\\d{11}$)|(\\d{13}$))/",
    isPumpable: false
  },
  {
    input: "/(^(6334)[5-9](\\d{11}$|\\d{13,14}$))|(^(6767)(\\d{12}$|\\d{14,15}$))/",
    isPumpable: false
  },
  {
    input:
      "/(^(49030)[2-9](\\d{10}$|\\d{12,13}$))|(^(49033)[5-9](\\d{10}$|\\d{12,13}$))|(^(49110)[1-2](\\d{10}$|\\d{12,13}$))|(^(49117)[4-9](\\d{10}$|\\d{12,13}$))|(^(49118)[0-2](\\d{10}$|\\d{12,13}$))|(^(4936)(\\d{12}$|\\d{14,15}$))|(^(564182)(\\d{11}$|\\d{13,14}$))|(^(6333)[0-4](\\d{11}$|\\d{13,14}$))|(^(6759)(\\d{12}$|\\d{14,15}$))/",
    isPumpable: false
  },
  {
    input: "/(^(352)[8-9](\\d{11}$|\\d{12}$))|(^(35)[3-8](\\d{12}$|\\d{13}$))/",
    isPumpable: false
  },
  {
    input: "/(^(30)[0-5]\\d{11}$)|(^(36)\\d{12}$)|(^(38[0-8])\\d{11}$)/",
    isPumpable: false
  },
  {
    input: "/^(389)[0-9]{11}$/",
    isPumpable: false
  },
  {
    input: "/(^(2014)|^(2149))\\d{11}$/",
    isPumpable: false
  },
  {
    input:
      "/(^(5[0678])\\d{11,18}$)|(^(6[^05])\\d{11,18}$)|(^(601)[^1]\\d{9,16}$)|(^(6011)\\d{9,11}$)|(^(6011)\\d{13,16}$)|(^(65)\\d{11,13}$)|(^(65)\\d{15,18}$)|(^(49030)[2-9](\\d{10}$|\\d{12,13}$))|(^(49033)[5-9](\\d{10}$|\\d{12,13}$))|(^(49110)[1-2](\\d{10}$|\\d{12,13}$))|(^(49117)[4-9](\\d{10}$|\\d{12,13}$))|(^(49118)[0-2](\\d{10}$|\\d{12,13}$))|(^(4936)(\\d{12}$|\\d{14,15}$))/",
    isPumpable: false
  },
  {
    input:
      "/^([A-Z]{1}[a-z]{1,})$|^([A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,})$|^([A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,}\\040[A-Z]{1}[a-z]{1,})$|^$/",
    isPumpable: false
  },
  {
    input:
      "/([a-zA-Z0-9\\_\\-\\.]+[a-zA-Z0-9\\_\\-\\.]+[a-zA-Z0-9\\_\\-\\.]+)+@([a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)+(\\.[a-zA-z0-9][a-zA-z0-9][a-zA-z0-9]*)(\\.[a-zA-z0-9]+)*/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "aa-",
    pumpable: "A---",
    suffix: ""
  },
  {
    input: '/("((\\\\.)|[^\\\\"])*")/',
    isPumpable: false
  },
  {
    input: "/('((\\\\.)|[^\\\\'])*')/",
    isPumpable: false
  },
  {
    input: "/^((\\$?\\-?)|(\\-?\\$?))([0-9]{1,3},([0-9]{3},)*[0-9]{3}|[0-9]+)?(\\.[0-9]*)?$/",
    isPumpable: false
  },
  {
    input: "/^((\\.)?([a-zA-Z0-9_-]?)(\\.)?([a-zA-Z0-9_-]?)(\\.)?)+$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "",
    pumpable: ".",
    suffix: "!"
  },
  {
    input:
      "/(^([0-9]|[0-1][0-9]|[2][0-3]):([0-5][0-9])(\\s{0,1})([AM|PM|am|pm]{2,2})$)|(^([0-9]|[1][0-9]|[2][0-3])(\\s{0,1})([AM|PM|am|pm]{2,2})$)/",
    isPumpable: false
  },
  {
    input: "/^([A-Z]{0,3})?[ ]?([0-9]{1,3},([0-9]{3},)*[0-9]{3}|[0-9]+)(.[0-9][0-9])?$/",
    isPumpable: false
  },
  {
    input:
      "/(?:youtu\\.be\\/|youtube.com\\/(?:watch\\?.*\\bv=|embed\\/|v\\/)|ytimg\\.com\\/vi\\/)(.+?)(?:[^-a-zA-Z0-9]|$)/",
    isPumpable: false
  },
  {
    input: "/(\\s|\\n|^)(\\w+:\\/\\/[^\\s\\n]+)/",
    isPumpable: false
  },
  {
    input:
      "/^(?<type>(\\w+(\\.?\\w+)+))\\s*,\\s*(?<assembly>[\\w\\.]+)(,\\s?Version=(?<version>\\d+\\.\\d+\\.\\d+\\.\\d+))?(,\\s?Culture=(?<culture>\\w+))?(,\\s?PublicKeyToken=(?<token>\\w+))?$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(3, 60)}"
  },
  {
    input:
      "/^([a-zA-Z]+):\\/\\/([a-zA-Z0-9_\\-]+)((\\.[a-zA-Z0-9_\\-]+|[0-9]{1,3})+)\\.([a-zA-Z]{2,6}|[0-9]{1,3})((:[0-9]+)?)((\\/[a-zA-Z0-9_\\-,.;=%]*)*)((\\?[a-zA-Z0-9_\\-,.;=&%]*)?)$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "a://a0",
    pumpable: "00",
    suffix: ""
  },
  {
    input: "/^\\$((\\d{1})\\,\\d{1,3}(\\,\\d{3}))|(\\d{1,3}(\\,\\d{3}))|(\\d{1,3})?$/",
    isPumpable: false
  },
  {
    input: "/^(100(?:\\.0{1,2})?|0*?\\.\\d{1,2}|\\d{1,2}(?:\\.\\d{1,2})?)$/",
    isPumpable: false
  },
  {
    input:
      "/^((http|https|ftp)\\:\\/\\/)?([a-zA-Z0-9\\.\\-]+(\\:[a-zA-Z0-9\\.&%\\$\\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|([a-zA-Z0-9\\-]+\\.)*[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,4})(\\:[0-9]+)*(\\/[^\\/][a-zA-Z0-9\\.\\,\\?\\'\\\\/\\+&%\\$#\\=~_\\-]*)*$/",
    isPumpable: true,
    isVulnerable: true,
    prefix: "http://a.aA",
    pumpable: "/!/0",
    suffix: "!"
  },
  {
    input:
      "/(?!00[02-5]|099|213|269|34[358]|353|419|42[89]|51[789]|529|53[36]|552|5[67]8|5[78]9|621|6[348]2|6[46]3|659|69[4-9]|7[034]2|709|715|771|81[789]|8[3469]9|8[4568]8|8[6-9]6|8[68]7|9[02]9|987)\\d{5}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input:
      "/(?!00[02-5]|099|213|269|34[358]|353|419|42[89]|51[789]|529|53[36]|552|5[67]8|5[78]9|621|6[348]2|6[46]3|659|69[4-9]|7[034]2|709|715|771|81[789]|8[3469]9|8[4568]8|8[6-9]6|8[68]7|9[02]9|987)\\d{5}(-\\d{4}){0,1}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: '/^(?!^(PRN|AUX|CLOCK\\$|NUL|CON|COM\\d|LPT\\d|\\..*)(\\..+)?$)[^\\x00-\\x1f\\\\?*:\\";|/]+$/',
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/[\\(]{1,}((?:(?<t>[^\\(]*))[)]{1,})/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(14, 60)}"
  },
  {
    input: "/[\\(]{1,}[^)]*[)]{1,}/",
    isPumpable: false
  },
  {
    input:
      "/^\\d{4}[\\-\\/\\s]?((((0[13578])|(1[02]))[\\-\\/\\s]?(([0-2][0-9])|(3[01])))|(((0[469])|(11))[\\-\\/\\s]?(([0-2][0-9])|(30)))|(02[\\-\\/\\s]?[0-2][0-9]))$/",
    isPumpable: false
  },
  {
    input: "/^(FR)?\\s?[A-Z0-9-[IO]]{2}[0-9]{9}$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^(?!0{1})\\d{6}/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^(\\(\\d{3}\\)[- ]?|\\d{3}[- ])?\\d{3}[- ]\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/(^\\d*\\.?\\d*[0-9]+\\d*$)|(^[0-9]+\\d*\\.\\d*$)/",
    isPumpable: false
  },
  {
    input:
      "/(^[A-Z]{1,2}[0-9]{1,}:{1}[A-Z]{1,2}[0-9]{1,}$)|(^\\$(([A-Z])|([a-z])){1,2}([0-9]){1,}:{1}\\$(([A-Z])|([a-z])){1,2}([0-9]){1,}$)|(^\\$(([A-Z])|([a-z])){1,2}(\\$){1}([0-9]){1,}:{1}\\$(([A-Z])|([a-z])){1,2}(\\$){1}([0-9]){1,}$)/",
    isPumpable: false
  },
  {
    input: "/^([1-9]\\d*|0)(([.,]\\d*[1-9])?)$/",
    isPumpable: false
  },
  {
    input: "/^(?:\\d+,\\s*)*\\d+\\s*$/",
    isPumpable: false
  },
  {
    input:
      "/^((\\+?(?<CountryCode>1)\\s(?<AreaCode>[2-9][0-8][0-9])\\s)|((?<AreaCode>[2-9][0-8][0-9])\\s))?(?<ExchangeCode>[2-9][0-9][0-9])\\s(?<StationCode>[0-9][0-9][0-9][0-9])$/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(8, 60)}"
  },
  {
    input:
      "/\\x26(?!((amp\\x3B)|(nbsp\\x3B)|(lt\\x3B)|(gt\\x3B)|(copy\\x3B)|(reg\\x3B)|(cent\\x3B)|(deg\\x3B)|(deg\\x3B)|(micro\\x3B)|(middot\\x3B)|(not\\x3B)|(para\\x3B)|(plusmn\\x3B)|(pound\\x3B)|(raquo\\x3B)|(sect\\x3B)|(yen\\x3B)|([\\x23][0-9]{1,3}\\x3B)|(lsquo\\x3B)|(rsquo\\x3B)|(sbquo\\x3B)|(ldquo\\x3B)|(rdquo\\x3B)|(bdquo\\x3B)|(dagger\\x3B)|(Dagger\\x3B)|(permil\\x3B)|(lsaquo\\x3B)|(rsaquo\\x3B)|(spades\\x3B)|(clubs\\x3B)|(hearts\\x3B)|(diams\\x3B)|(oline\\x3B)|(larr\\x3B)|(uarr\\x3B)|(rarr\\x3B)|(darr\\x3B)|(trade\\x3B)|([\\x23]x2122\\x3B)|(quot\\x3B)|(frasl\\x3B)|(ndash\\x3B)|(mdash\\x3B)|(iexcl\\x3B)|(cent\\x3B)|(curren\\x3B)|(brvbar\\x3B)|(brvbar\\x3B)|(uml\\x3B)|(die\\x3B)|(ordf\\x3B)|(laquo\\x3B)|(not\\x3B)|(shy\\x3B)|(macr\\x3B)|(hibar\\x3B)|(sup2\\x3B)|(sup3\\x3B)|(acute\\x3B)|(micro\\x3B)|(cedil\\x3B)|(sup1\\x3B)|(ordm\\x3B)|(raquo\\x3B)|(frac14\\x3B)|(frac12\\x3B)|(frac34\\x3B)|(iquest\\x3B)|(Agrave\\x3B)|(Aacute\\x3B)|(Acirc\\x3B)|(Atilde\\x3B)|(Auml\\x3B)|(Aring\\x3B)|(AElig\\x3B)|(Ccedil\\x3B)|(Egrave\\x3B)|(Eacute\\x3B)|(Ecirc\\x3B)|(Euml\\x3B)|(Igrave\\x3B)|(Iacute\\x3B)|(Icirc\\x3B)|(Iuml\\x3B)|(ETH\\x3B)|(Ntilde\\x3B)|(Ograve\\x3B)|(Oacute\\x3B)|(Ocirc\\x3B)|(Otilde\\x3B)|(Ouml\\x3B)|(times\\x3B)|(Oslash\\x3B)|(Ugrave\\x3B)|(Uacute\\x3B)|(Ucirc\\x3B)|(Uuml\\x3B)|(Yacute\\x3B)|(THORN\\x3B)|(szlig\\x3B)|(agrave\\x3B)|(aacute\\x3B)|(acirc\\x3B)|(atilde\\x3B)|(auml\\x3B)|(aring\\x3B)|(aelig\\x3B)|(ccedil\\x3B)|(egrave\\x3B)|(eacute\\x3B)|(ecirc\\x3B)|(euml\\x3B)|(igrave\\x3B)|(iacute\\x3B)|(icirc\\x3B)|(iuml\\x3B)|(eth\\x3B)|(ntilde\\x3B)|(ograve\\x3B)|(oacute\\x3B)|(ocirc\\x3B)|(otilde\\x3B)|(ouml\\x3B)|(divide\\x3B)|(oslash\\x3B)|(ugrave\\x3B)|(uacute\\x3B)|(ucirc\\x3B)|(uuml\\x3B)|(yacute\\x3B)|(thorn\\x3B)|(yuml\\x3B)|(Alpha\\x3B)|(Alpha\\x3B)|(Beta\\x3B)|(beta\\x3B)|(Gamma\\x3B)|(gamma\\x3B)|(Delta\\x3B)|(delta\\x3B)|(Epsilon\\x3B)|(epsilon\\x3B)|(Zeta\\x3B)|(zeta\\x3B)|(Eta\\x3B)|(eta\\x3B)|(Iota\\x3B)|(iota\\x3B)|(Kappa\\x3B)|(kappa\\x3B)|(Lambda\\x3B)|(lambda\\x3B)|(Mu\\x3B)|(mu\\x3B)|(Nu\\x3B)|(nu\\x3B)|(Xi\\x3B)|(xi\\x3B)|(Omicron\\x3B)|(omicron\\x3B)|(Pi\\x3B)|(pi\\x3B)|(Rho\\x3B)|(rho\\x3B)|(Sigma\\x3B)|(sigma\\x3B)|(Tau\\x3B)|(tau\\x3B)|(Upsilon\\x3B)|(upsilon\\x3B)|(Phi\\x3B)|(phi\\x3B)|(Chi\\x3B)|(chi\\x3B)|(Psi\\x3B)|(psi\\x3B)|(Omega\\x3B)|(omega\\x3B)))/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(4)}"
  },
  {
    input: "/([0-9]+)(?:st|nd|rd|th)/",
    isPumpable: false
  },
  {
    input: "/(?=^.{6,10}$)(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+}{\":;'?/>.<,])(?!.*\\s).*$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(0)}"
  },
  {
    input: "/[0-9]{1,2}[:|°|º][0-9]{1,2}[:|'](?:\\b[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+\\b)\"?[N|S|E|W]/",
    wasParseError: "{ParsingData.NonAsciiInput(13, 194)}"
  },
  {
    input:
      '/^([a-zA-Z]\\:|\\\\\\\\[^\\/\\\\:*?"<>|]+\\\\[^\\/\\\\:*?"<>|]+)(\\\\[^\\/\\\\:*?"<>|]+)+(\\.[^\\/\\\\:*?"<>|]+)$/',
    isPumpable: false
  },
  {
    input: "/^(?=(.*[a-z]){1,})(?=(.*[\\d]){1,})(?=(.*[\\W]){1,})(?!.*\\s).{7,30}$/",
    wasParseError: "{Nfa.UnsupportedGroupingConstruct(1)}"
  },
  {
    input: "/^\\+?\\(?\\d+\\)?(\\s|\\-|\\.)?\\d{1,3}(\\s|\\-|\\.)?\\d{4}$/",
    isPumpable: false
  },
  {
    input: "/^[[V|E|J|G]\\d\\d\\d\\d\\d\\d\\d\\d]{0,9}$/",
    wasParseError: '{Failure("lexing: empty token")}'
  },
  {
    input: "/^([1-9]\\d{3}|0[1-9]\\d{2}|00[1-9]\\d{1}|000[1-9]{1})$/",
    isPumpable: false
  },
  {
    input: "/^([\\d]*[1-9]+[\\d]*)$/",
    isPumpable: false
  },
  {
    input: "/(^(\\d{2}\\x2E\\d{3}\\x2E\\d{3}[-]\\d{1})$|^(\\d{2}\\x2E\\d{3}\\x2E\\d{3})$)/",
    isPumpable: false
  },
  {
    input:
      "/(?<email>[a-zA-Z][a-zA-Z0-9-_.]+\\@[a-zA-Z][a-zA-Z0-9-_]+\\.(?(?=[a-zA-Z]{2}\\.)([a-zA-Z0-9-_]{2}\\.[a-zA-Z0-9-_]{2})|([a-zA-Z0-9-_]{2,3})))/",
    wasParseError: "{ParsingData.UnsupportedInlineModifier(2, 60)}"
  },
  {
    input: "/^[http:\\/\\/www.|www.][\\S]+$/",
    isPumpable: false
  }
];

describe("pumpability", () => {
  it("should work", () => {
    for (let t of fromTestsTxt) {
      if (t.wasParseError) continue;
      //    it("should find " + t.input + " to be " + (t.isPumpable ? "pumpable" : "not pumpable"), () => {
      console.log("testing: " + t.input);
      try {
        let nfa = NFA.fromString(t.input);
        expect(nfa.pumpable()).to.equal(!!t.isPumpable);
      } catch (e) {
        if (/bored searching/.test(e.message)) {
          console.log("BORED");
        } else {
          throw e;
        }
      }
      //   });
    }
  });
});
