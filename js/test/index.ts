import { expect } from "chai";
import { NFA  } from "../src/nfa";
import { intersectRanges } from "../src/range";

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

describe('pumpable', () => {
  it('should find /(^\\d{1,9})+(,\\d{1,9})*$/ not pumpable', () => {
    expect(
      NFA.fromString('/(^\d{1,9})+(,\d{1,9})*$/').pumpable()
    ).to.equal(false)

    expect(
      NFA.fromString('/^(\d{1,9})+(,\d{1,9})*$/').pumpable()
    ).to.equal(true)
  })
})
