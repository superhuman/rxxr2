import "source-map-support/register";
import { NFA } from "./src/nfa";
import { Stringifier } from "./src/stringifier";
import { RegExpParser } from "regexp-to-ast";

const source = process.argv[2];
const parser = new RegExpParser();
const pattern = parser.pattern(source);
const nfa = NFA.fromString(source);

console.log(Stringifier.regexp(pattern));
console.log(nfa.summarize());

console.log(nfa.decisionPoints());
console.log(nfa.pumpable());

if (process.argv[3]) {
  console.log("match: ", nfa.match(process.argv[3]));
}
