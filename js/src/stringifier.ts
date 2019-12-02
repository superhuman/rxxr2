import { RegExpParser, BaseRegExpVisitor } from "regexp-to-ast";
import * as types from "regexp-to-ast";

export class Stringifier extends BaseRegExpVisitor {
  string: string;
  flags?: types.RegExpFlags;

  static regexp(node: types.IRegExpAST) {
    let s = new Stringifier();
    s.visit(node);
    return s.string;
  }

  constructor() {
    super();
    this.string = "";
  }

  visit(node: types.IRegExpAST) {
    super.visit(node);
  }

  visitChildren() {}

  visitPattern(node: types.RegExpPattern) {
    this.flags = node.flags;
    this.string = "/";
    this.visitDisjunction(node.value);
    this.string += "/";
    if (this.flags.global) this.string += "g";
    if (this.flags.ignoreCase) this.string += "i";
    if (this.flags.unicode) this.string += "u";
    if (this.flags.multiLine) this.string += "m";
    if (this.flags.sticky) this.string += "y";
  }

  visitDisjunction(node: types.Disjunction) {
    node.value.forEach((v, i) => {
      if (i > 0) {
        this.string += "|";
      }
      this.visit(v);
    });
  }

  visitAlternative(node: types.Alternative) {
    node.value.forEach(v => this.visit(v));
  }

  // Assertion
  visitStartAnchor(node: types.Assertion) {
    this.string += "^";
  }

  visitEndAnchor(node: types.Assertion) {
    this.string += "$";
  }

  visitWordBoundary(node: types.Assertion) {
    this.string += "\\b";
  }

  visitNonWordBoundary(node: types.Assertion) {
    this.string += "\\B";
  }

  visitLookahead(node: types.Assertion) {
    throw new Error("lookahead not yet supported");
  }

  visitNegativeLookahead(node: types.Assertion) {
    throw new Error("negative lookahead not yet supported");
  }

  visitCharacter(node: types.Character) {
    this.string += this.escape(node.value);
    if (node.quantifier) {
      this.visitQuantifier(node.quantifier);
    }
  }

  escape(string: string | number) {
    if (typeof string === "number") {
      string = String.fromCharCode(string);
    }

    string = string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    string = string.replace(/\s/g, m => {
      return `\\u${m
        .charCodeAt(0)
        .toString(16)
        .padStart(4, "0")}`;
    });

    return string;
  }

  visitSet(node: types.Set) {
    let string = "[";
    if (node.complement) {
      string += "^";
    }
    node.value.forEach(v => {
      if (typeof v === "number") {
        string += this.escape(v);
      } else {
        string += this.escape(v.from) + "-" + this.escape(v.to);
      }
    });
    string += "]";
    if (string === "[^\\x0a\\x0d\\x2028\\x2029]") {
      string = ".";
    }
    this.string += string;
    if (node.quantifier) {
      this.visitQuantifier(node.quantifier);
    }
  }

  visitGroup(node: types.Group) {
    this.string += "(";
    if (!node.capturing) {
      this.string += "?:";
    }
    this.visitDisjunction(node.value);
    this.string += ")";
    if (node.quantifier) {
      this.visitQuantifier(node.quantifier);
    }
  }

  visitGroupBackReference(node: types.GroupBackReference) {
    throw new Error("backreferences not yet supported");
  }

  visitQuantifier(node: types.Quantifier) {
    if (node.atLeast === 0 && node.atMost === Infinity) {
      this.string += "*";
    } else if (node.atLeast === 1 && node.atMost === Infinity) {
      this.string += "+";
    } else if (node.atLeast === 0 && node.atMost === 1) {
      this.string += "?";
    } else if (node.atLeast === 1 && node.atMost === 1) {
      return;
    } else if (node.atMost === Infinity) {
      this.string += `{${node.atLeast},}`;
    } else if (node.atMost === node.atLeast) {
      this.string += `{${node.atLeast}}`;
    } else {
      this.string += `{${node.atLeast},${node.atMost}}`;
    }
    if (!node.greedy) {
      this.string += "?";
    }
  }
}
