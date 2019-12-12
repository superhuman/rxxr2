
// in general a NFA with ambiguous transitions can go from 
// p : "a" -> q_0 .... q_n 
// where the result is not a single state, but a set of states.

import { RegExpParser, BaseRegExpVisitor } from "regexp-to-ast";
import * as types from "regexp-to-ast";
import { Stringifier } from "./stringifier";
import { Range, Ranges, intersectRanges, unionRanges, invertRanges, resortRanges } from "./range"

interface NFACondition {
  toString(): string;
  matches(string: string, i: number): number;
  generateRanges(string: string): Ranges;
}

const Epsilon = {
  toString() {
    return "𝜀";
  },
  matches(string: string, i: number) {
    return 0;
  },
  generateRanges() {
    return [{ from: 0, to: 0x10ffff }];
  }
};

const StartAnchor = {
  toString() {
    return "^";
  },
  matches(string: string, i: number) {
    if (i === 0) {
      return 0;
    }
    return -1;
  },

  generateRanges(string: string) {
    if (string.length === 0) {
      return [{ from: 0, to: 0x10ffff }];
    }
    return [];
  }
};

const EndAnchor = {
  toString() {
    return "$";
  },
  matches(string: string, i: number) {
    if (i === string.length) {
      return 0;
    }
    return -1;
  },

  generateRanges() {
    return [];
  }
};

const WordBoundary = {
  toString() {
    return "\\b";
  },

  matches(string: string, i: number): number {
    if (i === 0 && /\w/.test(string[i])) {
      return 0;
    }
    if (i === string.length && /\w/.test(string[i - 1])) {
      return 0;
    }
    if (/\w/.test(string[i - 1]) !== /\w/.test(string[i])) {
      return 0;
    }
    return -1;
  },

  generateRanges() {
    // TODO
    return [];
  }
};

const GroupBackReference = {
  toString() {
    return "\\B";
  },

  matches(string: string, i: number): number {
    throw new Error("unsupported Group Back Reference");
  },

  generateRanges() {
    // TODO
    return [];
  }
};

const NonWordBoundary = {
  toString() {
    return "\\B";
  },

  matches(string: string, i: number): number {
    let inverse = WordBoundary.matches(string, i);
    if (inverse === 0) {
      return -1;
    }
    return 0;
  },

  generateRanges() {
    // TODO
    return [];
  }
};

class CharSet {
  sets: Range[];

  constructor(sets: Range[], complement: boolean) {
    this.sets = resortRanges(sets);

    if (complement) {
      this.sets = invertRanges(this.sets);
    }
  }

  toString(): string {
    let escape = (string: string) => {
      return string.replace(/\W/gu, m => {
        return `\\u${m
          .charCodeAt(0)
          .toString(16)
          .padStart(4, "0")}`;
      });
    };

    let ret = this.sets
      .map(c => {
        if (c.from === c.to) {
          return escape(String.fromCharCode(c.from));
        }
        return escape(String.fromCharCode(c.from)) + "-" + escape(String.fromCharCode(c.to));
      })
      .join("");

    if (ret.length > 1) ret = `[${ret}]`;

    return ret;
  }

  matches(string: string, i: number): number {
    let c = string.charCodeAt(i);
    let match = false;
    for (let { from, to } of this.sets) {
      if (c >= from && c <= to) {
        match = true;
      }
    }

    if (match) {
      return 1;
    }
    return -1;
  }

  generateRanges() {
    return this.sets;
  }
}

interface NFATransition {
  condition: NFACondition;
  to: number;
}

interface NFAState {
  id: number;
  transitions: NFATransition[];
  accepting: boolean;
}

export class NFA {
  states: { [id: number]: NFAState };
  stateId: number;

  static fromString(source: string) {
    let parser = new RegExpParser();
    let pattern = parser.pattern(source);
    return new NFA(pattern);
  }

  constructor(pattern: types.RegExpPattern) {
    this.states = {};
    this.stateId = -1;
    this.newState();
    this.states[-1].accepting = true;
    this.newState();

    let visitor = new NFAConstructor(this);
    visitor.visit(pattern);

    // Simplify by removing Epsilon transitions
    Object.values(this.states).forEach(state => {
      let transitions = state.transitions;
      let seenStates: { [id: number]: boolean } = {};
      state.transitions = [];
      while (transitions[0]) {
        let transition = transitions.shift()!;
        if (transition.condition !== Epsilon) {
          state.transitions.push({ to: transition.to, condition: transition.condition });
          continue;
        }
        if (seenStates[transition.to]) {
          continue;
        }
        if (this.states[transition.to].accepting) {
          state.accepting = true;
        }
        seenStates[transition.to] = true;
        transitions.unshift(...this.states[transition.to].transitions);
      }
    });

    // simplify the NFA by merging identical states
    let jsonToStateID: { [json: string]: number } = {};
    let idMap: { [id: number]: number } = {};
    for (let state of Object.values(this.states)) {
      let json = JSON.stringify({ transitions: state.transitions, accepting: state.accepting });
      if (jsonToStateID[json] == null) {
        jsonToStateID[json] = state.id;
      }
      idMap[state.id] = jsonToStateID[json];
    }

    for (let state of Object.values(this.states)) {
      for (let transition of state.transitions) {
        transition.to = idMap[transition.to];
      }
    }

    // mark unused states to hide them from output
    let states = [this.states[0]];
    let usedStates: { [id: number]: boolean } = { 0: true };

    while (states.length) {
      let state = states.shift()!;
      usedStates[state.id] = true;
      state.transitions.forEach(transition => {
        if (!usedStates[transition.to]) {
          usedStates[transition.to] = true;
          states.push(this.states[transition.to]);
        }
      });
    }

    for (let id in this.states) {
      if (!usedStates[id]) {
        delete this.states[id];
      }
    }
  }

  match(string: string): boolean {
    for (let i = 0; i < string.length; i++) {
      if (this.matchState(string, i, this.states[0])) {
        return true;
      }
    }
    return false;
  }

  matchState(string: string, i: number, state: NFAState): boolean {
    if (state.accepting) {
      return true;
    }
    if (i > string.length) {
      return false;
    }

    for (let transition of state.transitions) {
      let consume = transition.condition.matches(string, i);
      if (consume > -1) {
        if (this.matchState(string, i + consume, this.states[transition.to])) {
          return true;
        }
      }
    }
    return false;
  }

  decisionPoints() {
    return Object.values(this.states).filter(state => {
      for (let a of state.transitions) {
        if (!(a.condition instanceof CharSet)) {
          continue;
        }
        for (let b of state.transitions) {
          if (a === b) {
            continue;
          }
          if (!(b.condition instanceof CharSet)) {
            continue;
          }

          if (intersectRanges(a.condition.sets, b.condition.sets).length) {
            return true;
          }
        }
      }

      return false;
    });
  }

  powerNfa() {
    let powerNfa: {
      states: { [id: number]: number[] };
      transitions: { condition: string; to: number }[];
    } = { states: { 0: [0] }, transitions: [] };
  }

  pumpable() {
    let states = this.decisionPoints();

    for (let state of states) {
      let seen = {};

      for (let transition of state.transitions) {
        let str = this.findTwoPathsTo(state.id, this.states[state.id], this.states[state.id], seen, "");
        if (str != null) {
          console.log("PUMPABLE: " + state.id + ": " + str);
          let prefix = state.id === 0 ? "" : this.findPathTo(state.id, [0], "");
          let suffix = state.accepting ? undefined : this.findPathToFail([state.id], "");
          if (str != null && prefix != null && suffix != null) {
            console.log("VULNERABLE: " + state.id + ": " + prefix + "(" + str + ")*" + suffix);
          }
          return true;
        }
      }
    }
    return false;
  }

  findPathTo(destination: number, path: number[], input: string): string | undefined {
    let state = this.states[path[path.length - 1]];

    for (let transition of state.transitions) {
      if (transition.to === destination) {
        return input + this.getGoodCharacterFromRanges(transition.condition.generateRanges(input));
      } else if (!path.includes(transition.to)) {
        let result = this.findPathTo(
          destination,
          path.concat([transition.to]),
          input + this.getGoodCharacterFromRanges(transition.condition.generateRanges(input))
        );
        if (result != null) {
          return result;
        }
      }
    }
  }

  findTwoPathsTo(
    destination: number,
    state1: NFAState,
    state2: NFAState,
    seen: { [key: string]: boolean },
    input: string
  ): string | undefined {
    if (Object.keys(seen).length > 10000) {
      throw new Error("got bored searching after 10000");
    }
    if (state1.id > state2.id) {
      let t = state1;
      state1 = state2;
      state2 = t;
    }
    for (let tid1 in state1.transitions) {
      let transition1 = state1.transitions[tid1];
      let ranges1 = transition1.condition.generateRanges(input);
      for (let tid2 in state2.transitions) {
        let transition2 = state2.transitions[tid2];
        let ranges2 = transition2.condition.generateRanges(input);

        let inCommon = intersectRanges(ranges1, ranges2);

        if (inCommon.length) {
          if (state1.id === destination && state1.id === state2.id && tid1 === tid2) {
            continue;
          }

          if (transition1.to === destination && transition2.to === destination) {
            return input + this.getGoodCharacterFromRanges(inCommon);
          }

          let key = state1.id + ":" + tid1 + "-" + state2.id + ":" + tid2;
          let result;
          if (!seen[key]) {
            seen[key] = true;

            result = this.findTwoPathsTo(
              destination,
              this.states[transition1.to],
              this.states[transition2.to],
              seen,
              input + this.getGoodCharacterFromRanges(inCommon)
            );
          }

          if (result != null) {
            return result;
          }
        }
      }
    }
  }

  findPathToFail(path: number[], input: string): string | undefined {
    let state = this.states[path[path.length - 1]];

    if (state.accepting) {
      return;
    }

    let ranges: Ranges = [];

    for (let transition of state.transitions) {
      ranges = unionRanges(ranges, transition.condition.generateRanges(input));
    }

    let failTransitions = intersectRanges(ranges, [{ from: 0, to: 0xffff }]);
    if (failTransitions.length) {
      return input + this.getGoodCharacterFromRanges(failTransitions);
    }

    for (let transition of state.transitions) {
      if (!path.includes(transition.to)) {
        let result = this.findPathToFail(
          path.concat([transition.to]),
          input + this.getGoodCharacterFromRanges(transition.condition.generateRanges(input))
        );
        if (result != null) {
          return result;
        }
      }
    }
  }

  reachableNodes() {
    let reachableSets = { "0": { states: [0], input: "" } };

    while (true) {
      for (let { states, input } of Object.values(reachableSets)) {
        let lastState = this.states[states.length - 1].id;
      }
    }
  }

  getGoodCharacterFromRanges(ranges: Range[]) {
    let printable = [
      { from: 48, to: 57 },
      { from: 65, to: 90 },
      { from: 95, to: 95 },
      { from: 97, to: 122 }
    ];

    let nice = intersectRanges(printable, ranges);
    if (nice.length > 0) {
      return String.fromCharCode(nice[0].from);
    }
    return String.fromCharCode(ranges[0].from);
  }

  newState() {
    let state = { id: this.stateId++, transitions: [], accepting: false };
    this.states[state.id] = state;
    return state;
  }

  addTransition(state: NFAState, condition: NFACondition, target: NFAState) {
    state.transitions.push({ condition, to: target.id });
  }

  summarize() {
    let ret = "";
    Object.values(this.states).forEach((state: NFAState) => {
      if (state.accepting) {
        ret += `${state.id} [accepting]\n`;
      }
      state.transitions.forEach(transition => {
        ret += `${state.id}: ${transition.condition.toString()} -> ${transition.to}\n`;
      });
      if (state.transitions.length === 0 && !state.accepting) {
        ret += `${state.id} [error]\n`;
      }
    });
    return ret;
  }
}

class NFAConstructor {
  nfa: NFA;
  flags?: types.RegExpFlags;

  constructor(nfa: NFA) {
    this.nfa = nfa;
  }

  charSet(input: (number | types.Range)[], complement: boolean): CharSet {
    // TODO: case-insensitivity, multiline, flag-handling!
    if (typeof input === "number") {
      input = [input];
    }
    return new CharSet(
      input.map(c => {
        if (typeof c === "number") {
          return { from: c, to: c };
        }
        return c;
      }),
      complement
    );
  }

  visit(node: types.RegExpPattern) {
    this.flags = node.flags;
    this.visitPattern(node);
  }

  visitPattern(node: types.RegExpPattern) {
    this.visitDisjunction(node.value, this.nfa.states[0], this.nfa.states[-1]);
  }

  visitDisjunction(node: types.Disjunction, from: NFAState, to: NFAState) {
    node.value.forEach(node => {
      this.visitAlternative(node, from, to);
    });
  }

  visitAlternative(node: types.Alternative, from: NFAState, to: NFAState) {
    if (node.value.length === 0) {
      this.nfa.addTransition(from, Epsilon, to);
      return;
    }

    node.value.forEach((n, i) => {
      let toState = i === node.value.length - 1 ? to : this.nfa.newState();

      this.visitTerm(n, from, toState);
      from = toState;
    });
  }

  visitTerm(node: types.Term, from: NFAState, to: NFAState) {
    switch (node.type) {
      case "Character":
        this.quantify(node.quantifier, from, to, (from, to) => {
          this.nfa.addTransition(from, this.charSet([{ from: node.value, to: node.value }], false), to);
        });
        break;
      case "Set":
        this.quantify(node.quantifier, from, to, (from, to) => {
          this.nfa.addTransition(from, this.charSet(node.value, node.complement), to);
        });
        break;

      case "Group":
        this.quantify(node.quantifier, from, to, (from, to) => {
          this.visitDisjunction(node.value, from, to);
        });
        break;

      case "EndAnchor":
        this.nfa.addTransition(from, Epsilon, to);

        break;
      case "StartAnchor":
        this.nfa.addTransition(from, Epsilon, to);
        break;

      case "WordBoundary":
        this.nfa.addTransition(from, Epsilon, to);
        break;

      case "NonWordBoundary":
        this.nfa.addTransition(from, Epsilon, to);
        break;

      case "GroupBackReference":
        this.nfa.addTransition(from, Epsilon, to);
        break;

      default:
        throw new Error(`unsupported ${node.type}`);
    }
  }

  quantify(
    quantifier: types.Quantifier | undefined,
    from: NFAState,
    to: NFAState,
    connector: (from: NFAState, to: NFAState) => void
  ) {
    let atMost = quantifier ? quantifier.atMost : 1;
    let atLeast = quantifier ? quantifier.atLeast : 1;

    // TODO: greediness

    if (atMost < atLeast) {
      throw new Error(`numbers out of order in {} quantifier: {${atLeast},${atMost}}`);
    }

    while (atLeast > 0) {
      let nextState = this.nfa.newState();
      connector(from, nextState);
      from = nextState;
      atLeast--;
      atMost--;
    }

    if (atMost === Infinity) {
      let loopState = this.nfa.newState();
      this.nfa.addTransition(from, Epsilon, loopState);
      connector(loopState, loopState);
      this.nfa.addTransition(loopState, Epsilon, to);
      return;
    }

    let finalStates = [from];
    while (atMost > 0) {
      let nextState = this.nfa.newState();
      connector(from, nextState);
      finalStates.push(nextState);
      from = nextState;
      atMost--;
    }
    finalStates.forEach(from => this.nfa.addTransition(from, Epsilon, to));
  }
}
