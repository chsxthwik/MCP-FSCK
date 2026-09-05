import { staticRules } from "./static.js";
import { deepRules } from "./deep.js";
import type { RuleMeta } from "../types.js";

export interface RegisteredRule {
  meta: RuleMeta;
  run: import("../types.js").RuleFn;
}

export const ALL_RULES: RegisteredRule[] = [...staticRules, ...deepRules];

export function rulesFor(scope: "static" | "deep"): RegisteredRule[] {
  return ALL_RULES.filter((r) => r.meta.scope === scope);
}
