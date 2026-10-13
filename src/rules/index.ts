import { staticRules } from "./static.js";
import { deepRules } from "./deep.js";
import type { ConfigFile, RawFinding, RuleMeta } from "../types.js";

export interface RegisteredRule {
  meta: RuleMeta;
  run: import("../types.js").RuleFn;
  /** File-level checks. Run once per config, not once per server. */
  runConfig?: (config: ConfigFile) => RawFinding[];
}

export const ALL_RULES: RegisteredRule[] = [...staticRules, ...deepRules];
