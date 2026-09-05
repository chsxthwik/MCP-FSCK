import { it, expect } from "vitest";
import * as statics from "../src/rules/static.js";

it("debug internals", () => {
  const anyStatics = statics as any;
  console.log("has isUnpinnedNpm:", typeof anyStatics.isUnpinnedNpm);
  const pkg = "@some/one@1.2.3";
  const withoutScope = pkg.startsWith("@") ? pkg.slice(pkg.indexOf("/") + 1) : pkg;
  console.log("withoutScope:", JSON.stringify(withoutScope));
  console.log("regex test:", /^[^@]+@[^@]+$/.test(withoutScope));
  console.log("Object keys:", Object.keys(anyStatics).join(","));
});
