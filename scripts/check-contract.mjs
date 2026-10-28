import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../contracts/fee_quote_guard.py", import.meta.url), "utf8");
const required = [
  "class FeeQuoteGuard(gl.Contract)",
  "def request_fee_receipt(",
  "def consume_fee_receipt(",
  "gl.vm.run_nondet_unsafe",
  "gl.nondet.web.render",
  "two_independent_registrable_domains_required",
  "action_commitment_mismatch",
  "fee_receipt_expired",
  "fee_receipt_already_used",
  "hashlib.sha256",
  "snapshot_bundle_hash",
];
for (const marker of required) if (!source.includes(marker)) throw new Error(`Missing FeeQuoteGuard invariant: ${marker}`);
console.log("FeeQuoteGuard contract guard check passed");
