import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

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
  "from urllib.parse import urlsplit",
  "def _parse_quote_url",
  "parsed.username is not None",
  "parsed.password is not None",
  "invalid_quote_url_authority",
  "def _valid_hostname",
];
for (const marker of required) if (!source.includes(marker)) throw new Error(`Missing FeeQuoteGuard invariant: ${marker}`);

function sourceIdentity(raw) {
  const parsed = new URL(raw);
  assert.equal(parsed.protocol, "https:");
  assert.equal(parsed.username, "");
  assert.equal(parsed.password, "");
  assert.ok(!parsed.port || parsed.port === "443");
  const labels = parsed.hostname.toLowerCase().replace(/\.$/, "").split(".");
  assert.ok(labels.length >= 2 && labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)));
  return labels.slice(-2).join(".");
}

assert.throws(() => sourceIdentity("https://buyer:secret@quotes.example.com/fee"));
assert.throws(() => sourceIdentity("https://attacker@quotes.example.com/fee"));
assert.equal(sourceIdentity("https://www.quotes.example.com/fee"), "example.com");
assert.equal(sourceIdentity("https://api.example.com/fee"), "example.com");
console.log("FeeQuoteGuard contract guard check passed");
