# FeeQuoteGuard for GenLayer

FeeQuoteGuard is an append-only GenLayer Intelligent Contract for agents that need an independently checked fee ceiling before they execute a paid action. It produces a `fqr_*` receipt bound to one canonical action, currency, cap, expiry, source provenance, and validator-agreed web snapshots.

## Why this is a reusable primitive

An agent can request a receipt with an action description, a maximum charge, a bounded expiry, and two to four public quote sources. Validators independently render every source and compare the action match, currency match, quoted fee, source identities, source hashes, and snapshot-bundle commitment. Ambiguous or unavailable evidence is inconclusive rather than silently approved.

The requester may consume an approved receipt once only. Consumption re-derives the canonical action hash, checks the stored expiry and fee ceiling, and emits a durable consumption hash. Other contracts or agent executors can read the receipt before performing the external paid action.

## Contract API

```python
request_fee_receipt(action, quote_currency, max_fee_units, expires_at, quote_urls) -> str
consume_fee_receipt(receipt_id, action, charged_fee_units) -> str
get_receipt(receipt_id) -> str
get_latest_receipt_id() -> str
get_receipt_count() -> u64
list_receipt_ids() -> str
```

## Safety properties

- Canonical SHA-256 commitments bind the reviewed action and source manifest.
- Two independent registrable domains are mandatory; `www` and sibling subdomains cannot count twice.
- Every validator recomputes rendered-source snapshot hashes and consequential decision fields.
- Fees must be positive, within the cap, and consumed before expiry.
- Receipts are requester-bound and replay protected.

## Local verification

```bash
node scripts/check-contract.mjs
```

## Studio deployment

- Contract: [`0x9f797016b31727AEac2548B1d1daB9F6eA32a9b5`](https://explorer-studio.genlayer.com/address/0x9f797016b31727AEac2548B1d1daB9F6eA32a9b5)
- The deployed Studio source matches `contracts/fee_quote_guard.py`.
