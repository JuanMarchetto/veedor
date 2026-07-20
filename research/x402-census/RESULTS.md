# x402 directory census — 2026-07-20

Every claim the [README](../../README.md) makes about the x402 discovery directory
comes from this run. Re-measure it yourself:

```sh
python3 census.py --sample 1000
```

## Numbers

| Measure | Value |
|---|---|
| Directory total (API `pagination.total`) | 24,929 |
| Sampled | 1,000 (offset 0 — the head of the directory, not a random draw) |
| Priced in USD stablecoins | 982 (18 pay in other assets, left unpriced rather than guessed) |
| Median price | $0.0100 |
| Under $0.01 | 40.0% |
| Under $0.10 | 85.7% |
| Over $1 | 2.0% |
| Top prices in sample | $2, $3, $5, $5, $1000 |

Raw items as fetched: [`sample-2026-07-20.json`](sample-2026-07-20.json).

## Physical work

The keyword scan (`3d print`, `fabricat`, `deliver`, `courier`, `assembl`,
`physical`, …) flagged 9 of 1,000 descriptions. Manual review of all nine: eight are
data or report services that merely *describe* physical things (shipping-rate data,
marine weather, ICS/SCADA threat intel, PDF generation, holiday calendars). One —
a print-and-mail service for USPS letters and postcards — actually causes something
to happen in the world. It is commodity postal fulfillment with no acceptance
criterion an inspection could check.

So the honest sentence is: **one service in a thousand touches the physical world,
and none carries a spec a verifier could measure delivery against.**

## Method and caveats

- The sample is the first 1,000 directory entries by API order, not a random draw
  over 24,929. Rerun with `--offset` to probe elsewhere.
- A resource is priced from its first `accepts` entry whose asset metadata names a
  USD stablecoin, at 6 decimals (what USDC/USDT use on Base, Ethereum, Polygon and
  Solana). Anything else counts as unpriced — no exchange-rate guessing.
- Price is the listed `amount` per call, not observed volume. The directory says
  what services *ask*, not what anyone *pays*; per-resource call telemetry, where
  Coinbase exposes it, is a separate measurement.
