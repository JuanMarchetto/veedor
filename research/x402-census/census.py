#!/usr/bin/env python3
"""Census of the x402 discovery directory: what does it actually sell, at what price?

One command, no dependencies beyond the Python standard library:

    python3 census.py --sample 1000

Fetches the directory total, samples the first N resources (the API paginates by
offset; the sample is the head of the directory, not a random draw — rerun with
--offset to probe elsewhere), writes the raw items to sample-<date>.json, and
prints price statistics. Every number in the repo's README that describes this
directory comes from a run of this script, so anyone can re-measure instead of
believing us.

Pricing: each resource lists one or more `accepts` entries with an atomic
`amount` and an asset. Entries whose asset metadata names a USD stablecoin
(USD Coin, USDC, USDT) are priced at 6 decimals, which is what those tokens use
on Base, Ethereum, Polygon and Solana. Resources paying in anything else are
counted as "unpriced" rather than guessed at.
"""

import argparse
import json
import re
import statistics
import urllib.request
from datetime import date

API = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
PAGE = 200
USD_NAMES = re.compile(r"usd", re.IGNORECASE)
PHYSICAL_HINTS = re.compile(
    r"\b(3d.?print|print(ed|ing)? (part|order)|fabricat|cnc|deliver|shipping|"
    r"ship (a|an|my)|courier|errand|assembl|manufactur|physical|warehouse|drone)\b",
    re.IGNORECASE,
)


def fetch(offset: int, limit: int) -> dict:
    with urllib.request.urlopen(f"{API}?limit={limit}&offset={offset}", timeout=30) as r:
        return json.load(r)


def usd_price(item: dict):
    for acc in item.get("accepts", []):
        name = (acc.get("extra") or {}).get("name", "")
        if USD_NAMES.search(name):
            try:
                return int(acc["amount"]) / 1_000_000
            except (KeyError, ValueError, TypeError):
                continue
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=1000)
    ap.add_argument("--offset", type=int, default=0)
    args = ap.parse_args()

    first = fetch(args.offset, PAGE)
    total = first["pagination"]["total"]
    items = list(first["items"])
    while len(items) < args.sample:
        page = fetch(args.offset + len(items), PAGE)
        if not page["items"]:
            break
        items.extend(page["items"])
    items = items[: args.sample]

    stamp = date.today().isoformat()
    raw_path = f"sample-{stamp}.json"
    with open(raw_path, "w") as f:
        json.dump({"fetched": stamp, "total": total, "offset": args.offset,
                   "items": items}, f)

    prices = [p for p in (usd_price(i) for i in items) if p is not None]
    unpriced = len(items) - len(prices)
    physical = [i for i in items if PHYSICAL_HINTS.search(i.get("description", ""))]

    print(f"directory total (API): {total}")
    print(f"sampled: {len(items)} (offset {args.offset}), raw -> {raw_path}")
    print(f"priced in USD stablecoins: {len(prices)}, unpriced/other asset: {unpriced}")
    if prices:
        prices.sort()
        pct = lambda cut: 100 * sum(1 for p in prices if p < cut) / len(prices)
        print(f"median price: ${statistics.median(prices):.4f}")
        print(f"under $0.10: {pct(0.10):.1f}%   under $0.01: {pct(0.01):.1f}%   "
              f"over $1: {100 - pct(1.0):.1f}%")
        print(f"top prices: {['$%.2f' % p for p in prices[-5:]]}")
    print(f"descriptions matching physical-work keywords: {len(physical)}")
    for i in physical:
        print(f"  REVIEW: {i.get('description', '')[:140]}")


if __name__ == "__main__":
    main()
