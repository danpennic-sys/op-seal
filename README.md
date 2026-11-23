# op-seal

Deterministic offline evidence sealer for Operator Pages.

**PROOF NOT PROMISE.**

Offline. No network. No wall-clock in the hash. Pure functions.

## What it does

Walks a directory, SHA-256 every file, builds a deterministic Merkle root (sorted, unpaired promoted), writes a sealed JSON pack.

Anyone can verify the pack against the directory offline: PASS or FAIL.

## Build

```bash
go build -o op-seal .
```

## Usage

```bash
# Seal a directory
./op-seal seal -dir ./evidence -out sealpack.json

# Verify
./op-seal verify -pack sealpack.json -dir ./evidence
```

## Sell it

Fits the Operator Pages stack: static HTML landing + Go binary.

Suggested pricing: $199 one-time Operator Pack (signed binary + runbook) or source license.

Integrate with your existing Stripe.

Open-source core stays free; paid pack adds signed binaries, air-gap instructions, and support.

## License

MIT
