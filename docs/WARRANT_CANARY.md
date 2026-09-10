# Warrant Canary

A warrant canary is a signed statement that no secret legal process has been
received. Its value is not in the statement — it is in the *routine*. The
signal is the **absence** of a fresh signature, because a maintainer who is
legally barred from saying "we were served" can still decline to repeat a
statement that is no longer true.

That has two consequences worth stating plainly, because they are what make a
canary meaningful rather than decorative:

1. **A canary that is never published cannot stop being published.** Until a
   first canary exists, there is no signal.
2. **A canary nobody watches carries nothing.** If it lapses and no one
   notices, silence conveys as much as it did before.

## Current status

**Vellaveto does not currently publish a warrant canary.**

What exists today:

| Piece | State |
|---|---|
| Creation and Ed25519 signing (`create_canary`) | implemented, exposed via the `vellaveto-canary` CLI |
| Verification (`verify_canary`) | implemented; used by the CLI and by `vellaveto-shield --canary <path>`, which fails closed on a bad signature |
| Freshness monitoring | `.github/workflows/canary-freshness.yml`, running daily |
| A published canary | **none** |

The tooling and the watchdog are in place, so publishing is one command. Until
someone runs it with a real key and a real statement, the mechanism is armed
but not carrying a signal — and this document says so rather than implying
otherwise.

## Publishing one

### 1. Generate a signing key, once

```bash
vellaveto-canary keygen > canary-signing-key.txt
```

The secret goes to stdout; the verifying (public) key is printed to stderr.

**Key custody is the whole security model.** Anyone holding the signing key can
forge a canary, which is the single failure that makes the signal worthless —
worse than having no canary, because readers will trust a forgery. Keep the
signing key offline, on hardware you control. Do not put it in CI secrets: a
canary signed automatically by infrastructure attests to nothing about a
person's legal circumstances, which is the only thing it is supposed to attest
to. Signing is deliberately a manual act.

Publish the verifying key somewhere durable and separate from the canary
itself, so a reader can tell a key rotation from a key compromise.

### 2. Write the statement

Put the text in a file. Say what is true, in your own words. A canary
typically asserts that as of the signing date no secret legal process,
gag order, or demand for user data has been received, and states that the
absence of a future update should be treated as meaningful.

Write it yourself. A statement about your legal circumstances is not something
to delegate, and no tool in this repository will compose one for you.

### 3. Sign and publish

```bash
VELLAVETO_CANARY_SIGNING_KEY=$(cat canary-signing-key.txt) \
  vellaveto-canary create \
    --statement-file STATEMENT.txt \
    --valid-days 90 \
    --out .well-known/canary.json
```

The key is read from the environment, never an argument, so it does not land
in shell history or process listings. The command verifies what it produced
before writing it out — a canary that fails its own signature check reads as
tampering, so it is never emitted.

Commit `.well-known/canary.json`. From that point the daily freshness workflow
enforces it.

### 4. Refresh on a cadence

Re-sign before expiry, on a schedule you keep publicly. Cadence is a trade-off:
a short window makes a lapse conspicuous quickly but demands frequent manual
signing; a long one is easier to sustain but delays the signal. Ninety days
with a 21-day warning is a reasonable default and is what the workflow assumes.

**Do not automate the signing.** Missing a refresh is supposed to be possible;
that possibility is the mechanism.

## Verifying one

```bash
vellaveto-canary verify --in .well-known/canary.json
vellaveto-canary verify --in .well-known/canary.json --min-days-remaining 21
```

Exit codes: `0` valid, `1` usage or I/O error, `2` invalid signature, expired,
or below the freshness threshold.

The consumer shield checks a canary at startup and refuses to run on a bad
signature:

```bash
vellaveto-shield --canary /path/to/canary.json
```

## Reading the signal

- **Fresh and valid** — the statement held as of the signing date. Note that
  this is a claim about the past, not a live guarantee.
- **Lapsed** — the maintainer did not re-sign. This may be legal compulsion.
  It may equally be illness, travel, or forgetfulness. A canary is evidence to
  weigh, not proof.
- **Signature invalid** — do not treat this as ordinary staleness. Either the
  file was altered or the key changed. Verify the key out of band before
  drawing any conclusion.

## Limitations

A canary is a weak instrument, and it is worth being honest about why:

- Its legal force is untested in most jurisdictions. A court may be able to
  compel a false statement or compel continued signing.
- It says nothing about compromise that does not involve legal process.
- It depends entirely on the signing key staying under the maintainer's sole
  control.
- Silence is ambiguous by construction, which is what lets it work at all and
  also what limits what it can tell you.

It is a transparency gesture with real but bounded value. Treat it as one
input, not an assurance.
