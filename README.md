# api-key-scan-demo

A mini project for learning **DevSecOps secret scanning**: a GitHub Actions pipeline that scans source code for hardcoded API keys and **stops the deployment** if it finds one.

It contains a one-page website with two deliberate, fake leaked secrets, a dependency-free Python scanner, a JSON rule file, unit tests, and a workflow that gates deployment on the scan result.

> All secrets in this repo are fake. The Google-style key in `site/index.html` has the right *format* so the rule can match it, but it is not a working credential.

---

## Project layout

```
api-key-scan-demo/
├── .github/workflows/secret-scan.yml   # CI pipeline: tests -> scan -> deploy
├── site/index.html                     # one-page site WITH two deliberate leaks
├── examples/index.fixed.html           # the same page, fixed (no secret in the browser)
├── rules/secret-rules.json             # detection rules (data, not code)
├── scripts/secret_scan.py              # the scanner (Python standard library only)
├── tests/test_secret_scan.py           # 28 unit tests
├── .gitignore
└── README.md
```

## How the whole thing works

```
git push / pull request
        |
        v
+-------------------+    +----------------------+
| job: unit-tests   |    | job: secret-scan     |     run in parallel
| tests the scanner |    | scans the repo       |
+---------+---------+    +----------+-----------+
          |                         |
          +------------+------------+
                       v
          +---------------------------+
          | job: deploy               |   needs: [unit-tests, secret-scan]
          | publishes ./site to Pages |   only runs if BOTH succeeded,
          +---------------------------+   and only on push to main
```

The key GitHub Actions concept is **`needs:`**. If `secret-scan` exits with a non-zero code, the job fails, and any job that `needs` it is skipped. The scanner returns exit code `1` when it finds a secret, so deployment never starts.

Why test the scanner too? A security gate that silently stops working is worse than no gate. The `unit-tests` job protects the gate itself.

## The scanner (`scripts/secret_scan.py`)

1. Loads the rules from `rules/secret-rules.json` and compiles the regexes.
2. Walks the directory tree, skipping `.git`, `node_modules`, `tests` and `__pycache__`, plus binary files (a NUL byte in the first 8000 bytes) and files over 1 MB.
3. Checks every line against every rule.
4. Applies false-positive filters (below).
5. Prints findings with the secret **redacted**, writes GitHub annotations and a job summary, and exits `1` if anything was found.

Exit codes: `0` clean, `1` secrets found, `2` bad usage or unreadable rules file.

### Detection rules

| Rule id | Pattern (summary) | Why it is reliable |
|---|---|---|
| `aws-access-key-id` | `AKIA` or `ASIA` followed by exactly 16 chars of `A-Z0-9` | Fixed public prefix and length (20 chars total) |
| `google-api-key` | `AIza` followed by exactly 35 chars of `A-Za-z0-9_-` | Fixed prefix and length (39 chars total) |
| `github-token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 or more alphanumerics | GitHub's token prefixes |
| `stripe-live-secret-key` | `sk_live_` + 24 or more alphanumerics | Distinct prefix; `sk_test_` keys are deliberately **not** flagged |
| `private-key-block` | `-----BEGIN ... PRIVATE KEY-----` headers (RSA, EC, DSA, OPENSSH, ENCRYPTED, plain, PGP) | Standard PEM/PGP header text |
| `generic-hardcoded-secret` | A name containing `api_key`, `api-key`, `secret`, `token`, `passwd` or `password`, then `=` or `:`, then a quoted literal of 16+ chars | Catches unknown providers; needs the filters below to avoid noise |

The first five rules use **lookarounds** (`(?<!...)` and `(?!...)`) so a string that is too long or too short is rejected instead of partially matched. For example, a 40-char `AIza...` string does not match `google-api-key`.

### False-positive controls

- **Entropy check (generic rule only).** Shannon entropy measures randomness per character. `"aaaaaaaaaaaaaaaaaaaa"` scores 0 and is ignored; a real random key scores well above the `3.0` threshold.
- **Placeholder filter (generic rule only).** Values containing `example`, `your`, `changeme`, `placeholder`, `dummy`, `sample`, `xxxx`, `<`, `>`, `${`, `{{` or `process.env` are ignored, so `"YOUR_API_KEY_HERE"` in docs does not fail your build. Trade-off: a real secret that happens to contain one of those substrings would be missed by the generic rule. That is why the provider-specific rules do *not* use this filter.
- **De-duplication.** Rules run in file order, specific first. If two rules match the same value on one line, only the first is reported. In the demo, line 23 matches both `google-api-key` and `generic-hardcoded-secret`; only the specific one is shown.
- **Inline allow marker.** A line containing `secretscan:allow` is skipped. Use it sparingly and make reviewers look at every use, because it is also how an attacker would hide something.

### Redaction

Findings print as `AIza************00`, never the full value. CI logs are often readable by many people and kept for a long time, so a scanner that prints the secret would create a second leak.

## Run it locally

Uses only the Python standard library, so there is nothing to install. Tested locally on Python 3.13; the workflow uses 3.12.

```bash
# 1. Run the unit tests
python3 -m unittest discover -s tests -v

# 2. Scan the whole repo (this FAILS on purpose: site/index.html has leaks)
python3 scripts/secret_scan.py .
echo $?        # 1

# 3. Scan the fixed page (this passes)
python3 scripts/secret_scan.py examples
echo $?        # 0
```

Real output from step 2:

```
SECRET SCAN FAILED: 2 potential secret(s) in 7 files scanned

  site/index.html:23  [HIGH] google-api-key  ->  AIza************00
      Google API key (AIza prefix + 35 chars)
  site/index.html:24  [MEDIUM] generic-hardcoded-secret  ->  q8Zr************Hs
      Variable/field named key, secret, token or password assigned a long quoted literal

Deployment must not continue. Remove the secret, ROTATE it (assume it is burned), then push again.
```

## Run it on GitHub

1. Create a new repository and push this project to the `main` branch.
2. In **Settings -> Pages**, set **Source** to **GitHub Actions** (needed for the deploy job).
3. Open the **Actions** tab. Expected result: `unit-tests` passes, `secret-scan` **fails** with red annotations on `site/index.html` lines 23 and 24, and `deploy` is **skipped**. The run's summary page also shows a table of findings.
4. Fix it: copy `examples/index.fixed.html` over `site/index.html`, commit, push. Now `secret-scan` passes and `deploy` runs.
5. For pull requests: in **Settings -> Branches**, add a branch protection rule on `main` that requires the `secret-scan` and `unit-tests` checks. Without that, someone can still merge a failing PR; the `needs:` gate only protects the deploy job.

Heads-up: GitHub has its own secret scanning and push protection, which may block your push or flag the fake key in `site/index.html` because it looks like a real credential format. That means GitHub's detection also works; if it happens, follow the prompt GitHub shows (the key is fake).

## How to fix a leaked key properly

The bug in `site/index.html`: **anything in front-end code is public.** Anyone can press F12 or "View source" and read it. Hiding or encoding the string does not help.

| Situation | Correct fix |
|---|---|
| Key must stay secret | Put it in a server-side environment variable or secret store, and have your own backend endpoint call the third-party API. See `examples/index.fixed.html`. |
| Provider issues browser-safe keys (e.g. Google Maps JS keys) | The key can be public, but restrict it in the provider console (allowed websites, allowed APIs, quotas). |
| A key was already committed or pushed | **Rotate it immediately.** Deleting it in a new commit does not remove it from git history. Treat it as compromised. |

## Limitations (read these)

- **Working tree only.** The scanner checks the files in the current checkout, not git history. A secret deleted two commits ago is still in history. Dedicated tools such as Gitleaks and TruffleHog scan history; learning one of them is a good next step.
- **Not exhaustive.** Six rules cover a few common formats. I only included patterns whose format I am confident about; I left out providers (Slack, Twilio, Azure and others) rather than guess their formats. Add a rule only after checking the provider's documented format and writing a positive and a negative test.
- **Formats can change.** Providers sometimes change token formats; that is why the GitHub and Stripe rules use "N or more" lengths.
- **Regex has blind spots.** A secret split across string pieces (`"AI" + "za..."`), Base64-encoded, or loaded from a file at runtime will not match. Entropy-only scanning of every string is deliberately not used because it is very noisy.
- **Possible false positives and negatives** are tuned by the entropy threshold and placeholder list in `secret_scan.py` and `rules/secret-rules.json`.

## Adding your own rule

1. Find the provider's documented key format.
2. Add an entry to `rules/secret-rules.json` (`id`, `description`, `severity`, `regex`; optional `secret_group`, `min_entropy`, `ignore_placeholders`).
3. In `tests/test_secret_scan.py`, add one example to `POSITIVES` (build it from two string pieces so the test file itself stays clean) and at least one near-miss in `NegativeDetection`. The test `test_every_rule_has_a_positive_example` fails until you do.
4. Run the tests, then scan the repo to check you did not create false positives.

## Concepts you practised

- **Shift-left security:** catching flaws before deployment instead of after.
- **Security gates in CI/CD:** job dependencies (`needs`), exit codes, conditional jobs (`if`).
- **Detection engineering:** regex precision, lookarounds, entropy, false-positive tuning, de-duplication.
- **Secure tooling:** redacting findings, least-privilege workflow `permissions`, testing the security control itself.
- **Secrets management basics:** never ship secrets to the client, restrict what must be public, rotate anything leaked.

## Suggested next steps

- Add a pre-commit hook that runs the scanner before every commit.
- Try Gitleaks or TruffleHog in a second workflow job and compare their findings with this scanner's.
- Add a dependency scan and CodeQL to the same pipeline.
- Pin third-party actions to full commit SHAs, and check for newer major versions of the actions used in the workflow.
