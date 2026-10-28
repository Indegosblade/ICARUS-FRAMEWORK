# Validation Results

Historical results from recorded pipeline executions against specific directories
and firmware images. Version labels identify the original experiments; counts and
claims below are preserved as historical evidence, not current release validation.
See the [documentation index](../docs/README.md) for current operating contracts.

## v1.4.0 — Cross-source entity resolution

First end-to-end run of the scored resolver (`resolve_scored`) on real data. A real Linux dump (40 `/usr/bin` ELF binaries, 25 systemd units, real `/etc/passwd`) was built with the `linux` parser, then atomized as two separate sources and resolved across them.

| Metric | Value |
|--------|------:|
| Atoms ingested (2 sources) | 104 |
| Entity types resolved | binaries, daemons |
| Canonical entities (`bags`) | 52 |
| &nbsp;&nbsp;— spanning ≥ 2 sources | 52 (100%) |
| Scored candidate pairs (`match_candidates`) | 424 |
| Confidence-bearing resolve events | 52 |

Every binary and daemon observed under both source versions merged into one canonical `bags` row carrying a `score`; every scored pair — above *or* below threshold — is retained in `match_candidates`, so each merge is auditable after the fact. The exact-key `resolve()` MVP and all pre-existing resolver behavior are unchanged.

## v1.4.0 — Resolver calibration & real-drift validation

Coverage was extended to five entity types (binaries, daemons, frameworks, kexts, files) and the merge threshold was **measured** rather than guessed, via a controlled-perturbation harness (`python -m icarus.core.resolver_eval`) that runs the real resolver over atoms with known ground-truth labels. Full methodology and the decision live in [docs/RESOLVER_CALIBRATION.md](../docs/RESOLVER_CALIBRATION.md).

**Real two-dump stress test.** Two dumps built from real `/usr/bin` ELF binaries — dump A (50 binaries) and dump B = A with *real* controlled drift (recompile = appended bytes → a real SHA-256 change at the same name/path; rename; 10 genuinely-new; 10 deleted) — were run through the full pipeline (`icarus build` ×2 → `icarus resolve`) and scored against the exact ground truth:

| threshold | precision | recall | per-category recall |
|----------:|----------:|-------:|---------------------|
| 0.40–0.50 | 1.00 | 1.00 | identical / recompile / rename all 1.0 |
| 0.85 (default) | 1.00 | 0.50 | recompiles + renames missed |

The synthetic harness and the real dumps agree to the number: recompiled/renamed binaries score ~0.538, so the precision-first default 0.85 misses them (recall 0.50, precision 1.00) while a threshold ≤0.53 recovers **all** of them (recall 1.00). The resolver *can* match them — the limit is the threshold, not the engine — and calibration is per-corpus: real `/usr/bin` has no two distinct binaries sharing a name+path, so it stays precision-safe even at 0.40, whereas a corpus with such collisions would not (which is why 0.85 remains the conservative default).

## v1.2.0 — iOS 27.0 daemon attack-surface map

First end-to-end run of the `macos` parser against a real Apple firmware image.

**Source:** `iPhone16,1_27.0_24A5370h_Restore.ipsw` (iOS 27.0, build 24A5370h, iPhone 15 Pro)
**Parser:** macos (auto-detected)
**Coverage:** base filesystem + SystemOS (sealed APFS) + AppOS cryptexes

| Metric | Value |
|--------|------:|
| Files cataloged | 252,434 |
| Binaries (Mach-O) | 3,763 |
| Daemons | 656 |
| &nbsp;&nbsp;— linked to executable | 647 (98.6%) |
| Mach services | 2,375 |
| Entitlements | 55,160 |
| &nbsp;&nbsp;— distinct keys | 5,129 |
| Frameworks | 3,438 |
| Kexts | 15 |
| Reachable + privileged (`v_sandbox_escape_surface`) | 588 |

Every launchable executable is captured with its entitlements — including the Safari/WebKit stack in the AppOS cryptex (`webpushd`, `webinspectord`, `browserkitd`). Top IPC-reachable, entitlement-bearing daemons: `SpringBoard` (527 entitlements), `assistantd`, `sharingd`, `locationd`, `CommCenter` (holds `com.apple.private.skywalk.register-kernel-pipe`). Most common entitlement keys: `security.exception.mach-lookup.global-name` (1,395), `private.tcc.allow` (671), `platform-application` (545).

Entitlements are parsed directly from each Mach-O code signature by `macho.py` (stdlib only, no `codesign`/`ldid`). The daemon → binary → entitlement chain populates `v_sandbox_escape_surface`; `mach_service_owners()` resolves any Mach service back to the daemon that vends it.

## v1.1.1

### Large-scale scan

**Source:** Windows user profile directory
**Parser:** Windows (auto-detected)

| Metric | Value |
|--------|------:|
| Files cataloged | 2,045,000 |
| Binaries detected | 29,427 |
| Frameworks | 25,078 |
| Total entities | 2,099,505 |
| Database size | 20.5 GB |
| PII findings pre-sanitize | 24,822 |
| PII findings post-sanitize | 0 |

### Cross-platform validation

4 datasets across Windows and Linux:

| Dataset | Platform | Entities | Source Size | Binaries | PII Post-Sanitize |
|---------|----------|------:|-----:|---------:|:---:|
| User profile | Windows | 116,002 | 244 GB | 399 PE | 0 |
| Python 3.12 | Windows | 55,346 | 2,079 MB | 150 PE | 0 |
| Chrome profile | Windows | 25,916 | 3,249 MB | 3 PE | 0 |
| Ubuntu /usr | Linux (WSL2) | 96,181 | 12,834 MB | 1,111 ELF | 0 |

---

## Definitions

- **Entities** — rows across all ontology tables (files, binaries, daemons, entitlements, frameworks, etc.)
- **PII Post-Sanitize** — HYGEIA `verify_clean()` findings after sanitization. 0 means the database contains no detected PII.
- **Binaries** — PE (Windows) or ELF (Linux) executables detected with architecture classification.
