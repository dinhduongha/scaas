> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Releasing and distributing scaas-app, scaas-tui and the CLI without binaries on GitHub (2026-11-27)

Research of 2026-11-27 for the owner, who asked how scaas-app's four front-ends (Qt, Flutter, Dioxus, Tauri with a React UI,
including a web build and a browser extension), `scaas-tui` and the CLI `scaas` are released and distributed. Nothing here is
built, specified or ruled; every recommendation is a proposal, and the owner questions are listed in §8. External claims carry a
source id ([D*n*], §9, all read 2026-11-27); **[I]** marks an inference of this note, not a source's statement. No release
tooling exists yet in either repository, so nothing below is AUDITED or measured.

## Summary

**Recommendation in five lines.**

1. **Source first, now:** every target ships as source plus one pinned build script and one verify script; third parties that
   build from source (Flathub, AUR, a Homebrew tap formula, the user) need no ruling. That is the standing rule as written.
2. **Reproducible builds and a signed release manifest** (text: source commit, toolchain pins, the sha256 of each unsigned
   payload, the SBOM's digest, a sequence number), committed to the repo and signed offline by the owner. Provenance attestations
   cover digests only, so no binary goes on GitHub.
3. **Stores only after two owner rulings:** whether a binary we build may go anywhere outside GitHub (Q1), and which legal
   entity holds the store accounts and signing keys (Q3). Prefer stores that rebuild and compare: Firefox AMO and an
   F-Droid-style signature copy.
4. **No self-updater and no hosted web wallet until ruled.** Meanwhile the web build and the extension run locally only (a
   local `--serve`, "load unpacked").
5. **Two blockers that need no new research:** the licence keeps F-Droid's main repo, `homebrew/core` and Debian main out (§1.2).
   The Qt fork's `fdroid/` and `fastlane/` are upstream's. They point at upstream's GitHub releases and carry upstream's brand,
   so they are rewritten or moved to `legacy/` before any listing (§1.3).

## 1. What the repositories already say

### 1.1 The rule on binaries

- `AGENTS.md`, Security: "No built binaries on GitHub: source and build scripts only." scaas-app's `README.md` ("Licence and
  brand") says the same for that repository: "Only source and build scripts are published; no built binaries."
- The owner's wording (2026-10-13, recorded in the agents' notes, not in `decisions.md`): publication packages are source-only:
  build and reproduce scripts the reader runs, no prebuilt binaries in the repo, GitHub Releases, GitHub Pages or a pushed
  container image. CI may publish text and JSON results, not binaries. Browser demos get a local `--serve`.
- **Gap:** the rule has no anchor in `decisions.md`, and its scope is "on GitHub". It does not say whether a binary **we** build
  may be uploaded elsewhere: a store, our own server, an IPFS pin. That is owner question Q1. This note sorts every channel into
  three classes:
  - **A**, a third party builds from our source (fits the rule as written);
  - **B**, we build and upload to a store, not GitHub (the rule's words allow it, its intent may not);
  - **C**, we host binaries ourselves outside GitHub (an owner call).

### 1.2 The licence

New files carry `LicenseRef-Vegan-Community-1.0` (root `LICENSE`). It grants MIT or Apache-2.0 freedoms to eligible users and
excludes businesses that kill animals. That is a restriction by field of endeavour, which the Open Source Definition's criterion 6
forbids ("The license must not restrict anyone from making use of the program in a specific field of endeavor") [D43]. **[I]** So
the code is not FLOSS under the OSI or DFSG reading, and the channels that require FLOSS are out unless the owner changes the
licence of what they ship:

- **F-Droid's main repository** requires Free, Libre and Open Source Software judged by the DFSG, FSF, GNU and OSI standards [D3].
- **`homebrew/core`** requires "a licence compatible with the Debian Free Software Guidelines" [D19].
- **Debian main** and most distribution main archives **[I]**.

Flathub needs only content that "allow[s] legal redistribution", with the licence stated in MetaInfo [D17]. The commercial stores,
AUR, winget and Homebrew casks or taps take a custom licence **[I]**. The Qt front-end is mixed: files derived from Status
stay MPL-2.0 under `scaas-qt-wallet-client/`, and new files carry the Vegan licence (scaas-app `README.md`).

### 1.3 The Qt fork's packaging directories

- `scaas-qt-wallet-client/fdroid/` is upstream's kit for an F-Droid build that is byte-for-byte reproducible. Its `README.md`
  says the fdroiddata entry uses `Binaries:` pointing at **upstream's GitHub releases** APK, with F-Droid copying the developer
  signature onto its own rebuild, gated by `AllowedAPKSigningKeys`. The app id is upstream's (`app.status.mobile`). As it
  stands, it conflicts with both the binaries rule and the brand rule.
- What it teaches is reusable. `build-qt.sh` sets `SOURCE_DATE_EPOCH` to the commit time of the latest release tag (not
  `HEAD`) and `LC_ALL=C`. It patches `--build-id=none` and `-ffile-prefix-map` into Qt's top-level CMake, and compiles QML with
  `qmlcachegen --only-bytecode`, because the AOT code generator is not deterministic. It turns off unity builds and IPO, and
  deletes de-registered submodules. The Go library builds with `-trimpath -buildvcs=false`, and its build ids are stripped.
- `cleanup-binaries.sh` deletes every binary file under `vendor/` before the F-Droid scanner runs. That is the scanner's own
  "no prebuilt binaries in the source" rule.
- `fastlane/metadata/android/en-US/title.txt` still reads upstream's product name, against scaas-app's README ("no Status
  name, logo or look is used"). `flatpak/` holds one GTK patch; the `Makefile` builds a single-file Flatpak bundle locally
  (`scripts/bundle-flatpak.sh`).
- Signing scripts take key material as files or environment variables. `sign-windows-bin.sh` uses a PFX file
  (`WINDOWS_CODESIGN_PFX_PATH`), `sign-linux-file.sh` a GPG key file plus a passphrase variable, and `sign-macos-pkg.sh` and
  `notarize-macos-pkg.sh` use codesign and `notarytool`. §3 explains why a file-held key no longer fits Windows and should not
  fit any channel here.

### 1.4 CI, pins and what a release carries

- This repository's CI (`.github/workflows/ci.yml` header) only checks: contracts, node, clients, docs, format. There is no
  release job. It already runs `cargo deny` and `cargo audit` on `ua-rs` and the crates over it, from `clients/ua-rs/deny.toml`.
  scaas-app's own CI is a format job (`.github/workflows/format.yml`); the Qt fork keeps upstream's `pr.yml` and an Appium job.
- Third-party sources are fetched and checked by `scripts/vendor.sh` against sha256 and git-tree pins
  ([ARCH-POS-24](../decisions.md#ARCH-POS-24)). Dependency upgrades take releases at least two weeks old
  ([ARCH-POS-25](../decisions.md#ARCH-POS-25)). Rust is pinned to 1.97.1 by the root `rust-toolchain.toml`. These are the
  inputs a reproducible build needs.
- A release binary carries trust decisions. The TUI's release chain profiles (RPC lists, chain ids) are compiled in or
  digest-pinned ([CLI-TUI-11](../clients/scaas-tui.md#CLI-TUI-11), over [CLI-SDK-15](../clients/scaas-sdk.md#CLI-SDK-15)).
  A swapped binary therefore swaps the nodes the user trusts, so its integrity is a security property, not only a packaging
  concern.

## 2. Reproducible builds per toolchain

The goal: anyone can rebuild a release from the tagged commit and get the same bytes, except the signature. Then a store, a
reviewer or a user can check a binary against the source, and a binary we never published can still be verified.

| Toolchain (targets) | Levers | Known traps | How a match is checked |
|---|---|---|---|
| Rust: CLI, TUI, `app-core-rust`, Dioxus, Tauri's core | the pinned toolchain, `--locked`, `vendor/`; `--remap-path-prefix` for the workspace, `CARGO_HOME` and the toolchain, with the default `all` scope, because narrower scopes leave local paths in `.rmeta` and `.rlib` [D30]; `SOURCE_DATE_EPOCH` [D32]; `trim-paths` is still an unstable cargo feature [D31] | linker-generated paths (`.pdb`, Apple OSO entries) are not remapped, and remapping is textual, so Windows separators need care [D30]; RUSTFLAGS differences change the hash **[I]** | sha256 of the stripped executable in a pinned container **[I]** |
| Qt/C++: Qt front-end | the fork's list in §1.3 | QML AOT, unity and IPO builds, build ids, absolute paths (fork `README.md`) | F-Droid signature copy (APK); sha256 of the AppImage or tarball payload **[I]** |
| Flutter: Android, iOS, desktop | pinned Flutter SDK and FRB versions (scaas-app plan F1); `SOURCE_DATE_EPOCH` | absolute build paths in `.dart_tool/flutter_build/dart_plugin_registrant.dart` broke one Flutter app's F-Droid match [D33]; the engine comes prebuilt with the SDK **[I]** | as for any APK [D1] |
| Tauri bundles: desktop and mobile | Rust as above; `npm ci` from the lockfile with a pinned Node; a pinned bundler | installers (MSI, NSIS, DMG, AppImage) add timestamps and signatures **[I]** | compare the unpacked payload (executable plus the UI assets), not the installer **[I]** |
| wasm: web build, extension | pinned `wasm-bindgen` and `wasm-opt`; `ua-rs` already cross-checks on wasm32 in CI | the JS bundler's output order and its hashed file names **[I]** | AMO reviewers rebuild from source and diff, "There must be no differences" [D25] |
| Android APK, any front-end | v2 and v3 signatures cover every byte, so a match means byte-identical apart from the signature [D1] | ZIP entry order between Android Studio and Gradle, a `baseline.prof` that is not deterministic, apksigner versions after build-tools 34 breaking apksigcopier (F-Droid docs, through search) [D1] | F-Droid copies our signature onto its rebuild; `diffoscope` to find a difference |

**How a user or a store verifies (proposal).**

- One `verify-release.sh` per target: it builds the tagged commit in the pinned container, prints the sha256 of each unsigned
  payload, and compares them with the release manifest (§5.3).
- F-Droid does this itself with signature copying [D1], and AMO with its reviewer rebuild [D25].
- For a store that re-signs (Play App Signing, the App Store), byte equality with the user's copy is not available. Compare
  the extracted payload (`classes.dex`, native libraries) instead **[I]**.

## 3. Code signing and who holds keys

| Platform | What signs, and who holds the key | Key lost or exposed |
|---|---|---|
| Windows (Authenticode) | Since 2023-06-01, code-signing keys are generated and kept in a hardware module (FIPS 140-2 level 2 or Common Criteria EAL 4+), non-exportable (CA/B Forum CSC-17; secondary source) [D15]. A PFX file in CI no longer fits. Azure Artifact Signing works from GitHub Actions over OIDC, but its public-trust identities were limited in 2026 to organisations with three years of history (US, Canada; EU and UK in a later, AI-generated Q&A answer), with individuals paused [D16]. | revoke and reissue the certificate **[I]**; unsigned builds meet SmartScreen warnings **[I]** |
| macOS | Developer ID signature, hardened runtime, secure timestamp, then notarization; required since macOS 10.15 for Developer ID software. The notary service keeps an audit trail, so tickets of unauthorised versions can be revoked [D13]. | revoke the Developer ID certificate; Apple revokes the tickets [D13] |
| Android | Under Play App Signing, Google keeps the app signing key and we keep an upload key, which can be reset. It is mandatory for new Play apps since August 2021. To share one key across stores, upload our own key instead of letting Google generate it. Self-managed: "if you lose your app's signing key, you lose the ability to update your app" [D8]. v3 key rotation chains old to new certificates; it is not recommended for API 31 and below, and `checkSignatures` follows it from API 33 [D7]. | Play: an upload-key reset; self-managed: a new package name, users reinstall [D8] |
| Android developer verification | From 2026-09-30, apps installed on certified devices in Brazil, Indonesia, Singapore and Thailand need a verified developer and a registered package name plus certificate fingerprint; global in 2027. Unverified apps go through an "advanced flow" [D5]. Open-source repositories may register keys for us, but a verified identity is still needed [D6]. F-Droid opposes the programme (open letter of 2026-02-24, read through search) [D4]. | the identity is the developer account, not the key [D6] |
| iOS, iPadOS | App Store or TestFlight. In the EU, alternative marketplaces or Web Distribution, still notarized by Apple [D12]. Wallets only from "developers enrolled as an organization" (3.1.5(i)) [D11]. | Apple-managed distribution certificates **[I]** |
| Linux | Flathub signs its own repository **[I]**; detached GPG or minisign signatures for anything else **[I]** | rotate and announce in the next signed manifest **[I]** |
| Extensions | Mozilla signs every extension for release and beta Firefox, listed or unlisted [D26]. Chrome signs by default; since 2025-05-07, verified uploads let us require our own RSA key on every upload (Chrome blog, through search) [D23]. Safari web extensions are packaged from a ZIP in App Store Connect and go through TestFlight and App Store review [D14]. | AMO and the Chrome Web Store hold the publishing identity **[I]** |
| Self-updaters | Tauri's updater signature cannot be disabled [D27]; Sparkle signs with ed25519 [D28] | an exposed updater key can push code to every install **[I]**: the worst case |

**Key custody (proposal).**

- **Root:** one offline release key held by the owner on hardware (a smartcard or HSM), never in CI. It signs only the release
  manifest (§5.3) and the store keys' rotation statements. TUF's model, with the root kept offline [D29].
- **Per channel:** separate keys (the Play upload key, the Apple and Windows identities, the AMO and Chrome accounts), each
  replaceable without touching the root.
- **Never in CI secrets** of this public repository. If CI ever signs, it does so only through OIDC to a cloud HSM (Artifact
  Signing, a KMS), behind a protected environment that waits for the owner's approval **[I]**.
- **The manifest key's scheme:** an Ed25519 key is the simplest. A UA key through `ua-rs` (Falcon or ML-DSA) would make the
  release PQ-signed like everything else, but every verifier would then need `ua-rs`. That is owner question Q10.

## 4. Channels and their policies

**Class:** A, a third party builds from our source; B, we build and upload to a store; C, we host the binary ourselves.
"Licence" means whether `LicenseRef-Vegan-Community-1.0` is accepted (§1.2).

| Channel | Who builds and who signs | Class | Licence | Policy for a crypto wallet | Update speed |
|---|---|---|---|---|---|
| F-Droid main repo | F-Droid builds and signs with its key; with `Binaries:` it publishes our APK only if its rebuild matches [D1] | A (or C with `Binaries:`, whose URL must not be GitHub) | **no** [D3] | anti-features such as Non-Free Network Services or Tethered Network Services if the app needs one server [D2] | F-Droid's build cycle |
| Own F-Droid-format repo | we build and sign | C | yes | none of its own **[I]** | ours |
| Google Play | we upload an AAB; Google signs [D8] | B | yes | a Financial Features declaration; licences per listed country (EU: MiCA); non-custodial wallets self-declare [D9]. New personal accounts need a 12-tester closed test of 14 days (Play help, through search) [D10] | review, then a staged rollout |
| Apple App Store (iOS, macOS) | we upload; Apple signs | B | yes | organisation enrolment for wallets [D11] | review |
| Flathub | Flathub builds from the manifest's declared sources with no network; no binaries in the submission [D17] | A | yes, if redistributable [D17] | none stated [D17] | a manifest PR |
| Snap Store | we, or Launchpad, build **[I]** | B | yes **[I]** | manual review of new names since 2024-03; crypto-wallet names rejected (2024 sources; current status unverified) [D18] | fast once listed **[I]** |
| Homebrew | core: builds from source, but needs a DFSG licence [D19]; cask: our signed and notarized binary, and casks failing Gatekeeper were set for disabling from 2026-09 (release notes, through search) [D19]; own tap with a source formula **[I]** | core A (no), cask C, tap A | core **no**, tap yes | none | a tap is ours |
| winget | the manifest names an `InstallerUrl` and `InstallerSha256` [D20]; the binary is hosted by us | C | yes | none stated [D20] | a manifest PR |
| AUR | anyone maintains a `PKGBUILD` that builds from source **[I]** (the Arch wiki refused the automated fetch [D21]) | A | yes **[I]** | none **[I]** | the maintainer's |
| Chrome Web Store | we upload; Google signs, or our key with verified uploads [D23] | B | yes | longer review for new developers, broad host permissions and big changes; days to weeks [D22]; MV3 bundles every script and WASM [D24] | review per update |
| Firefox AMO | we upload; Mozilla signs [D26]; reviewers rebuild from our source and diff [D25] | B | yes | as for any extension | automated signing within 24 h, manual review at any time [D26] |
| Safari | App Store Connect packager from a ZIP [D14] | B | yes | as for the App Store [D11] | review |
| Web build on an origin | whoever serves it | C | yes | none | instant, which is the problem |

**The web build.**

- A wallet served from an origin trusts that server on every load. SRI pins subresources by hash [D39], but nothing pins the
  top-level document **[I]**.
- Options:
  - **IPFS content under an ENS `contenthash`** [D40]: immutable per release, but a gateway is a server again **[I]**.
  - **Isolated Web Apps:** signed Web Bundles whose origin is derived from the signing key, with a strict CSP [D41];
    availability is narrower than the open web **[I]**.
  - **WEBCAT:** an experimental extension that checks enrolled sites against their publishers' commitments [D42].
- Under the rule as written, GitHub Pages is excluded. Any hosting is class C, owner question Q5.

**The extension.** AMO gives the strongest public check (a rebuild with no differences [D25]). Chrome's verified uploads stop a
stolen dashboard account from shipping a new version [D23]. MV3 forbids remote code, so all wasm ships inside the package [D24].

## 5. Updates

### 5.1 Store-managed updates

F-Droid, Flathub, Play, the App Store, AMO and the Chrome Web Store update on their own schedule and under their own signatures.
Android refuses an update signed by a different certificate [D8]. Refusing a downgrade is the store's or the OS's job
**[I]**.

### 5.2 Self-updaters

- Tauri's updater: signatures are mandatory; by default it installs only a higher version, and a custom comparator can allow
  rollbacks [D27].
- Sparkle: ed25519 signatures, with Developer ID signing recommended on top [D28].
- An updater turns one key into a push channel to every install, and it needs a hosted endpoint (class C).

**Proposal:** no self-updater in a first release; the CLI and TUI are rebuilt or come through a package manager.

### 5.3 A signed release manifest (proposal)

One text file per release, committed to the repository and signed by the offline root (§3). Named fields:

- `app`, `version`, `sequence` (strictly increasing), `source_commit`;
- `toolchains` (each pin);
- `artifacts`: per target, the sha256 of the unsigned payload;
- `sbom_sha256`;
- `profiles_sha256` (the release chain profiles, [CLI-TUI-11](../clients/scaas-tui.md#CLI-TUI-11));
- `min_supported`, `expires`.

**Rollback and freeze.** A client or verifier keeps the highest `sequence` it has seen and refuses a lower one. TUF's rollback
rule: an attacker "cannot trick clients into installing software that is older than that which the client previously knew"
[D29]. An `expires` date catches a freeze: a client "MUST NOT trust an expired file" [D29].

The manifest is text, so publishing it fits "CI may publish text and JSON results". It lets anyone verify a binary from any
channel without our hosting one.

## 6. Supply chain

- **SBOM:** CycloneDX from Cargo metadata with `cargo-cyclonedx` [D38]; the npm and Dart lockfiles alongside **[I]**.
  `cargo-auditable` embeds the dependency tree in each Rust binary, so `cargo audit`, Trivy, Syft, Grype and osv-scanner can read
  a shipped binary [D37]. The SBOM is text and goes beside the manifest.
- **Gates:**
  - Rust: extend the existing `cargo deny` and `cargo audit` (ci.yml) to scaas-app's crates; its plan already asks `cargo deny`
    for licences (task M1).
  - Tauri's UI: `npm ci` from the lockfile, plus `npm audit` **[I]**.
  - Flutter: a committed `pubspec.lock` **[I]**.
  - Every pin follows the two-week age of [ARCH-POS-25](../decisions.md#ARCH-POS-25).
- **Provenance without publishing binaries:**
  - SLSA Build L2 means a hosted platform generates and signs the provenance; L3 adds a hardened, isolated build [D34].
  - GitHub's artifact attestations are Sigstore-signed, meet L2 alone and L3 with reusable workflows. For a public repository
    they go to the Sigstore public-good instance, with a transparency log [D35].
  - `cosign sign-blob --bundle` signs a file keyless with an OIDC identity and records a transparency-log inclusion proof [D36].
  - **[I]** An attestation names a subject by digest. CI can build, attest and publish only the attestation and the digest, then
    discard the binary. The binary never reaches GitHub, and a rebuild that matches the digest inherits the provenance.
- **Order of evidence:** a rebuild that matches (reproducibility) is stronger than provenance, which only says who built it.
  Provenance is a supplement, never the only guard **[I]**.

## 7. Recommendation per front-end and channel

| Target | Now (class A, no ruling) | After Q1 and Q3 |
|---|---|---|
| CLI `scaas`, `scaas-tui` | source, `verify-release.sh`, manifest; an AUR `PKGBUILD` and a Homebrew tap formula, both building from source | winget and Homebrew cask (class C) only with a Windows and Apple identity |
| Qt desktop | source plus the fork's determinism levers; a Flathub manifest | Developer ID plus notarization and Windows signing for DMG and MSI (class C) |
| Qt Android | not before `fdroid/` and `fastlane/` are rewritten (our app id, our brand, no upstream URL) | Play (B); our own F-Droid-format repo (C) |
| Flutter Android, iOS | source; the plan's Linux-first order | Play (B), App Store with an organisation account (B) |
| Dioxus desktop | source, Flathub | as Qt desktop |
| Tauri desktop and mobile | source, Flathub (desktop) | stores (B); no updater until Q6 |
| Tauri web build | local `--serve` only | IPFS with ENS, or an Isolated Web App, or none (Q5) |
| Browser extension | load-unpacked from a local build | AMO first (its rebuild check), then Chrome with verified uploads, then Safari (B) |

**Order (proposal):**

1. The manifest and the verify scripts for the CLI and TUI. They are pure Rust and their build is already pinned.
2. Flathub and AUR.
3. Everything in class B or C after the rulings.

## 8. Open owner questions

- **Q1 (scope of the rule).** Does "no built binaries on GitHub" also forbid a binary we build and upload to a store (class B)
  or host ourselves (class C)? Should it get an anchored entry in `decisions.md` (none exists, §1.1)?
- **Q2 (licence and FLOSS channels).** Accept that F-Droid main, `homebrew/core` and Debian main are closed under
  `LicenseRef-Vegan-Community-1.0`, or license what those channels ship differently? The Qt fork also mixes MPL-2.0 files.
- **Q3 (legal entity and key holder).** Apple wallets need an organisation account [D11]; Windows public-trust signing favours
  organisations with history [D16]; Android verification needs a verified identity [D5]. Who is the publisher, and does the
  owner hold every key on hardware?
- **Q4 (Android developer verification).** Register package names and keys [D5], [D6], or rely on the "advanced flow" for
  unverified apps, as F-Droid advises developers [D4]?
- **Q5 (web wallet).** Host one at all? If so: our own origin, IPFS with ENS, or an Isolated Web App.
- **Q6 (self-updater).** None, or Tauri's or Sparkle's updater with a key the owner holds, and the hosted endpoint it needs
  (class C)?
- **Q7 (Play App Signing).** Let Google generate the app signing key, or upload our own so other stores share it [D8]?
- **Q8 (the Qt fork's packaging).** Rewrite `fdroid/` and `fastlane/` for our app id and brand, or move them to `legacy/`?
- **Q9 (extension stores).** Which of AMO, the Chrome Web Store and Safari, and in which order?
- **Q10 (the manifest key).** Offline Ed25519, or a UA key through `ua-rs` (PQ, but every verifier then needs `ua-rs`)?

## 9. Sources (all read 2026-11-27)

- [D1] F-Droid, "Reproducible Builds": <https://f-droid.org/docs/Reproducible_Builds/>
- [D2] F-Droid, "Anti-Features": <https://f-droid.org/docs/Anti-Features/>
- [D3] F-Droid, "Inclusion Policy": <https://f-droid.org/docs/Inclusion_Policy/>
- [D4] F-Droid, "An Open Letter Opposing Android Developer Verification", 2026-02-24 (read through search snippets): <https://f-droid.org/2026/02/24/open-letter-opposing-developer-verification.html>
- [D5] Android Developers, "Android developer verification": <https://developer.android.com/developer-verification>
- [D6] Android Developers, "Register an app on open-source registry": <https://developer.android.com/developer-verification/guides/open-source-app-registration>
- [D7] AOSP, "APK Signature Scheme v3": <https://source.android.com/docs/security/features/apksigning/v3>
- [D8] Android Developers, "Sign your app": <https://developer.android.com/studio/publish/app-signing>
- [D9] Play Console Help, cryptocurrency exchanges and software wallets: <https://support.google.com/googleplay/android-developer/answer/16329703>
- [D10] Play Console Help, testing requirements for new personal developer accounts (read through search snippets): <https://support.google.com/googleplay/android-developer/answer/14151465>
- [D11] Apple, "App Review Guidelines", 3.1.5: <https://developer.apple.com/app-store/review/guidelines/>
- [D12] Apple, apps in the EU and Web Distribution (read through search snippets): <https://developer.apple.com/support/dma-and-apps-in-the-eu/>, <https://developer.apple.com/support/web-distribution-eu/>
- [D13] Apple, "Notarizing macOS software before distribution": <https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution>
- [D14] Apple, "Packaging and distributing Safari Web Extensions with App Store Connect": <https://developer.apple.com/documentation/safariservices/packaging-and-distributing-safari-web-extensions-with-app-store-connect>
- [D15] SSL.com, "Code Signing Key Storage Requirements Will Change on June 1, 2023" (secondary, through search): <https://www.ssl.com/article/code-signing-key-storage-requirements-will-change-on-june-1-2023/>
- [D16] Microsoft, Artifact Signing FAQ and Q&A threads (search snippets; one answer AI-generated): <https://learn.microsoft.com/en-us/azure/artifact-signing/faq>, <https://learn.microsoft.com/en-us/answers/questions/5810735/cant-create-a-new-trusted-signing-individual-ident>, <https://github.com/Azure/artifact-signing-action>
- [D17] Flathub, "Requirements": <https://docs.flathub.org/docs/for-app-authors/requirements>
- [D18] Snapcraft forum, "Manual review of all new snap name registrations", and The Register, 2024-03-28 (through search): <https://forum.snapcraft.io/t/manual-review-of-all-new-snap-name-registrations/39440>, <https://theregister.com/2024/03/28/canonical_snap_store_scams/>
- [D19] Homebrew, "Acceptable Formulae": <https://docs.brew.sh/Acceptable-Formulae>; release notes 5.0.0 and 6.0.0 (through search): <https://brew.sh/2025/11/12/homebrew-5.0.0>, <https://brew.sh/2026/06/11/homebrew-6.0.0/>
- [D20] Microsoft Learn, "Create your package manifest" (winget): <https://learn.microsoft.com/en-us/windows/package-manager/package/manifest>
- [D21] ArchWiki, "AUR submission guidelines" (refused the automated fetch; not read): <https://wiki.archlinux.org/title/AUR_submission_guidelines>
- [D22] Chrome for Developers, "Chrome Web Store review process": <https://developer.chrome.com/docs/webstore/review-process>
- [D23] Chrome for Developers blog, "Verified uploads in the Chrome Web Store" (read through search snippets): <https://developer.chrome.com/blog/verified-uploads-cws>
- [D24] Chrome for Developers, "Deal with remote hosted code violations": <https://developer.chrome.com/docs/extensions/develop/migrate/remote-hosted-code>
- [D25] Firefox Extension Workshop, "Source code submission": <https://extensionworkshop.com/documentation/publish/source-code-submission/>
- [D26] Firefox Extension Workshop, "Signing and distribution overview": <https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/>
- [D27] Tauri 2, "Updater" plugin: <https://v2.tauri.app/plugin/updater/>
- [D28] Sparkle, "Documentation": <https://sparkle-project.org/documentation/>
- [D29] The Update Framework specification: <https://theupdateframework.github.io/specification/latest/>
- [D30] The rustc book, "Remap source paths": <https://doc.rust-lang.org/rustc/remap-source-paths.html>
- [D31] The Cargo book, "Unstable features", `trim-paths`: <https://doc.rust-lang.org/cargo/reference/unstable.html>
- [D32] Reproducible Builds, "SOURCE_DATE_EPOCH": <https://reproducible-builds.org/docs/source-date-epoch/>
- [D33] F-Droid forum, "Flutter app not reproducible" (read through search snippets): <https://forum.f-droid.org/t/flutter-app-not-reproducible/27462>
- [D34] SLSA v1.0, "Security levels": <https://slsa.dev/spec/v1.0/levels>
- [D35] GitHub Docs, "Artifact attestations": <https://docs.github.com/en/actions/concepts/security/artifact-attestations>
- [D36] Sigstore, "Signing blobs": <https://docs.sigstore.dev/cosign/signing/signing_with_blobs/>
- [D37] `cargo-auditable` README: <https://github.com/rust-secure-code/cargo-auditable>
- [D38] `cargo-cyclonedx` README: <https://github.com/CycloneDX/cyclonedx-rust-cargo>
- [D39] MDN, "Subresource Integrity": <https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity>
- [D40] ENS, "ENSIP-7: Contenthash field": <https://docs.ens.domains/ensip/7>
- [D41] WICG, "Isolated Web Apps" explainer: <https://github.com/WICG/isolated-web-apps/blob/main/README.md>
- [D42] Freedom of the Press Foundation, WEBCAT on addons.mozilla.org (read through search snippets): <https://addons.mozilla.org/en-US/firefox/addon/webcat/>
- [D43] Open Source Initiative, "The Open Source Definition", criterion 6: <https://opensource.org/osd>
