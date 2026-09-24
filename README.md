# Greenlight

Greenlight is an authorized-use reconnaissance and misconfiguration scanner for penetration testers and security teams. Its defining feature is not any one scan module — it's the **authorization gate**: Greenlight refuses to scan any target that isn't clearly private/loopback unless you've explicitly recorded (or interactively confirmed) authorization to test it, and every scan is written to a local audit log. No gate, no scan.

## Acceptable Use

**Greenlight must only be used against systems you own, or for which you have explicit written permission to test.**

- Unauthorized scanning of systems you do not own or control may be **illegal** under computer-crime laws in your jurisdiction (e.g. the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents elsewhere), even when the scan is passive/read-only.
- Greenlight enforces an authorization gate in code (see below), but that gate is a safety rail, not a legal opinion — recording an authorization note does not make a scan lawful if you don't actually have the underlying permission.
- Greenlight performs **read-only reconnaissance only**. It does not brute-force credentials, send exploit payloads, flood/DoS a target, craft evasive packets, or persist on a target. It identifies potential issues; it does not exploit them.
- You are responsible for keeping your own authorization records (contracts, written permission, signed scope documents) — Greenlight's `.greenlight/authorizations.json` is a local operational log, not a substitute for a real engagement agreement.

If you're not sure whether you're authorized to scan something, you aren't — get it in writing first.

## What it does

1. **DNS recon** — real `A`/`AAAA`/`MX`/`TXT`/`NS` lookups, plus rate-limited subdomain enumeration against a built-in ~90-word list (www, api, staging, admin, ...), flagging publicly-resolvable dev/admin/staging subdomains.
2. **HTTP security headers** — a real HTTP(S) request checking `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`, with a plain-English explanation of what's missing and why it matters.
3. **TLS/SSL configuration** — a real TLS handshake reporting negotiated protocol/cipher and certificate validity, flagging outdated protocols (TLS 1.0/1.1) and expired/near-expiry/not-yet-valid/unverifiable certificates.
4. **Exposure/misconfiguration checks** — real read-only `GET` requests checking for exposed `.git/config`, `.env`, directory listings, and the presence of `security.txt`.
5. **Rate-limited TCP port check** — a concurrency-capped (hard max 20), timeout-bounded TCP connect scan over a small default port list (or a user-specified list/range, capped at 1000 ports unless you pass `--force-wide-scan`).

Everything is implemented with Node's built-in `dns`, `net`, `tls`, and `http`/`https` modules — no exploit payloads, no brute-forcing, no packet crafting, nothing that mutates the target.

## Install / Quick start

```bash
npm install
npm run build
```

Every run prints an authorized-use banner:

```
==================================================================
 GREENLIGHT — Authorized-use reconnaissance scanner
 Only scan systems you own or have explicit written permission to test.
 Unauthorized scanning of systems you do not control may be illegal.
==================================================================
```

### The authorization workflow

Scanning a private/loopback address (127.0.0.1, ::1, RFC1918 10.x/172.16-31.x/192.168.x, or "localhost") never requires authorization — Greenlight assumes that's your own machine/lab:

```bash
node dist/index.js scan 127.0.0.1
```

Scanning anything else without authorization is refused:

```
$ node dist/index.js scan example.com

Authorization refused: No current authorization record found for "example.com" and it is
not a private/loopback address. Run "greenlight authz add example.com --note \"<justification>\""
first, or re-run with --authorize to confirm interactively.
```

Record authorization first, with a justification note (contract reference, written permission, etc.):

```bash
node dist/index.js authz add example.com --note "Written permission from IT director, engagement dated 2026-09-24"
node dist/index.js authz list
node dist/index.js scan example.com
```

Or authorize interactively for a single run, by typing the target hostname back (the same "type X to confirm" pattern used for other high-stakes confirmations):

```bash
node dist/index.js scan example.com --authorize
```
```
You are about to scan "example.com", which is not a private/loopback address.
Greenlight only scans systems you own or are explicitly authorized to test.
Type the target hostname exactly ("example.com") to confirm you have authorization:
```

Revoke authorization when an engagement ends:

```bash
node dist/index.js authz revoke example.com
```

Every scan attempt — authorized or refused — is appended to `.greenlight/audit.log.jsonl` with a timestamp, the target, which modules ran, and how it was authorized.

### Example output

```
$ node dist/index.js scan 127.0.0.1:57009 --modules headers,exposure,ports --scheme http --ports 57009,57010

==================================================================
 GREENLIGHT — Authorized-use reconnaissance scanner
 Only scan systems you own or have explicit written permission to test.
 Unauthorized scanning of systems you do not control may be illegal.
==================================================================

Target: 127.0.0.1
Authorization: literal IP 127.0.0.1 is in a private/loopback range

--- headers ---
  [MEDIUM] Missing Content-Security-Policy header
      Content-Security-Policy restricts which sources of scripts/styles/frames the browser will
      execute or render. Without it, a single injected-HTML bug (e.g. reflected/stored XSS) can
      run arbitrary attacker script with no defense-in-depth backstop.
  [MEDIUM] Missing X-Frame-Options header
      ...
  [LOW] Missing X-Content-Type-Options header
      ...
  [LOW] Missing Referrer-Policy header
      ...
  [INFO] Missing Permissions-Policy header
      ...
  [INFO] Server/technology banner disclosed
      Response advertises: DemoServer/1.0. This makes fingerprinting the software stack (and its
      known CVEs) easier for an attacker; consider suppressing these headers.
--- exposure ---
  [HIGH] Exposed .env file
      A .env-style file is publicly accessible and looks like KEY=VALUE configuration. These
      files commonly contain database credentials, API keys, and secrets. Move it outside the
      web root and block dotfile access.
--- ports ---
  [INFO] Port 57009 is open
      TCP port 57009 accepted a connection. Confirm this service is intended to be reachable
      from this network.

Summary:
  HIGH: 1
  MEDIUM: 2
  LOW: 2
  INFO: 3
```

(Captured against a local Node test HTTP server on loopback — see "Testing" below.)

### Exit codes (CI gate)

- `0` — scan completed, no high-severity findings.
- `1` — scan completed, at least one high-severity finding (use this to fail a CI job).
- `2` — authorization refused, or invalid CLI arguments.
- `3` — the scan itself failed unexpectedly.

## CLI reference

```
greenlight scan <target> [options]
  --authorize              interactively confirm authorization for this run
  --modules <list>         comma-separated: dns,headers,tls,exposure,ports
  --ports <spec>           e.g. "22,80,443" or "1-1024"
  --force-wide-scan        allow port specs wider than 1000 ports
  --port-timeout <ms>      per-connection TCP timeout (default 1000)
  --port-concurrency <n>   max concurrent port connections, hard-capped at 20
  --http-timeout <ms>      HTTP/TLS request timeout (default 5000)
  --scheme <http|https>    scheme for header/exposure checks (default https)
  --json                   machine-readable JSON output

greenlight authz add <target> --note "<justification>" [--days N]
greenlight authz list
greenlight authz revoke <target>
```

## How the authorization gate is enforced

The gate lives in `src/authz.ts`, in `ensureAuthorized()`, and `src/scan.ts`'s `runScan()` is the **only** entry point that runs scan modules — it calls the gate before touching the network, and throws `AuthorizationError` (without running any module) if the gate refuses:

```ts
const decision = await ensureAuthorized(target, {
  authorizeFlag: userOpts.authorizeFlag,
  promptFn: userOpts.promptFn,
});

if (!decision.allowed) {
  appendAuditEntry({ timestamp: new Date().toISOString(), target: host, result: "denied", modules: opts.modules, reason: decision.reason });
  throw new AuthorizationError(decision.reason ?? `Authorization refused for target "${host}".`);
}
```

`ensureAuthorized()` fails closed: a target is only exempt from the gate if it's a literal loopback/RFC1918 address, "localhost", or a hostname that *resolves only* to such addresses (resolution failures are treated as **not** exempt). Otherwise it requires either a current record in `.greenlight/authorizations.json` or a correct interactive confirmation.

## Testing

The automated test suite (Vitest) spins up real local HTTP, TLS, and TCP servers on loopback (`test/fixtures/testServer.ts`) and runs the real scan modules against them — no external network access is used or required. Run it with:

```bash
npm test
```

Coverage includes: the gate refusing an unauthorized non-private target, allowing a loopback target with no authorization, allowing a non-private target after `authz add`, revocation, interactive-prompt confirmation/rejection, audit logging of both denied and successful scans, and each scan module's findings against local fixtures (missing vs. present security headers, exposed `.env`/`.git/config`, directory listings, open/closed ports, TLS handshake + certificate expiry/validity logic, and DNS record/subdomain logic against an injected fake resolver).

## Limitations

Greenlight is a **reconnaissance and misconfiguration scanner**, not a full vulnerability-exploitation framework, and it does not replace a professional penetration test. Specifically:

- It identifies *potential* issues (missing headers, outdated TLS, exposed files, open ports, weak DNS hygiene) — it does not verify exploitability, chain findings together, or attempt to prove impact.
- It has no authenticated-scanning mode, no web-app crawling/spidering, no JavaScript-rendered content analysis, and no support for scanning APIs that require auth tokens.
- The DNS subdomain wordlist is small (~90 entries) and will miss subdomains not in the list; it is not a substitute for certificate-transparency-log or passive-DNS-based enumeration.
- The default port list is intentionally small and common-services-only; a closed/filtered result does not guarantee nothing is listening on an unchecked port.
- TLS/cert findings are based on standard chain validation and expiry; they do not evaluate cipher-suite ordering, OCSP behavior, or advanced misconfigurations beyond protocol version and validity dates.
- False positives/negatives are possible, especially behind load balancers, WAFs, or CDNs that alter headers/responses.
- Rate limiting (max 20 concurrent connections, small default port/word lists, per-connection timeouts) is intentional and non-negotiable — Greenlight is deliberately not tunable into a stress-testing/DoS tool.

Always corroborate findings manually and use professional judgment before reporting them to a client.

## License

MIT — see [LICENSE](./LICENSE).
