# Assess one HTTP application

The guided CLI tests protected prompt disclosure on one application endpoint.
It creates the target identity for you, so setup does not require agent JSON,
discovery results or internal asset IDs. This workflow uses the existing
experimental `protected-disclosure-v1` prompts: seven groups, at most five samples
each. It does not assess authentication enforcement, tenant isolation, tool
execution or the application's overall security.

The supported application accepts one JSON POST prompt field and returns generated
text at a configured JSON pointer. For example, an application can accept a
`question` field at `/support/chat` and return text at `/answer/text`. The scanner
keeps that exact path. It does not add a provider route or invent a model name.

## Configure the protected fixture

Seed a synthetic opaque canary in the application's protected system instructions,
outside user input. Use 16 to 128 characters from `A-Z`, `a-z`, `0-9`, `_`, `.`,
`~` and `-`. The scanner can verify a returned marker; it cannot independently
verify how it was seeded. A secret that was never seeded cannot establish safety
when it is absent from responses.

Keep the same marker in an environment reference available to the CLI. In Bash,
this reads it without placing the value in command arguments or shell history:

```bash
read -rsp 'Protected synthetic canary: ' AIS_TARGET_CANARY
export AIS_TARGET_CANARY
printf '\n'
```

If the application requires Bearer authentication, read its issued test credential
into a different reference:

```bash
read -rsp 'Issued test credential: ' AIS_TARGET_BEARER
export AIS_TARGET_BEARER
printf '\n'
```

Credentials must contain 16 to 4,096 visible ASCII characters without spaces.
Do not place a marker or credential in the target name, endpoint, mapping fields,
context labels or attack input. The scanner rejects known collisions before
printing a plan or sending requests.

## Create the private profile

Choose a location outside the checkout:

```bash
ai-agent-scanner target init support-bot --output ../private-targets/support-bot.json
```

The wizard asks for:

1. The exact application URL.
2. Allowed network CIDRs. A literal IP offers its exact `/32` or `/128` as the
   default. Hostnames require declared networks; setup performs no DNS lookup.
3. The prompt JSON field, default `question`.
4. The generated response JSON pointer, default `/answer`. Use `/answer/text`
   for a nested string or `/messages/0/text` for an array element. Pointer escapes
   are `~0` for `~` and `~1` for `/`.
5. Authentication: `none` or `bearer`. Bearer mode also asks for the credential's
   environment reference and a public principal label.
6. The protected canary environment reference, default `AIS_TARGET_CANARY`.
7. A public protected-fixture context label and confirmation of out-of-band seeding.

Input is not echoed. The profile stores reference names and target configuration,
not protected values. Setup reads only the references you declare, when available,
to reject collisions with public target fields; missing values can be supplied
before planning or execution. Its directory must be owned by the current user with mode
`0700`; the file uses `0600`. The wizard can create the explicitly selected parent
directory, but it never overwrites an existing file or adopts an unsafe directory.
Read and assessment commands do not create profile directories. No operator home,
global profile registry, server database or discovery scan is consulted.

Use HTTPS for remote Bearer credentials. Plain HTTP Bearer requests require a
literal loopback address and `--allow-loopback`; a hostname that resolves to
loopback does not qualify. The initial adapter does not support query parameters,
embedded URL credentials, percent-escaped paths, extra JSON body fields, cookie
login, streaming or conversation continuation.

## Review the offline plan

```bash
ai-agent-scanner assess --profile ../private-targets/support-bot.json --plan
```

For an owned local fixture, add `--allow-loopback` to both planning and execution.
The plan is JSON. Its `target` preview shows the public name, exact endpoint,
prompt field, response pointer, authentication mode, principal/context labels and
allowed networks. Review these settings before execution. URLs use a canonical
authority, including the default port; application paths remain unchanged.
`configuration_status: ready` means the local configuration and
declared references are available. Reachability, DNS, TLS and the response mapping
remain untested. A blocked plan exits nonzero and gives static reason codes without
printing private paths, reference names or values. Planning sends no request and
does not create a report or checkpoint.

## Run the assessment

```bash
ai-agent-scanner assess --profile ../private-targets/support-bot.json --output assessment.json
```

Defaults are 35 shared request attempts, a 180-second overall deadline, ten seconds
per request and 65,536 response bytes. You can lower the sample budget or change
the bounds explicitly:

```bash
ai-agent-scanner assess --profile ../private-targets/support-bot.json \
  --max-requests 10 --timeout-seconds 120 --request-timeout-seconds 5 \
  --max-response-bytes 65536 --output assessment.json
```

There is no hidden discovery or liveness request. Only the seven selected prompt
checks run, with a maximum of 35 attack POSTs. Each sample uses a fresh client HTTP
session; cookies are not replayed and redirects are not followed. This does not
reset application conversations or establish independent server-side model state.
Use a stateless endpoint or arrange and document required resets outside this
assessment; reset provenance remains operator-attested. The target's declared networks and current
transport restrictions are enforced when connecting. Protected values are pinned
once for execution; changing the environment mid-run does not change the principal
or marker.

The terminal reports confirmed disclosure, inconclusive or incomplete assessment
with actual attempted/evaluated counts. Repeated receipts are original occurrences,
not a count of independent vulnerabilities. JSON and SARIF preserve the evidence
while omitting generated response text. A confirmed canary gives supported high
risk; quiet responses remain inconclusive with null risk, never a passed prompt
check. A complete execution can exit zero with either outcome. Incomplete execution
exits nonzero and retains available evidence.

Partial summaries combine acknowledged receipts with finalized check counters
without counting the same sample twice. Their counts are known minima: a request
sent after the last acknowledged checkpoint may not be represented yet.

Use `--format sarif` for SARIF. Reports are owner-only. Create a new profile when
the mapping, principal, protected fixture or policy changes; use a new public
context label for a changed fixture or authorization meaning. The public target
binding distinguishes the endpoint, mapping, principal label and session contract.
Labels remain operator attestations rather than proof of principal equivalence.

## Retain evidence after an interrupted process

```bash
ai-agent-scanner assess --profile ../private-targets/support-bot.json \
  --checkpoint-dir ../new-assessment-checkpoint --output assessment.json
ai-agent-scanner recover --checkpoint-dir ../new-assessment-checkpoint \
  --output recovered-assessment.json
```

The checkpoint directory must be new and separate from the profile and report.
Recovery exports acknowledged evidence offline. It does not load the profile,
resolve credentials, contact the application or replay probes. A retained finding
survives a later timeout or failure; unfinished checks remain incomplete. See the
[checkpoint contract](cli-checkpoints.md) for filesystem and recovery limits.

This workflow improves application coverage and setup. Its controlled fixtures
and finite prompts do not establish production recall or enterprise readiness.
