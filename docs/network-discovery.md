# Network discovery boundary

Network discovery is bounded, read-only inventory sampling, not vendor ownership,
live generation compatibility, authentication success, or security coverage.
It sends GET requests only. Recognized model inventories are:

- `/v1/models`: a nonempty OpenAI-compatible model list with typed model IDs.
  The provider is `openai-compatible`, not OpenAI or vLLM ownership.
- `/api/tags`: a nonempty Ollama-shaped model list with names and valid
  modification timestamps.
- `/info`: TGI-shaped model identity, a `router: text-generation-router`
  discriminator, nonempty version, and positive integer `max_input_tokens`.
  Older `max_input_length` is accepted only when the current field is absent.
  This field fallback still requires the router discriminator and version;
  historical servers without that discriminator remain unsupported.
  A current field takes precedence; unrelated legacy extension metadata cannot
  invalidate an otherwise supported current response. Router identity is
  self-reported protocol evidence, not ownership or live generation compatibility.

These sampled schemas follow the [OpenAI model-list reference](https://developers.openai.com/api/reference/resources/models/methods/list),
[Ollama model-list reference](https://docs.ollama.com/api/tags), and
[TGI current Info schema](https://github.com/huggingface/text-generation-inference/blob/main/router/src/lib.rs),
[historical input-limit field](https://github.com/huggingface/text-generation-inference/blob/v1.4.5/router/src/lib.rs),
and [TGI read-only route](https://github.com/huggingface/text-generation-inference/blob/main/router/src/server.rs).
Fixtures do not prove compatibility with every live server or future schema.
Header names, authentication challenges, HTML, keywords, and generic JSON key
pairs cannot identify a provider. Empty correctly typed inventories are clean
negatives but do not provide enough evidence to identify a service. Unsupported
provider signatures do not silently receive heuristic network identification.
Code and traffic sources retain their separate provider/domain observations.

## Limits and failures

The scanner samples ten configured common ports per address. Each range is at
most 1024 addresses, with at most 50 simultaneous TCP connection probes. It uses
HTTP on ordinary ports and HTTPS on 443/8443. TLS hosted on other ports, plaintext
on TLS ports, alternate inventory routes, and authenticated inventory are not
fully covered. The TCP connection timeout and each HTTP request timeout are ten
seconds. Existing scan-wide request limits, response limits, cancellation, and
server deadlines still apply.

Discovery bodies are capped at 10,000 bytes in addition to the transport body
limit. JSON container nesting is capped at 32, counting the outer object as one;
this bound does not depend on the Python parser's recursion limit. Non-finite
numeric literals and overflowing numeric exponents are rejected.
Invalid or truncated advertised inventories, duplicate/non-finite JSON,
HTTP 408/429/5xx, DNS failures, unexpected TCP errors, and timeouts make the scan
incomplete. Earlier successful observations remain available. Closed ports,
missing optional routes, redirects, generic pages, and ordinary authorization
responses are normal unidentified observations. No redirect is followed and no
credentials or body text are stored as discovery evidence.

Explicit CLI domain discovery resolves only the requested canonical name, not
guessed subdomains. A and AAAA lookups each have a ten-second lifetime and async
cancellation. A maximum of 32 unique addresses is accepted. Mixed allowed and
forbidden answers fail closed; an over-limit answer set is not scanned. TCP checks
use approved addresses, while a single HTTP observation pass retains the hostname
for Host/SNI and stable endpoint identity. HTTP independently revalidates its DNS
answers through the shared transport policy. These are authority observations,
not a claim that every individual DNS member serves the same inventory.
Hostname observations omit unknown internet exposure rather than treating every
DNS name as public. Literal IP observations use the address's global classification.

The API's admission policy currently normalizes requested domains to approved IP
ranges. Its network discovery therefore remains IP-based and can miss virtual
hosts that require the original hostname. This slice does not change that server
policy or broaden allowed targets.
