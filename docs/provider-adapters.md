# Provider request adapters

Active model probes require a supported provider and an explicitly selected model.
The scanner never invents a model name or sends a placeholder API key. Unsupported providers,
missing models, and unresolved explicit credentials produce `skipped` security results.
Unknown endpoints are not probed with prompts in GET query strings.

Supported adapters are `openai`, `openai-compatible`, `vllm`, `ollama`, `anthropic`,
`google`, and `gemini`. These identify wire protocols, not a verified server vendor.
Cloud SDK authentication, Azure deployment-specific authentication, Bedrock signing,
streaming responses, tools, and multimodal inputs are not supported by these adapters.

Use explicit local CLI configuration:

```json
{"agents":[{"id":"lab","name":"Lab model","provider":"vllm",
"endpoint":"https://lab.example.test/proxy/v1/models",
"model":"operator-selected-model","api_key_env":"LAB_MODEL_KEY"}]}
```

`api_key_env` names an environment variable. Its value is resolved transiently during
execution and omitted from persisted reports, including reflected copies in findings.
Do not put a literal key in configuration. Use HTTPS when sending credentials remotely.
The `model` remains in the result so the selected target is auditable.

Without an explicit reference, configured `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and
`GEMINI_API_KEY` are used only for their respective official HTTPS API host on port 443.
Automatically discovered proxies never receive those default credentials. Official cloud
hosts without credentials are skipped. Local compatible servers can operate without a key.

Ollama discovery routes `/api/tags` and `/api/generate` map to `/api/chat`, sending
`model`, `messages`, `stream: false`, and a bounded output option. Its generated response
comes from `message.content`. [Ollama API reference](https://docs.ollama.com/api/chat)

vLLM model discovery at `/v1/models` maps to `/v1/chat/completions` with a selected
model and user message. Deployment prefixes are retained.
[vLLM server reference](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)

Anthropic uses `/v1/messages`, the `anthropic-version` header, and `max_tokens`.
Configured keys use `x-api-key`.
[Anthropic Messages reference](https://platform.claude.com/docs/en/api/messages/create)

Gemini uses `/v1beta/models/<model>:generateContent`, `contents` with text parts,
and the configured `x-goog-api-key` header. A complete generateContent endpoint supplies
its own model identifier. [Gemini API reference](https://ai.google.dev/api/generate-content)

Tests use fixture model names, mocked responses, and local data. They do not establish
compatibility with every live model or perform paid provider requests.
