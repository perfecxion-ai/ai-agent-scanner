# Discovery input boundaries

## Recorded traffic

Traffic discovery reads captured HAR entries, JSON objects or arrays, JSON-lines
records, and text access-log lines containing a complete HTTP request URL.
Structured records accept `url`, `uri`, `request_url`, or `target` in the record
or its `request` object. Relative paths without an authority, compressed files,
packet captures, and arbitrary prose mentions are not supported.

Known provider authorities establish an observed service request. Shared API
paths do not identify a vendor: an unknown proxy using `/v1/chat/completions`
is not labeled OpenAI. Requests do not establish deployment exposure, successful
model execution, or vulnerabilities. Query strings, fragments, and URL userinfo
are removed from output; request headers and bodies are not retained.

Each provider and normalized endpoint has a deterministic asset ID. Each request
record contributes once to the endpoint count. The analyzer reads at most 16 MiB
per file, 64 MiB per source, 50 files, 10,000 directory entries, and 100,000
records per file. UTF-8 is required. Symlinks are rejected.

A missing, unreadable, malformed, or oversized selected source increments the
active scan's failure count. Valid records from other files are preserved and
the shared pipeline reports a partial result. Direct use without an active scan
budget raises an explicit error for incomplete input.

## Cloud inventory

Supported read-only inventories are AWS SageMaker endpoints in service, Bedrock
provisioned throughput and custom models, Lambda configuration candidates,
Azure Cognitive Services accounts and OpenAI deployments, optionally Azure ML
online endpoints, and GCP Vertex AI endpoints. Other services are not queried.
Lambda environment-variable names and layer names provide configuration hints;
secret values do not identify an AI integration and are not retained.

Cloud asset IDs derive from provider resource identity, such as an ARN or Azure
resource ID. Provisioned models remain separate even when they share an underlying
model. An ARN or GCP resource name is not a reachable HTTP endpoint. HTTP targets
are recorded only when the SDK explicitly returns an endpoint. Inventory does
not establish network exposure or support automatic generation testing.

AWS uses the SDK credential chain, a named `profile`, or explicit paired
`access_key_id` and `secret_access_key` (optionally `session_token`). Profiles
and explicit credentials cannot be combined. Azure uses `DefaultAzureCredential`
and requires `subscription_id`; `resource_group` narrows account inventory.
Azure ML additionally requires `resource_group` and `workspace`. GCP uses the
SDK credential chain and requires `project_id`; regions default to `us-central1`.
Provider credentials are never stored in inventory results.

Each service emits at most 1,000 resources and consumes at most 100 pages per
list operation. Repeated Bedrock pagination tokens stop discovery. SDK pagers
that reach the page cap are conservatively incomplete even when that page may
be their last. AWS applies five-second connection and ten-second read timeouts
with bounded retries; GCP disables endpoint-list retries and applies ten-second
request timeouts. Azure retains SDK timeout defaults. Provider SDK requests run
in worker threads and do not use the HTTP probe transport; cancellation cannot
interrupt a synchronous SDK request already in progress.

Missing dependencies, invalid provider configuration, permission failures, and
inventory limits increment the active scan's failure count. Previously observed
resources and healthy services are retained; the pipeline reports partial
execution. Exceptions are logged with fixed operation labels to avoid exposing
credentials embedded in provider errors. Successful empty inventories have no
failure count. Automated tests use mocked SDK objects without provider accounts.

The imported SDKs are `boto3` (including `botocore`), `azure-identity`,
`azure-mgmt-cognitiveservices`, `azure-ai-ml`, and `google-cloud-aiplatform`.
Pagination and scope parameters follow the official
[AWS Bedrock list API](https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock/client/list_provisioned_model_throughputs.html),
[Azure account listing](https://learn.microsoft.com/en-us/python/api/azure-mgmt-cognitiveservices/azure.mgmt.cognitiveservices.operations.accountsoperations?view=azure-python),
[Azure ML endpoint listing](https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.operations.onlineendpointoperations?view=azure-python),
and [GCP endpoint service API](https://docs.cloud.google.com/python/docs/reference/aiplatform/latest/google.cloud.aiplatform_v1.services.endpoint_service.EndpointServiceClient).
