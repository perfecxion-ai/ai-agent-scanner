"""Bounded read-only cloud inventory, distinct from live generation testing."""

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit

from src.core.transport import current_budget


MAX_RESOURCES = 1000
MAX_PAGES = 100


class CloudInfrastructureScanner:
    """Inventory supported resources with ambient SDK credentials or a profile."""

    @staticmethod
    def _failure(operation):
        # Provider exceptions may include signed URLs or credentials.
        logging.getLogger(__name__).warning('Cloud discovery incomplete: %s', operation)
        budget = current_budget()
        if budget is None:
            raise ValueError('Cloud discovery incomplete') from None
        budget.failures += 1

    def _bounded(self, records, limit, operation):
        for index, record in enumerate(records):
            if index >= limit:
                self._failure(operation + ' limit')
                return
            yield record

    def _pages(self, pages, operation):
        # Do not fetch an extra provider page merely to detect the limit.
        iterator = iter(pages)
        for _ in range(MAX_PAGES):
            try:
                page = next(iterator)
            except StopIteration:
                return
            yield page
        self._failure(operation + ' limit')

    def _operation(self, operation, function, *args):
        agents = []
        try:
            for agent in self._bounded(function(*args), MAX_RESOURCES, operation):
                agents.append(agent)
        except Exception:
            self._failure(operation)
        return agents

    @staticmethod
    def _asset(provider, resource_id, name, metadata, endpoint=None, confidence=0.95):
        if not isinstance(resource_id, str) or not resource_id:
            raise ValueError('Cloud resource lacks identity')
        # SDK-returned HTTP endpoints are observations; ARNs are never HTTP targets.
        safe_endpoint = None
        if isinstance(endpoint, str):
            parsed = urlsplit(endpoint)
            if parsed.scheme in {'http', 'https'} and parsed.hostname:
                host = parsed.hostname
                authority = f'[{host}]' if ':' in host else host
                if parsed.port:
                    authority += f':{parsed.port}'
                safe_endpoint = urlunsplit((parsed.scheme, authority, parsed.path or '/', '', ''))
                if parsed.username is not None or parsed.password is not None or parsed.query:
                    metadata = {**metadata, 'endpoint_redacted': True}
        return {
            'id': str(uuid.uuid5(uuid.NAMESPACE_URL, f'cloud:{provider}:{resource_id}')),
            'name': name, 'provider': provider, 'endpoint': safe_endpoint,
            'discovery_method': 'cloud_scan', 'confidence': confidence,
            'metadata': {'resource_id': resource_id, 'evidence_status': 'inventory_observation', **metadata},
        }

    async def scan_aws(self, config: Dict) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._aws, config)

    def _aws(self, config):
        try:
            import boto3
            from botocore.config import Config

            region = config.get('region', 'us-east-1')
            session_kwargs = {'region_name': region}
            if config.get('profile'):
                session_kwargs['profile_name'] = config['profile']
            if any(config.get(key) for key in ('access_key_id', 'secret_access_key', 'session_token')):
                if config.get('profile') or not config.get('access_key_id') or not config.get('secret_access_key'):
                    raise ValueError('AWS static credentials require a pair and no profile')
                session_kwargs.update(aws_access_key_id=config['access_key_id'],
                                      aws_secret_access_key=config['secret_access_key'])
                if config.get('session_token'):
                    session_kwargs['aws_session_token'] = config['session_token']
            session = boto3.Session(**session_kwargs)
            options = Config(connect_timeout=5, read_timeout=10, retries={'max_attempts': 2})
        except Exception:
            self._failure('aws initialization')
            return []
        agents = []
        for service, operation in [('sagemaker', self._aws_sagemaker),
                                   ('bedrock', self._aws_bedrock), ('lambda', self._aws_lambda)]:
            # Separate services preserve healthy observations when access is denied elsewhere.
            agents.extend(self._operation('aws ' + service, operation, session, region, options))
        return agents

    def _aws_sagemaker(self, session, region, options):
        client = session.client('sagemaker', region_name=region, config=options)
        pages = client.get_paginator('list_endpoints').paginate(StatusEquals='InService')
        for page in self._pages(pages, 'aws sagemaker pages'):
            for endpoint in page.get('Endpoints', []):
                resource_id = endpoint['EndpointArn']
                yield self._asset('aws_sagemaker', resource_id, f"SageMaker: {endpoint['EndpointName']}", {
                    'cloud': 'aws', 'region': region, 'service': 'sagemaker',
                    'endpoint_name': endpoint['EndpointName'], 'status': endpoint.get('EndpointStatus'),
                })

    def _aws_pages(self, method, list_key, operation, **kwargs):
        token = None
        seen_tokens = set()
        for _ in range(MAX_PAGES):
            response = method(**kwargs, **({'nextToken': token} if token else {}))
            yield from response.get(list_key, [])
            token = response.get('nextToken')
            if not token:
                return
            if token in seen_tokens:
                self._failure(operation + ' repeated token')
                return
            seen_tokens.add(token)
        self._failure(operation + ' page limit')

    def _aws_bedrock(self, session, region, options):
        client = session.client('bedrock', region_name=region, config=options)
        # Each list operation has its own failure boundary.
        for method, key, service, arguments in [
            (client.list_provisioned_model_throughputs, 'provisionedModelSummaries', 'bedrock', {'statusEquals': 'InService'}),
            (client.list_custom_models, 'modelSummaries', 'bedrock_custom', {}),
        ]:
            try:
                for resource in self._aws_pages(method, key, 'aws ' + service, **arguments):
                    identity_key = 'provisionedModelArn' if service == 'bedrock' else 'modelArn'
                    resource_id = resource[identity_key]
                    name = resource.get('provisionedModelName') or resource.get('modelName') or resource_id
                    yield self._asset('aws_bedrock', resource_id, f'Bedrock: {name}', {
                        'cloud': 'aws', 'region': region, 'service': service,
                        'model_arn': resource.get('modelArn'), 'status': resource.get('status'),
                    })
            except Exception:
                self._failure('aws ' + service)

    def _aws_lambda(self, session, region, options):
        client = session.client('lambda', region_name=region, config=options)
        indicators = ('openai', 'anthropic', 'langchain', 'llamaindex', 'llama_index',
                      'bedrock', 'sagemaker', 'huggingface', 'transformers', 'cohere')
        pages = client.get_paginator('list_functions').paginate()
        for page in self._pages(pages, 'aws lambda pages'):
            for function in page.get('Functions', []):
                # Names identify configuration hints; secret values are not inspected or retained.
                hints = ' '.join(function.get('Environment', {}).get('Variables', {}).keys())
                hints += ' ' + ' '.join(layer.get('Arn', '') for layer in function.get('Layers', []))
                matches = [indicator for indicator in indicators if indicator in hints.lower()]
                if matches:
                    yield self._asset('aws_lambda', function['FunctionArn'], f"Lambda AI: {function['FunctionName']}", {
                        'cloud': 'aws', 'region': region, 'service': 'lambda',
                        'function_name': function['FunctionName'], 'runtime': function.get('Runtime'),
                        'ai_indicators': matches, 'evidence_status': 'configuration_candidate',
                    }, confidence=0.6)

    async def scan_azure(self, config: Dict) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._azure, config)

    def _azure(self, config):
        try:
            from azure.identity import DefaultAzureCredential

            subscription = config['subscription_id']
            if not subscription:
                raise ValueError('Azure requires subscription_id')
            credential = DefaultAzureCredential()
        except Exception:
            self._failure('azure initialization')
            return []
        try:
            agents = self._operation('azure cognitive services', self._azure_cognitive, credential, subscription, config)
            if config.get('resource_group') or config.get('workspace'):
                if not config.get('resource_group') or not config.get('workspace'):
                    self._failure('azure ml scope')
                else:
                    agents.extend(self._operation('azure ml', self._azure_ml, credential, subscription, config))
            return agents
        finally:
            try:
                credential.close()
            except Exception:
                self._failure('azure credential cleanup')

    def _azure_cognitive(self, credential, subscription, config):
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        with CognitiveServicesManagementClient(credential, subscription) as client:
            accounts = (client.accounts.list_by_resource_group(config['resource_group'])
                        if config.get('resource_group') else client.accounts.list())
            for account in self._bounded(self._azure_records(accounts, 'azure account pages'), MAX_RESOURCES, 'azure accounts'):
                properties = account.properties
                is_openai = account.kind == 'OpenAI'
                metadata = {'cloud': 'azure', 'service': account.kind, 'location': account.location,
                            'public_network_access': getattr(properties, 'public_network_access', None)}
                yield self._asset('azure_openai' if is_openai else 'azure_cognitive', account.id,
                                  f'Azure: {account.name}', metadata,
                                  endpoint=getattr(properties, 'endpoint', None))
                if is_openai:
                    parts = account.id.split('/')
                    if len(parts) < 5 or parts[3].lower() != 'resourcegroups':
                        self._failure('azure account resource identity')
                        continue
                    try:
                        deployments = self._azure_records(client.deployments.list(parts[4], account.name), 'azure deployment pages')
                        for deployment in self._bounded(deployments, MAX_RESOURCES, 'azure deployments'):
                            model = getattr(deployment.properties, 'model', None)
                            yield self._asset('azure_openai', deployment.id, f'Azure OpenAI Deployment: {deployment.name}', {
                                **metadata, 'service': 'openai_deployment', 'deployment_name': deployment.name,
                                'model': getattr(model, 'name', None),
                            })
                    except Exception:
                        self._failure('azure deployments')

    def _azure_records(self, pager, operation):
        for page in self._pages(pager.by_page(), operation):
            yield from page

    def _azure_ml(self, credential, subscription, config):
        from azure.ai.ml import MLClient

        client = MLClient(credential, subscription, config['resource_group'], config['workspace'])
        for endpoint in self._azure_records(client.online_endpoints.list(), 'azure ml pages'):
            yield self._asset('azure_ml', endpoint.id, f'Azure ML: {endpoint.name}', {
                'cloud': 'azure', 'service': 'azure_ml', 'endpoint_name': endpoint.name,
                'auth_mode': endpoint.auth_mode,
                'public_network_access': getattr(endpoint, 'public_network_access', None),
            }, endpoint=endpoint.scoring_uri)

    async def scan_gcp(self, config: Dict) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._gcp, config)

    def _gcp(self, config):
        return self._operation('gcp vertex endpoints', self._gcp_endpoints, config)

    def _gcp_endpoints(self, config):
        from google.cloud import aiplatform_v1

        project = config['project_id']
        if not project:
            raise ValueError('GCP requires project_id')
        region = config.get('region', 'us-central1')
        if not isinstance(region, str) or not re.fullmatch(r'[a-z][a-z0-9-]+', region):
            raise ValueError('Invalid GCP region')
        # Low-level pager avoids the high-level SDK eagerly fetching every page.
        with aiplatform_v1.EndpointServiceClient(client_options={'api_endpoint': f'{region}-aiplatform.googleapis.com'}) as client:
            pager = client.list_endpoints(request={'parent': f'projects/{project}/locations/{region}', 'page_size': 100},
                                          retry=None, timeout=10)
            for page in self._pages(pager.pages, 'gcp endpoint pages'):
                for endpoint in page.endpoints:
                    yield self._asset('gcp_vertex', endpoint.name, f'Vertex AI: {endpoint.display_name}', {
                        'cloud': 'gcp', 'project': project, 'region': region, 'service': 'vertex_ai',
                        'endpoint_id': endpoint.name.rsplit('/', 1)[-1],
                        'deployed_models': len(endpoint.deployed_models),
                    })
