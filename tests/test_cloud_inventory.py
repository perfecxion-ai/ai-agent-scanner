import builtins
import json
import sys
from types import ModuleType, SimpleNamespace as NS

import pytest

from src.core.pipeline import run_pipeline
from src.core.transport import ScanBudget, scan_transport
from src.discovery.cloud_scanner import CloudInfrastructureScanner
from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope


def install_module(monkeypatch, name, **attributes):
    module = ModuleType(name)
    module.__dict__.update(attributes)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def aws_sdk(monkeypatch, denied=False, empty=False, repeated=False):
    calls = []
    resources = [
        {'provisionedModelArn': 'arn:aws:bedrock:us-east-1:123:provisioned-model/a',
         'modelArn': 'arn:aws:bedrock:us-east-1:123:foundation-model/shared'},
        {'provisionedModelArn': 'arn:aws:bedrock:us-east-1:123:provisioned-model/b',
         'modelArn': 'arn:aws:bedrock:us-east-1:123:foundation-model/shared'},
    ]

    def throughputs(**kwargs):
        calls.append(kwargs)
        if empty:
            return {'provisionedModelSummaries': []}
        if kwargs.get('nextToken'):
            return {'provisionedModelSummaries': [resources[1]], **({'nextToken': 'page-2'} if repeated else {})}
        return {'provisionedModelSummaries': [resources[0]], 'nextToken': 'page-2'}

    def client(service, **kwargs):
        if service == 'bedrock':
            return NS(list_provisioned_model_throughputs=throughputs, list_custom_models=lambda: {'modelSummaries': []})
        if service == 'sagemaker':
            if denied:
                raise RuntimeError('AccessDenied synthetic-private-secret')
            pages = [{'Endpoints': [] if empty else [
                {'EndpointArn': 'arn:aws:sagemaker:us-east-1:123:endpoint/lab',
                 'EndpointName': 'lab', 'EndpointStatus': 'InService'}]}]
        else:
            pages = [{'Functions': [] if empty else [
                {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:lab', 'FunctionName': 'lab',
                 'Environment': {'Variables': {'OPENAI_API_KEY': 'synthetic-secret-value'}}},
                {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:unrelated', 'FunctionName': 'unrelated',
                 'Environment': {'Variables': {'ORDINARY_KEY': 'openai only in secret value'}}}]}]
        return NS(get_paginator=lambda operation: NS(paginate=lambda **kwargs: iter(pages)))

    sessions = []

    def session(**kwargs):
        sessions.append(kwargs)
        return NS(client=client)

    install_module(monkeypatch, 'boto3', Session=session)
    install_module(monkeypatch, 'botocore')
    install_module(monkeypatch, 'botocore.config', Config=lambda **kwargs: kwargs)
    return calls, sessions


@pytest.mark.asyncio
async def test_aws_pages_stable_resources_and_no_secret_values(monkeypatch):
    calls, sessions = aws_sdk(monkeypatch)
    budget = ScanBudget()
    config = {'access_key_id': 'synthetic-access', 'secret_access_key': 'synthetic-secret'}
    with scan_transport(budget):
        scanner = CloudInfrastructureScanner()
        result = await scanner.scan_aws(config)
        repeated = await scanner.scan_aws(config)
    assert budget.failures == 0
    assert len(result) == 4
    assert result == repeated
    bedrock = [item for item in result if item['provider'] == 'aws_bedrock']
    assert len({item['id'] for item in bedrock}) == 2
    assert all(item['endpoint'] is None for item in result)
    assert calls[:2] == [{'statusEquals': 'InService'}, {'statusEquals': 'InService', 'nextToken': 'page-2'}]
    assert sessions[0]['aws_secret_access_key'] == 'synthetic-secret'
    assert 'synthetic-' not in json.dumps(result)
    assert next(item for item in result if item['provider'] == 'aws_lambda')['metadata']['evidence_status'] == 'configuration_candidate'
    assert all('internet_facing' not in item['metadata'] for item in result)


@pytest.mark.asyncio
async def test_cloud_denial_preserves_other_inventory_and_pipeline_is_partial(monkeypatch, caplog):
    aws_sdk(monkeypatch, denied=True)
    scope = DiscoveryScope(include_network=False, include_cloud=True, cloud_accounts={'aws': {}})
    report = await run_pipeline(DiscoveryEngine(), None, None, scope, 'discovery_only')
    assert report['status'] == 'partial'
    assert len(report['agents']) == 3
    assert report['transport_incomplete'] is True
    assert 'synthetic-private-secret' not in caplog.text
    assert len({item['id'] for item in report['agents']}) == 3


@pytest.mark.asyncio
async def test_successful_empty_cloud_inventory_has_no_failures(monkeypatch):
    aws_sdk(monkeypatch, empty=True)
    budget = ScanBudget()
    with scan_transport(budget):
        assert await CloudInfrastructureScanner().scan_aws({}) == []
    assert budget.failures == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,module,config', [
    ('aws', 'boto3', {}),
    ('azure', 'azure.identity', {'subscription_id': 'sub'}),
    ('gcp', 'google.cloud', {'project_id': 'project'}),
])
async def test_missing_sdk_is_incomplete(provider, module, config, monkeypatch):
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == module:
            raise ImportError('missing synthetic-secret')
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', importing)
    budget = ScanBudget()
    with scan_transport(budget):
        assert await getattr(CloudInfrastructureScanner(), 'scan_' + provider)(config) == []
    assert budget.failures == 1


@pytest.mark.asyncio
async def test_repeated_pagination_token_stops_with_partial_inventory(monkeypatch):
    calls, _ = aws_sdk(monkeypatch, repeated=True)
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_aws({})
    assert len(calls) == 2
    assert budget.failures == 1
    assert len(result) == 4


@pytest.mark.asyncio
async def test_resource_limit_keeps_observations_but_marks_incomplete(monkeypatch):
    aws_sdk(monkeypatch)
    monkeypatch.setattr('src.discovery.cloud_scanner.MAX_RESOURCES', 1)
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_aws({})
    assert len(result) == 3
    assert budget.failures == 1


def azure_sdk(monkeypatch, deployments_denied=False):
    closed = []
    account_id = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.CognitiveServices/accounts/lab'
    account = NS(id=account_id, name='lab', kind='OpenAI', location='westus', properties=NS(
        endpoint='https://user:synthetic-secret@lab.openai.azure.com?token=synthetic-key',
        public_network_access='Disabled'))
    deployment = NS(id=account_id + '/deployments/model-a', name='model-a', properties=NS(model=NS(name='model')))
    calls = []

    def list_deployments(group, name):
        calls.append((group, name))
        if deployments_denied:
            raise RuntimeError('synthetic-secret-denied')
        return NS(by_page=lambda: iter([iter([deployment])]))

    class Client:
        accounts = NS(list=lambda: NS(by_page=lambda: iter([iter([account])])),
                      list_by_resource_group=lambda group: NS(by_page=lambda: iter([iter([account])])))
        deployments = NS(list=list_deployments)

        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            closed.append('client')

    install_module(monkeypatch, 'azure')
    install_module(monkeypatch, 'azure.identity', DefaultAzureCredential=lambda: NS(close=lambda: closed.append('credential')))
    install_module(monkeypatch, 'azure.mgmt')
    install_module(monkeypatch, 'azure.mgmt.cognitiveservices', CognitiveServicesManagementClient=Client)
    return calls, closed


@pytest.mark.asyncio
async def test_azure_scope_safe_endpoint_and_distinct_deployment_identity(monkeypatch):
    calls, closed = azure_sdk(monkeypatch)
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_azure({'subscription_id': 'sub'})
    assert budget.failures == 0
    assert calls == [('group', 'lab')]
    assert len({item['id'] for item in result}) == 2
    assert result[0]['endpoint'] == 'https://lab.openai.azure.com/'
    assert result[0]['metadata']['endpoint_redacted'] is True
    assert result[1]['endpoint'] is None
    assert result[0]['metadata']['public_network_access'] == 'Disabled'
    assert 'synthetic-' not in json.dumps(result)
    assert closed == ['client', 'credential']


@pytest.mark.asyncio
async def test_azure_deployment_failure_preserves_account(monkeypatch):
    azure_sdk(monkeypatch, deployments_denied=True)
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_azure({'subscription_id': 'sub'})
    assert len(result) == 1
    assert budget.failures == 1


@pytest.mark.asyncio
async def test_azure_ml_scope_and_sdk_scoring_uri(monkeypatch):
    azure_sdk(monkeypatch)
    calls = []

    def ml_client(*args):
        calls.append(args[1:])
        endpoint = NS(id='/subscriptions/sub/resourceGroups/group/providers/Microsoft.MachineLearningServices/workspaces/ws/onlineEndpoints/lab',
                      name='lab', scoring_uri='https://lab.example/score', auth_mode='key', public_network_access='Disabled')
        return NS(online_endpoints=NS(list=lambda: NS(by_page=lambda: iter([iter([endpoint])]))))

    install_module(monkeypatch, 'azure.ai')
    install_module(monkeypatch, 'azure.ai.ml', MLClient=ml_client)
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_azure({'subscription_id': 'sub', 'resource_group': 'group', 'workspace': 'ws'})
    assert budget.failures == 0
    assert calls == [('sub', 'group', 'ws')]
    assert result[-1]['provider'] == 'azure_ml'
    assert result[-1]['endpoint'] == 'https://lab.example/score'


def test_page_budget_does_not_fetch_an_extra_page(monkeypatch):
    monkeypatch.setattr('src.discovery.cloud_scanner.MAX_PAGES', 2)
    visited = []

    def pages():
        for index in range(100):
            visited.append(index)
            yield []

    budget = ScanBudget()
    with scan_transport(budget):
        assert list(CloudInfrastructureScanner()._pages(pages(), 'fixture pages')) == [[], []]
    assert visited == [0, 1]
    assert budget.failures == 1


@pytest.mark.asyncio
async def test_gcp_uses_scoped_endpoint_listing_not_global_state_or_model_property(monkeypatch):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def list_endpoints(self, **kwargs):
            calls.append(kwargs)
            return NS(pages=iter([NS(endpoints=[NS(name='projects/p/locations/r/endpoints/42',
                              display_name='lab', deployed_models=[NS(id='m')])])]))

    install_module(monkeypatch, 'google')
    install_module(monkeypatch, 'google.cloud', aiplatform_v1=NS(EndpointServiceClient=Client))
    budget = ScanBudget()
    with scan_transport(budget):
        result = await CloudInfrastructureScanner().scan_gcp({'project_id': 'p', 'region': 'us-central1'})
    assert budget.failures == 0
    assert calls == [{'client_options': {'api_endpoint': 'us-central1-aiplatform.googleapis.com'}},
                     {'request': {'parent': 'projects/p/locations/us-central1', 'page_size': 100}, 'retry': None, 'timeout': 10}]
    assert result[0]['endpoint'] is None
    assert result[0]['metadata']['deployed_models'] == 1
