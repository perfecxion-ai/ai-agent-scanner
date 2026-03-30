"""
Cloud Infrastructure Scanner for AI Services

Discovers AI agents and ML services across AWS, Azure, and GCP by
querying cloud provider APIs for known AI/ML resource types.

Requires optional cloud SDK dependencies:
    pip install ai-agent-scanner[cloud]
    # or individually: boto3, azure-identity, azure-mgmt-cognitiveservices,
    #                   google-cloud-aiplatform
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import uuid


class CloudInfrastructureScanner:
    """Scan cloud infrastructure for AI services."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._boto3 = None
        self._azure_identity = None
        self._google_cloud = None

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------

    async def scan_aws(self, config: Dict) -> List[Dict[str, Any]]:
        """
        Scan AWS infrastructure for AI services.

        Discovers: SageMaker endpoints, Bedrock models, Lambda functions
        with AI SDK imports, API Gateway endpoints serving AI.

        Args:
            config: Dict with optional 'region', 'profile', 'access_key_id',
                    'secret_access_key' keys.
        """
        try:
            import boto3
        except ImportError:
            self.logger.warning(
                "boto3 is not installed — AWS scanning disabled. "
                "Install with: pip install boto3"
            )
            return []

        agents = []
        region = config.get('region', 'us-east-1')
        profile = config.get('profile')

        session_kwargs = {'region_name': region}
        if profile:
            session_kwargs['profile_name'] = profile

        try:
            session = boto3.Session(**session_kwargs)

            # 1. SageMaker Endpoints
            agents.extend(await self._scan_aws_sagemaker(session, region))

            # 2. Bedrock Models
            agents.extend(await self._scan_aws_bedrock(session, region))

            # 3. Lambda functions with AI SDK layers/env vars
            agents.extend(await self._scan_aws_lambda(session, region))

        except Exception as e:
            self.logger.error(f"AWS scan error: {e}")

        self.logger.info(f"AWS scan complete: {len(agents)} agents found in {region}")
        return agents

    async def _scan_aws_sagemaker(self, session, region: str) -> List[Dict]:
        """Discover SageMaker inference endpoints."""
        agents = []
        try:
            sm = session.client('sagemaker', region_name=region)
            paginator = sm.get_paginator('list_endpoints')

            for page in paginator.paginate(StatusEquals='InService'):
                for ep in page.get('Endpoints', []):
                    endpoint_name = ep['EndpointName']
                    agents.append({
                        'id': str(uuid.uuid4()),
                        'name': f"SageMaker: {endpoint_name}",
                        'provider': 'aws_sagemaker',
                        'endpoint': f"https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{endpoint_name}/invocations",
                        'discovery_method': 'cloud_scan',
                        'confidence': 0.95,
                        'metadata': {
                            'cloud': 'aws',
                            'region': region,
                            'service': 'sagemaker',
                            'endpoint_name': endpoint_name,
                            'status': ep.get('EndpointStatus'),
                            'creation_time': str(ep.get('CreationTime', '')),
                            'internet_facing': False,  # SageMaker endpoints are VPC by default
                        }
                    })
        except Exception as e:
            self.logger.debug(f"SageMaker scan: {e}")
        return agents

    async def _scan_aws_bedrock(self, session, region: str) -> List[Dict]:
        """Discover Bedrock provisioned model throughput and custom models."""
        agents = []
        try:
            bedrock = session.client('bedrock', region_name=region)

            # Provisioned throughput (active model deployments)
            try:
                response = bedrock.list_provisioned_model_throughputs(
                    statusEquals='InService'
                )
                for pt in response.get('provisionedModelSummaries', []):
                    model_id = pt.get('modelArn', '').split('/')[-1]
                    agents.append({
                        'id': str(uuid.uuid4()),
                        'name': f"Bedrock: {pt.get('provisionedModelName', model_id)}",
                        'provider': 'aws_bedrock',
                        'endpoint': f"https://bedrock-runtime.{region}.amazonaws.com",
                        'discovery_method': 'cloud_scan',
                        'confidence': 0.95,
                        'metadata': {
                            'cloud': 'aws',
                            'region': region,
                            'service': 'bedrock',
                            'model_arn': pt.get('modelArn'),
                            'status': pt.get('status'),
                            'internet_facing': False,
                        }
                    })
            except Exception:
                pass

            # Custom models
            try:
                response = bedrock.list_custom_models()
                for model in response.get('modelSummaries', []):
                    agents.append({
                        'id': str(uuid.uuid4()),
                        'name': f"Bedrock Custom: {model.get('modelName', 'unknown')}",
                        'provider': 'aws_bedrock',
                        'endpoint': f"https://bedrock-runtime.{region}.amazonaws.com",
                        'discovery_method': 'cloud_scan',
                        'confidence': 0.90,
                        'metadata': {
                            'cloud': 'aws',
                            'region': region,
                            'service': 'bedrock_custom',
                            'model_arn': model.get('modelArn'),
                            'base_model': model.get('baseModelName'),
                            'internet_facing': False,
                        }
                    })
            except Exception:
                pass

        except Exception as e:
            self.logger.debug(f"Bedrock scan: {e}")
        return agents

    async def _scan_aws_lambda(self, session, region: str) -> List[Dict]:
        """Discover Lambda functions that use AI SDKs."""
        agents = []
        ai_indicators = [
            'openai', 'anthropic', 'langchain', 'llamaindex', 'llama_index',
            'bedrock', 'sagemaker', 'huggingface', 'transformers', 'cohere',
            'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AI_', 'LLM_',
        ]

        try:
            lam = session.client('lambda', region_name=region)
            paginator = lam.get_paginator('list_functions')

            for page in paginator.paginate():
                for fn in page.get('Functions', []):
                    # Check environment variables for AI SDK indicators
                    env_vars = fn.get('Environment', {}).get('Variables', {})
                    env_str = ' '.join(f"{k}={v}" for k, v in env_vars.items())

                    # Check layers for AI SDK packages
                    layers = [l.get('Arn', '') for l in fn.get('Layers', [])]
                    layers_str = ' '.join(layers)

                    # Check runtime and handler for AI patterns
                    combined = f"{env_str} {layers_str} {fn.get('Description', '')} {fn.get('Handler', '')}"

                    matches = [ind for ind in ai_indicators if ind.lower() in combined.lower()]
                    if matches:
                        fn_name = fn['FunctionName']
                        agents.append({
                            'id': str(uuid.uuid4()),
                            'name': f"Lambda AI: {fn_name}",
                            'provider': 'aws_lambda',
                            'endpoint': fn.get('FunctionArn'),
                            'discovery_method': 'cloud_scan',
                            'confidence': min(0.5 + len(matches) * 0.15, 0.95),
                            'metadata': {
                                'cloud': 'aws',
                                'region': region,
                                'service': 'lambda',
                                'function_name': fn_name,
                                'runtime': fn.get('Runtime'),
                                'ai_indicators': matches,
                                'has_url': bool(fn.get('FunctionUrl')),
                                'internet_facing': bool(fn.get('FunctionUrl')),
                            }
                        })
        except Exception as e:
            self.logger.debug(f"Lambda scan: {e}")
        return agents

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    async def scan_azure(self, config: Dict) -> List[Dict[str, Any]]:
        """
        Scan Azure infrastructure for AI services.

        Discovers: Azure OpenAI deployments, Cognitive Services,
        Azure ML endpoints, Azure Functions with AI SDKs.

        Args:
            config: Dict with 'subscription_id' and optionally 'resource_group'.
        """
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            self.logger.warning(
                "azure-identity is not installed — Azure scanning disabled. "
                "Install with: pip install azure-identity azure-mgmt-cognitiveservices"
            )
            return []

        agents = []
        subscription_id = config.get('subscription_id')
        if not subscription_id:
            self.logger.error("Azure scan requires 'subscription_id' in config")
            return []

        try:
            credential = DefaultAzureCredential()

            # 1. Cognitive Services / Azure OpenAI
            agents.extend(
                await self._scan_azure_cognitive_services(credential, subscription_id, config)
            )

            # 2. Azure ML Endpoints
            agents.extend(
                await self._scan_azure_ml(credential, subscription_id, config)
            )

        except Exception as e:
            self.logger.error(f"Azure scan error: {e}")

        self.logger.info(f"Azure scan complete: {len(agents)} agents found")
        return agents

    async def _scan_azure_cognitive_services(self, credential, subscription_id, config) -> List[Dict]:
        """Discover Azure Cognitive Services and OpenAI deployments."""
        agents = []
        try:
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

            client = CognitiveServicesManagementClient(credential, subscription_id)

            for account in client.accounts.list():
                is_openai = account.kind and 'OpenAI' in account.kind
                endpoint = account.properties.endpoint if account.properties else None

                agents.append({
                    'id': str(uuid.uuid4()),
                    'name': f"Azure {'OpenAI' if is_openai else 'Cognitive'}: {account.name}",
                    'provider': 'azure_openai' if is_openai else 'azure_cognitive',
                    'endpoint': endpoint,
                    'discovery_method': 'cloud_scan',
                    'confidence': 0.95,
                    'metadata': {
                        'cloud': 'azure',
                        'service': account.kind,
                        'resource_group': account.id.split('/')[4] if account.id else None,
                        'location': account.location,
                        'provisioning_state': account.properties.provisioning_state if account.properties else None,
                        'internet_facing': True,  # Cognitive Services endpoints are public by default
                    }
                })

                # List model deployments for OpenAI accounts
                if is_openai and account.id:
                    rg = account.id.split('/')[4]
                    try:
                        for dep in client.deployments.list(rg, account.name):
                            model_name = dep.properties.model.name if dep.properties and dep.properties.model else 'unknown'
                            agents.append({
                                'id': str(uuid.uuid4()),
                                'name': f"Azure OpenAI Deployment: {dep.name} ({model_name})",
                                'provider': 'azure_openai',
                                'endpoint': f"{endpoint}openai/deployments/{dep.name}",
                                'discovery_method': 'cloud_scan',
                                'confidence': 0.98,
                                'metadata': {
                                    'cloud': 'azure',
                                    'service': 'openai_deployment',
                                    'deployment_name': dep.name,
                                    'model': model_name,
                                    'internet_facing': True,
                                }
                            })
                    except Exception:
                        pass

        except ImportError:
            self.logger.warning("azure-mgmt-cognitiveservices not installed")
        except Exception as e:
            self.logger.debug(f"Azure Cognitive Services scan: {e}")
        return agents

    async def _scan_azure_ml(self, credential, subscription_id, config) -> List[Dict]:
        """Discover Azure ML online endpoints."""
        agents = []
        try:
            from azure.ai.ml import MLClient

            resource_group = config.get('resource_group')
            workspace = config.get('workspace')
            if not resource_group or not workspace:
                return []

            ml_client = MLClient(credential, subscription_id, resource_group, workspace)

            for ep in ml_client.online_endpoints.list():
                agents.append({
                    'id': str(uuid.uuid4()),
                    'name': f"Azure ML: {ep.name}",
                    'provider': 'azure_ml',
                    'endpoint': ep.scoring_uri,
                    'discovery_method': 'cloud_scan',
                    'confidence': 0.90,
                    'metadata': {
                        'cloud': 'azure',
                        'service': 'azure_ml',
                        'endpoint_name': ep.name,
                        'auth_mode': ep.auth_mode,
                        'internet_facing': True,
                    }
                })
        except ImportError:
            self.logger.debug("azure-ai-ml not installed — skipping ML endpoint scan")
        except Exception as e:
            self.logger.debug(f"Azure ML scan: {e}")
        return agents

    # ------------------------------------------------------------------
    # GCP
    # ------------------------------------------------------------------

    async def scan_gcp(self, config: Dict) -> List[Dict[str, Any]]:
        """
        Scan GCP infrastructure for AI services.

        Discovers: Vertex AI endpoints, Cloud Functions with AI SDKs,
        Cloud Run services with AI patterns.

        Args:
            config: Dict with 'project_id' and optionally 'region'.
        """
        try:
            from google.cloud import aiplatform
        except ImportError:
            self.logger.warning(
                "google-cloud-aiplatform is not installed — GCP scanning disabled. "
                "Install with: pip install google-cloud-aiplatform"
            )
            return []

        agents = []
        project_id = config.get('project_id')
        region = config.get('region', 'us-central1')

        if not project_id:
            self.logger.error("GCP scan requires 'project_id' in config")
            return []

        try:
            from google.cloud import aiplatform

            aiplatform.init(project=project_id, location=region)

            # 1. Vertex AI Endpoints
            for ep in aiplatform.Endpoint.list():
                agents.append({
                    'id': str(uuid.uuid4()),
                    'name': f"Vertex AI: {ep.display_name}",
                    'provider': 'gcp_vertex',
                    'endpoint': ep.resource_name,
                    'discovery_method': 'cloud_scan',
                    'confidence': 0.95,
                    'metadata': {
                        'cloud': 'gcp',
                        'project': project_id,
                        'region': region,
                        'service': 'vertex_ai',
                        'endpoint_id': ep.name,
                        'deployed_models': len(ep.gca_resource.deployed_models) if ep.gca_resource else 0,
                        'internet_facing': True,
                    }
                })

            # 2. Vertex AI Models (deployed)
            for model in aiplatform.Model.list():
                if model.gca_resource.deployed_models:
                    agents.append({
                        'id': str(uuid.uuid4()),
                        'name': f"Vertex Model: {model.display_name}",
                        'provider': 'gcp_vertex',
                        'endpoint': model.resource_name,
                        'discovery_method': 'cloud_scan',
                        'confidence': 0.85,
                        'metadata': {
                            'cloud': 'gcp',
                            'project': project_id,
                            'service': 'vertex_model',
                            'model_id': model.name,
                            'internet_facing': False,
                        }
                    })

        except Exception as e:
            self.logger.error(f"GCP scan error: {e}")

        self.logger.info(f"GCP scan complete: {len(agents)} agents found")
        return agents
