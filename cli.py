#!/usr/bin/env python3
"""
AI Agent Scanner CLI Tool
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path

from src.discovery.discovery_engine import DiscoveryEngine, DiscoveryScope


def load_ai_signatures():
    """Load AI service signatures"""
    signatures_path = Path(__file__).parent / "data" / "signatures" / "ai_services.json"
    if not signatures_path.exists():
        print(f"Error: AI signatures file not found at {signatures_path}")
        sys.exit(1)
    
    with open(signatures_path, 'r') as f:
        return json.load(f)


async def main():
    parser = argparse.ArgumentParser(description='AI Agent Scanner')
    parser.add_argument('--network', '-n', help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--domain', '-d', help='Domain to scan (e.g., example.com)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.network and not args.domain:
        print("Error: Must specify either --network or --domain")
        parser.print_help()
        sys.exit(1)
    
    # Load AI signatures
    ai_signatures = load_ai_signatures()
    
    # Create discovery engine
    discovery_engine = DiscoveryEngine()
    
    # Create scope
    scope = DiscoveryScope(
        include_network=True,
        network_ranges=[args.network] if args.network else None,
        domains=[args.domain] if args.domain else None
    )
    
    print("🤖 AI Agent Scanner")
    print("=" * 50)
    
    if args.network:
        print(f"📡 Scanning network: {args.network}")
    if args.domain:
        print(f"🌐 Scanning domain: {args.domain}")
    
    print("\n🔍 Discovering AI agents...")
    
    # Discover agents
    agents = await discovery_engine.discover_agents(scope, ai_signatures)
    
    print(f"\n✅ Discovery complete! Found {len(agents)} potential AI agents")
    
    if agents:
        print("\n🤖 Discovered AI Agents:")
        print("-" * 50)
        
        for i, agent in enumerate(agents, 1):
            print(f"\n{i}. {agent.name}")
            print(f"   Provider: {agent.provider}")
            print(f"   Endpoint: {agent.endpoint}")
            print(f"   Discovery: {agent.discovery_method}")
            print(f"   Confidence: {agent.confidence:.1%}")
            
            if args.verbose:
                print(f"   Metadata: {json.dumps(agent.metadata, indent=6)}")
    
    # Save results if output file specified
    if args.output:
        results = [
            {
                'id': agent.id,
                'name': agent.name,
                'type': agent.type,
                'provider': agent.provider,
                'endpoint': agent.endpoint,
                'discovery_method': agent.discovery_method,
                'confidence': agent.confidence,
                'metadata': agent.metadata
            }
            for agent in agents
        ]
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())