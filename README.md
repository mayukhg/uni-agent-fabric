# The Universal Agentic Fabric
## Plug-and-Play AI Defense Ecosystem

A universal, plug-and-play security defense ecosystem that normalizes security data from any source using OCSF (Open Cybersecurity Schema Framework) and processes it through an agentic AI core.

## Architecture

The system is built on four distinct layers:

1. **Layer 1: Integration Gateway (The "Plug")** - Modular connectors for various security tools
2. **Layer 2: Normalization Engine (The "Translator")** - OCSF-based data normalization
3. **Layer 3: Unified Data Moat (The "Context")** - Graph database for contextualized data
4. **Layer 4: Agentic Core (The "Play")** - AI-powered risk detection and remediation

## Quick Start

### Prerequisites

- Python 3.9+
- Docker and Docker Compose
- Kubernetes cluster (for production)
- Neo4j or Amazon Neptune (graph database)
- Kafka or NATS (message queue)
- HashiCorp Vault (secrets management)

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Start services with Docker Compose
docker-compose up -d

# Run the application
python -m src.main
```

### Production Deployment

```bash
# Deploy with Helm
helm install agentic-defense ./helm-chart
```

## Project Structure

```
uni-agent-fabric/
├── src/
│   ├── layer1_integration/    # Integration Gateway
│   ├── layer2_normalization/  # Normalization Engine
│   ├── layer3_moat/           # Unified Data Moat
│   ├── layer4_agentic/        # Agentic Core
│   ├── adapters/              # Output Adapters
│   ├── onboarding/            # Onboarding Wizard
│   └── common/                # Shared utilities
├── connectors/                # Connector implementations
├── helm-chart/                # Kubernetes Helm charts
├── docker/                    # Docker configurations
└── tests/                     # Test suite
```

## Documentation

- [PRD.md](PRD.md) - Product Requirements Document
- [IMPLEMENTATION_REQUIREMENTS.md](IMPLEMENTATION_REQUIREMENTS.md) - Implementation requirements

## License

Proprietary

