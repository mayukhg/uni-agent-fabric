# Product Requirements Document (PRD)
## Project: The Universal Agentic Fabric ("Plug-and-Play" AI Defense Ecosystem)

| Detail | Value |
|--------|-------|
| Target Release | 2.0 (Plug-and-Play Update) |
| Status | DRAFT |
| Document Owner | Product Management |

---

## 1. Executive Summary & Objective

The objective of this initiative is to evolve the existing Autonomous AI Defense Ecosystem into a "plug-and-play" solution, tentatively named "The Universal Agentic Fabric." Currently, the ecosystem's data ingestion layer is hardcoded to specific platforms. To achieve a true plug-and-play model, we must abstract this layer so the ecosystem can accept security data from any source (e.g., Splunk, AWS Security Hub, CrowdStrike, Azure Sentinel, Tenable) without requiring custom code for every integration.

The core innovation strategy is the implementation of a Universal Normalization Layer sitting between external security tools and the Agentic Core. This strategy is defined by three components:

- **The "Plug"**: Modular Integration Drivers (Connectors).
- **The "Protocol"**: OCSF (Open Cybersecurity Schema Framework) for data normalization.
- **The "Play"**: The existing Agentic Core running on normalized data.

---

## 2. Target Audience & User Experience

The primary users are Security Operations Center (SOC) administrators and security engineers seeking rapid value and easy integration without complex setup.

### Desired User Experience (Onboarding Wizard):

The onboarding process must be a simple, "wizard" style UI that abstracts technical complexity:

1. **Step 1: Select Data Source**: User selects their existing tool from a "Marketplace" menu (e.g., Qualys, Splunk).
2. **Step 2: Input Credentials**: User provides necessary API Keys or URLs.
3. **Step 3: Select Output**: User selects their chat/collaboration tool (e.g., Slack).
4. **Step 4: Connect**: The system finalizes the integration.

---

## 3. Functional Requirements: The Solution Architecture

The architecture is divided into four distinct layers designed to decouple data ingestion from agentic action.

### 3.1 Layer 1: The Integration Gateway (The "Plug")

This layer is responsible for fetching data anonymously, ensuring the Core does not need knowledge of the data origin.

- **FR 1.1 - Modular Connectors**: The system must utilize a library of lightweight, Python-based "API Connectors" as modular integration drivers.
- **FR 1.2 - Authentication & Fetching**: Each connector must authenticate with specific vendor APIs (e.g., Splunk, Tenable, Jira) and fetch raw JSON alerts.
- **FR 1.3 - Secure Auth Storage**: A Secrets Management Vault must be implemented to securely store user API keys for existing tools.
- **FR 1.4 - Automated Scheduling**: Upon user configuration via the UI, the system must auto-configure the ingestion schedule (e.g., every 5 minutes).

### 3.2 Layer 2: The Normalization Engine (The "Translator")

To avoid building separate agents for every tool, this engine converts disparate raw data into a single, unified language.

- **FR 2.1 - Standard Protocol**: The normalization standard must be OCSF (Open Cybersecurity Schema Framework).
- **FR 2.2 - Data Transformation**: The engine must map vendor-specific fields from raw input into the OCSF standard output format.
  - Example Input (Tenable): `{"vuln_id": "CVE-2024-123", "severity": "high"}`
  - Example Output (OCSF): `{"class_uid": 2001, "severity_id": 4, "vulnerability": {"cve": "CVE-2024-123"}}`
- **FR 2.3 - Universal Compatibility**: By normalizing data, the existing "Risk Scoring Engine" must become instantly compatible with any data source that can be mapped to OCSF.

### 3.3 Layer 3: The Unified Data Moat (The "Context")

This layer acts as the single source of truth, stitching normalized data with environmental context.

- **FR 3.1 - Graph Storage**: The moat must use a high-speed Graph Database (e.g., Neo4j or Amazon Neptune) for storage.
- **FR 3.2 - Dynamic Contextualization**: The moat must dynamically ingest data based on its type:
  - If the source provides asset data (e.g., CMDB), it must populate the "Asset Inventory".
  - If the source provides vulnerability data, it must populate risk nodes and link them to assets.

### 3.4 Layer 4: The Agentic Core (The "Play")

The existing Agentic Core pillars must be decoupled from specific input sources and operate solely on data from the Unified Data Moat.

- **FR 4.1 - Pillar 1 (The Eyes)**: The LangGraph State Machine must query the Graph Database to make decisions, identifying "High Risk Objects" regardless of whether the originating alert came from AWS, Azure, etc.
- **FR 4.2 - Pillar 2 (The Shield)**: To support plug-and-play, the edge-optimized SLM must be packaged as a Sidecar Container or WASM Module, injectable into any Kubernetes cluster via a simple Helm Chart.
- **FR 4.3 - Pillar 3 (The Law)**: The Multi-Agent Swarm must utilize a "Config Parser" to standardize various Infrastructure-as-Code templates (Terraform, CloudFormation, ARM) into a generic model for auditing.

### 3.5 Output Adapters

- **FR 5.1 - Action Formatting**: An Output Adapter must format decisions and trigger actions or alerts in external collaboration tools (e.g., Slack/Teams).

---

## 4. Non-Functional Requirements

### 4.1 Latency & Performance

- **NFR 1.1 - Triage SLA**: The normalization layer must be lightweight to ensure the total system maintains a < 5-minute SLA for SOC triage.
- **NFR 1.2 - High Volume Scale**: The system must use stream processing technologies (e.g., Kafka or NATS) to handle high volumes of data (10k+ alerts).

### 4.2 Reliability & Failover

- **NFR 2.1 - Circuit Breaker**: A Circuit Breaker Pattern must be implemented. If the "Plug" (API connection) fails, the system must default to pre-defined "Rule-Based Logic".

### 4.3 Trust & Explainability

- **NFR 3.1 - Source Attribution**: The AI's "Reasoning Log" must explicitly include the source of the data (e.g., "Based on data from Tenable...") to reinforce trust in the integrated solution.

### 4.4 Deployment & Privacy

- **NFR 4.1 - Containerized Delivery**: The solution must be delivered as containerized microservices (Docker/Helm).
- **NFR 4.2 - No SaaS Requirement**: To address privacy concerns, users must be able to deploy the system by running a command like `helm install agentic-defense` directly on their cluster, with no mandatory SaaS component.

---

## 5. Data Flow Summary

The data flow through the Universal Agentic Fabric is as follows:

1. A security tool (e.g., CrowdStrike) generates an alert.
2. The Connector fetches the alert via API (Polling/Webhook).
3. The Normalizer converts the alert to OCSF Standard.
4. The Moat enriches the alert with Asset Context and stores it in the Graph DB.
5. Agent (The Eyes) detects the new High-Risk Node in the Graph and calculates a Risk Score.
6. If the Risk > Threshold, Remediation is triggered.
7. The Output Adapter formats the decision and sends it to Slack/Teams.

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | - | Product Management | Initial draft |

