# [VoidMetric](https://ssii.fzoirm.com) Integrity Adapters
Enterprise and open-source platforms.

Standalone Cloudflare Workers that pull signals from security and identity
platforms, normalize them into VoidMetric's 4×3 Systemic Integrity matrix,
and POST scoring data to your VoidMetric ingest endpoint.

**Zero platform modification.** No custom decoders, no SPIs, no CRDs,
no sidecars, no output modules. Reads only from standard API surfaces.

## Open-Source Platforms

| Adapter | Platform | Signal source |
|---------|----------|---------------|
| [Wazuh](./wazuh/) | SIEM / HIDS | Alert API (`/alerts`) |
| [Keycloak](./keycloak/) | Identity / AuthN | Admin Events API |
| [Kubernetes](./k8s/) | Container orchestration | Events API + metrics-server |

## Enterprise Platforms

| Adapter | Platform | Signal source |
|---------|----------|---------------|
| [Splunk](./splunk/) | SIEM | REST API (`/services/logs`) |
| [Okta](./okta/) | Identity / IAM | System Log API |
| [CrowdStrike](./crowdstrike/) | EDR / XDR | Falcon API (`/incidents`) |
| [Microsoft Sentinel](./sentinel/) | SIEM / SOAR | KQL via ARM |
| [Palo Alto Cortex](./cortex/) | XDR / Threat intel | Cortex XDR API |

## Quick start

...   
