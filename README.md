# [VoidMetric](https://ssii.fzoirm.com) Integrity Adapters

## Open-Source Platforms

| Adapter | Platform | Signal source | Status |
|---|---|---|---|
| [Wazuh](./wazuh/) | SIEM / HIDS | Alert API (`/alerts`) | ✓ Available |
| [Keycloak](./keycloak/) | Identity / AuthN | Admin Events API | ✓ Available |
| [Kubernetes](./k8s/) | Container orchestration | Events API + metrics-server | ✓ Available |

## Enterprise Platforms

Built during onboarding. Data-driven (KV config, no code). The first tenant
using a platform gets their adapter mapped via the governance
console. Subsequent tenants on the same platform reuse the pattern.

| Adapter | Platform | Signal source |
|---|---|---|
| Splunk | SIEM | REST API (`/services/logs`) |
| Okta | Identity / IAM | System Log API |
| CrowdStrike | EDR / XDR | Falcon API (`/incidents`) |
| Microsoft Sentinel | SIEM / SOAR | KQL via ARM |
| Palo Alto Cortex | XDR / Threat intel | Cortex XDR API |

## Deployment modes

- **Managed service:** Deploy the adapter to your own Cloudflare Worker. It POSTs to `void.fzoirm.com`. You get raw `ScoringResult` JSON via the portal API. No portal, no governance console, no automated dispatch.
- **Full platform (self-hosted or onboarded):** You own the ingest endpoint and get the complete platform: integrity portal, governance console, PagerDuty/Slack dispatch, and all tuning controls.   

**Data boundary:** Your raw telemetry never leaves your infrastructure. The adapter normalizes locally and POSTs only a 12-node abstracted matrix (floats in [0,1]). No PII, no raw events, no entity identifiers cross the wire.   