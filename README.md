# Azure SOC Home Lab – Honeypot with Microsoft Sentinel

## 📌 Overview
This project demonstrates a cloud-based Security Operations Center (SOC) lab built in Microsoft Azure to simulate and detect real-world attack activity.

A publicly exposed Windows VM was deployed as a honeypot. Security events were ingested into Microsoft Sentinel (SIEM), enriched with GeoIP data, and visualized using a custom attack map workbook.

---

## 🏗 Architecture

- Azure Subscription
- Resource Group (SOC-Lab)
- Virtual Network (VNet)
- Windows Virtual Machine
- Network Security Group (RDP exposed)
- Log Analytics Workspace
- Microsoft Sentinel
- GeoIP Watchlist
- Custom Workbook (Attack Map)

---

## 🔍 Detection Workflow

1. Deployed Windows VM in Azure
2. Exposed RDP (3389) to public internet
3. Collected failed login attempts (Event ID 4625)
4. Ingested logs via Azure Monitor Agent (AMA)
5. Queried logs using KQL
6. Enriched attacker IPs using GeoIP watchlist
7. Visualized global attack origins in Sentinel workbook

---

## 🧠 Sample KQL Query

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");

SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)