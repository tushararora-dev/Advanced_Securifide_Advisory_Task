# 📐 Threat Intelligence Pipeline

## 🎯 Project Objective

A modular and extensible **Threat Intelligence Pipeline** that:
* Ingests threat data from public feeds (IPs, URLs)
* Normalizes, enriches, filters, and de-duplicates the data
* Stores data in JSON
* Exposes the final threat indicators through a REST API (Flask)

## 🧩 Modules Overview

| Module | Role |
|--------|------|
| `Ingestion/` | Fetch raw feeds (Spamhaus, Blocklist.de, DigitalSide) |
| `normalize.py` | Normalize feed data into a consistent JSON schema |
| `enrichment/` | Add metadata like geolocation or classify URL/IP suspicion |
| `deduplicate.py` | Remove duplicates (textual and logical) |
| `storage/` | Save/restore data, manage backups, and metadata |
| `app/` (Flask app) | REST API to expose IOCs and allow refreshing the pipeline |
| `pipeline.py` | Orchestrates ingestion → normalization → enrichment → storage |

## 🔁 System Flow

```
┌─────────────┐
│ CRON / POST │
│   /refresh  │
└──────┬──────┘
       ↓
┌────────────────────┐
│ Ingestion (3 Feeds)│
└────────────────────┘
       ↓
┌────────────────────┐
│   Normalization    │
└────────────────────┘
       ↓
┌────────────────────────────────────┐
│            Enrichment              │
│ - IP Geolocation (mock/ipinfo.io)  │
│ - Suspicious URL Heuristics        │
│ - Optional ML-based classifier     │
└────────────────────────────────────┘
       ↓
┌────────────────────┐
│   De-duplication   │
└────────────────────┘
       ↓
┌────────────────────┐
│    JSON Storage    │
└────────────────────┘
       ↓
┌─────────────────────────────────────┐
│              Flask API              │
│  - /iocs, /refresh, /stats, /health │
└─────────────────────────────────────┘
```

## 🚀 Scaling for Production

| Area | Current Approach | Production Recommendation |
|------|------------------|---------------------------|
| **Feed Scheduling** | Manual or via `POST /refresh` | Use `cron` or task schedulers like **Celery + Redis** |
| **Normalization** | Inline in memory | Batch with parallel processing (e.g., multiprocessing) |
| **Enrichment** | Local mock or API | Offload to a queue system (e.g., **RabbitMQ** + workers) |
| **Storage** | JSON file | Move to **MongoDB** or **Elasticsearch** for better querying |
| **API** | Flask standalone | Deploy via **Gunicorn** + **Nginx**, containerize with **Docker** |
| **Data Growth** | Full overwrite | Incremental updates with deduplication and versioning |
| **Monitoring** | Logs only | Integrate **Prometheus/Grafana** or cloud-based monitoring |
| **Security** | None | Add **API keys, rate limiting, IP whitelisting**, HTTPS |

## 🧠 Assumptions

* IP enrichment is mocked locally using `mock_ip_db.json` due to rate limits on `ipinfo.io`
* JSON is used for storage simplicity (instead of Mongo/Elastic)
* Flask is hosted locally for demo purposes
* ML classifier (if used) is heuristic-based or rule-based, not production-grade
* Feed reliability and formatting are assumed to be stable
* IOC confidence scoring is custom and domain-specific, not learned

## ✅ Key Strengths

* **Modular design** — easy to replace/enhance each step (e.g., plug-in ML model)
* **Human-readable storage** + easy debugging
* **Real-world feeds** (Spamhaus, Blocklist.de) provide realistic threat data
* **Good coverage** of key cybersecurity techniques (enrichment, deduplication, classification)

## 📌 Suggested Enhancements

* Use **async I/O** for faster feed downloads
* Replace local deduplication with **Bloom filters** for scale
* Add **authentication** for API endpoints
* Add **real-time alerting** for high-confidence IOCs

## 🛠️ Quick Start

1. **Setup Environment**
   - Install required dependencies
   - Configure feed sources
   - Initialize storage directories

2. **Run Pipeline**
   - Execute manual pipeline run
   - Or trigger via API endpoint

3. **Access Data**
   - Query IOCs via REST API
   - Monitor pipeline health
   - View statistics and metrics

## 📊 API Endpoints

- `GET /iocs` - Retrieve threat indicators
- `POST /refresh` - Trigger pipeline refresh
- `GET /stats` - View pipeline statistics  
- `GET /health` - Check system health

## 🔧 Configuration

The pipeline supports configuration through environment variables and configuration files for:
- Feed source URLs and credentials
- Enrichment service settings
- Storage backends
- API security settings
- Logging levels and destinations

