# ITSC Incident RAG Platform

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68+-009688.svg)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.15-005571.svg)
![Google Gemini](https://img.shields.io/badge/AI-Google%20Gemini-4285F4.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## 📌 Overview

The **ITSC Incident RAG Platform** is an AI-powered Security Operations Center (SOC) support system designed to automate the analysis of security incident logs. By leveraging **Retrieval-Augmented Generation (RAG)**, the platform correlates incoming incident tickets with the **MITRE ATT&CK** knowledge base to suggest precise mitigation strategies and identify related threats.

this project aims to reduce the Mean Time to Response (MTTR) for SOC analysts by providing context-aware AI insights directly within their investigation workflow.

## ✨ Key Features

- **🤖 AI-Automated Analysis**: Automatically analyzes incident logs using Google Gemini and Qdrant to map threats to MITRE ATT&CK patterns.
- **🛡️ Mitigation Recommendations**: Generates actionable course-of-action plans for identified threats.
- **📊 Real-time Dashboard**: Visualizes critical alerts, pending analysis, and resolved cases.
- **🔍 Advanced Search**: Full-text search capabilities across incident logs via Elasticsearch.
- **✅ SOC Workflow Management**: Integrated tools for analysts to review, rate, and select AI-suggested actions.

## 🛠️ Tech Stack

- **Backend Framework**: Python (FastAPI)
- **AI & LLM Integration**: LangChain, Google Gemini Pro
- **Vector Database**: Qdrant (Knowledge Base Storage)
- **Log Storage**: Elasticsearch (Incident Logs)
- **Primary Database**: PostgreSQL (User Management & Metadata)
- **Infrastructure**: Docker & Docker Compose

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed:
- [Docker](https://www.docker.com/) & Docker Compose
- [Python 3.9+](https://www.python.org/)
- Google Cloud API Key (with Vertex AI/Gemini access)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/rag_itsc.git
   cd rag_itsc
   ```

2. **Environment Configuration**
   Create a `.env` file in the root directory based on the template below:

   ```env
   # Database & Infrastructure
   ES_URL=http://localhost:9200
   ES_INDEX=cmu-incidents-fastapi
   QDRANT_HOST=localhost
   QDRANT_PORT=6333
   
   # AI Configuration
   GEMINI_API_KEY=your_google_api_key_here
   COLLECTION_NAME=mitre_attack_collection
   VECTOR_DIMS=768
   STIX_FILE_PATH=./data/mitre-attack.json

   # Security
   SECRET_KEY=your_super_secret_key
   ALGORITHM=HS256
   
   # PostgreSQL
   POSTGRES_USER=admin
   POSTGRES_PASSWORD=password
   POSTGRES_DB=rag_db
   ```

3. **Start Infrastructure**
   Run the following to start Elasticsearch, Kibana, Qdrant, and PostgreSQL:
   ```bash
   docker-compose up -d
   ```

4. **Install Dependencies**
   Create a virtual environment and install Python packages:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

5. **Ingest Knowledge Base** (First time only)
   Populate the vector database with MITRE ATT&CK data:
   ```bash
   python ingest_data.py
   ```

### 🏃‍♂️ Running the Application

Start the FastAPI server:
```bash
python -m uvicorn app.main:app --reload
```
- **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Kibana Dashboard**: [http://localhost:5601](http://localhost:5601)

## 📂 Project Structure

```
rag_itsc/
├── app/
│   ├── api/            # API Endpoints (Auth, Dashboard, Analysis)
│   ├── core/           # Config & Security (JWT, Deps)
│   ├── db/             # Database Connections (Elasticsearch, Postgres)
│   ├── services/       # AI Engine & External Services
│   └── main.py         # Application Entrypoint
├── data/               # Static Data (STIX/MITRE JSONs)
├── elasticsearch/      # ES Configs
├── docker-compose.yml  # Container Orchestration
├── ingest_data.py      # Vector DB Ingestion Script
└── requirements.txt    # Python Dependencies
```

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

---
**Developed for ITSC Security Operations**
