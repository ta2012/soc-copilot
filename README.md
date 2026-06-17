# SOC - COPILOT v.01 (Executive Proof-of-Concept)

This project is a functional **Proof-of-Concept (POC)** simulating the end-to-end multi-agent SIEM log triage pipeline for the target **SOC Co-Pilot** system. 

---

## Executive Summary

To showcase the product flow instantly without requiring active cloud API bills, vector database setups, or corporate API keys, this prototype implements **lightweight string parsing and local heuristics** as placeholders for the AI models:

* **Log Retrieval:** Implements keyword matching and query filtering on a local JSON file in place of a live **ChromaDB** or **Elasticsearch** vector database.
* **Threat Assessment:** Employs pre-defined rule mappings matching user behaviors to output threat severity and MITRE ATT&CK codes, rather than using raw LLM reasoning calls.
* **Report Drafting:** Formulates structured incident triage reports matching detected anomalies using templates instead of real-time text generation models.

This allows stakeholders to immediately evaluate the user experience, orchestration speed, and output structure.

---

## POC vs. Production Architecture

| Component | This Prototype (POC) | Production Target |
| :--- | :--- | :--- |
| **Agent Orchestration** | Procedural Python workflow | **LangGraph** (cyclic graphs with loops & callbacks) |
| **Data Retrieval** | String parsing on `exabeam_logs.json` | Semantic Search over **ChromaDB / Vector database** |
| **Log Source** | Static mock data files | Real-time APIs connected to **Exabeam SIEM** |
| **Log Evaluation** | Heuristic signature checks | **Groq/Llama-3** LLM reasoning (zero-day detection) |
| **Triage Report** | Rule-based Markdown layouts | Dynamically generated reports (via OpenAI/Groq API) |

---

## Running the Demo

### Prerequisites
* Python 3.8 or higher installed on the host machine.

### Installation & Launch
1. **Initialize the local virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
2. **Launch the server:**
   ```powershell
   .\run.ps1
   ```
3. **Open the interface:**
   Navigate to **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser to test the query templates and view the real-time agent execution logs.
