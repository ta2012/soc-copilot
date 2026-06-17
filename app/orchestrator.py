import os
from dotenv import load_dotenv
from openai import OpenAI
from app.agents import LogRetrieverAgent, ThreatScorerAgent, ReportWriterAgent

# load environment variables from env file
load_dotenv()

class SOCPilotOrchestrator:
    # Orchestrator Class: routes stuff sequentially between agents
    def __init__(self, logs_path: str = "data/logs.json"):
        self.logs_path = logs_path
        
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
        self.api_base = os.getenv("OPENAI_API_BASE") or os.getenv("GROQ_API_BASE") or None
        self.model = os.getenv("LLM_MODEL", "gpt-3.5-turbo")
        
        self.client = None
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key, base_url=self.api_base)
            
        self.log_retriever = LogRetrieverAgent(logs_path=self.logs_path)
        self.threat_scorer = ThreatScorerAgent(client=self.client, model=self.model)
        self.report_writer = ReportWriterAgent(client=self.client, model=self.model)

    def execute_flow(self, query: str) -> dict:
        # runs the pipeline log retrieve -> threat score -> report write
        trace = []
        
        # Step 0: init
        trace.append({
            "agent": "ORCHESTRATOR",
            "status": "active",
            "message": f"Orchestrator initialized. Analyzing query: '{query}'",
            "output": None
        })
        
        # Step 1: pull relevant logs
        trace.append({
            "agent": "LOG_RETRIEVER",
            "status": "active",
            "message": "Triggered Log Retriever. Querying index database for matching logs...",
            "output": None
        })
        
        try:
            retrieved_logs, retrieve_summary = self.log_retriever.run(query)
            trace.append({
                "agent": "LOG_RETRIEVER",
                "status": "completed",
                "message": retrieve_summary,
                "output": retrieved_logs
            })
        except Exception as e:
            trace.append({
                "agent": "LOG_RETRIEVER",
                "status": "failed",
                "message": f"Log retrieval failed: {str(e)}",
                "output": []
            })
            retrieved_logs = []

        # Step 2: run risk assessment
        trace.append({
            "agent": "THREAT_SCORER",
            "status": "active",
            "message": f"Routing {len(retrieved_logs)} logs to Threat Scorer.",
            "output": None
        })
        
        try:
            threat_data = self.threat_scorer.run(retrieved_logs, query)
            trace.append({
                "agent": "THREAT_SCORER",
                "status": "completed",
                "message": f"Threat scoring completed. Threat level: {threat_data.get('threat_score')}. MITRE techniques: {threat_data.get('mitre_mapping')}",
                "output": threat_data
            })
        except Exception as e:
            threat_data = {
                "threat_score": "UNKNOWN",
                "mitre_mapping": "N/A",
                "reasoning": f"Threat scoring execution error: {str(e)}"
            }
            trace.append({
                "agent": "THREAT_SCORER",
                "status": "failed",
                "message": f"Threat scoring execution failed: {str(e)}",
                "output": threat_data
            })

        # Step 3: create markdown response
        trace.append({
            "agent": "REPORT_WRITER",
            "status": "active",
            "message": "Triggered Report Writer. Formulating security incident report...",
            "output": None
        })
        
        try:
            report_markdown = self.report_writer.run(threat_data, retrieved_logs, query)
            trace.append({
                "agent": "REPORT_WRITER",
                "status": "completed",
                "message": "Incident report compiled successfully.",
                "output": report_markdown
            })
        except Exception as e:
            report_markdown = f"### Report Generation Failed\n\nError: {str(e)}"
            trace.append({
                "agent": "REPORT_WRITER",
                "status": "failed",
                "message": f"Report Writer execution failed: {str(e)}",
                "output": report_markdown
            })

        # Final step: package response trace
        trace.append({
            "agent": "ORCHESTRATOR",
            "status": "completed",
            "message": "Orchestrator flow completed. Output report compiled.",
            "output": {
                "query": query,
                "threat_score": threat_data.get("threat_score"),
                "mitre_mapping": threat_data.get("mitre_mapping"),
                "final_report": report_markdown
            }
        })
        
        return {
            "query": query,
            "mode": "LLM Mode" if self.client else "Simulation Mode (Rule-based)",
            "threat_score": threat_data.get("threat_score"),
            "mitre_mapping": threat_data.get("mitre_mapping"),
            "trace": trace
        }
