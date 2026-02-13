from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from typing import TypedDict, List, Dict, Any, Optional


class TicketState(TypedDict):
    ticket_id: str
    original_content: str
    customer_email: str
    current_step: str
    agent_decisions: List[Dict[str, Any]]
    extracted_data: Dict[str, Any]
    classification: Dict[str, Any]
    knowledge_search_results: List[Dict[str, Any]]
    escalation_analysis: Dict[str, Any]
    final_response: Dict[str, Any]
    processing_complete: bool
    step_by_step_log: List[str]

# Agent Classes
class DataExtractionAgent:
    def __init__(self, client):
        self.client = client
        self.name = "Data Extraction Agent"
    
    def extract_ticket_data(self, state: TicketState) -> TicketState:
        """Extract structured data from raw ticket content"""
        step_log = f"🔍 {self.name}: Starting data extraction from ticket content"
        state["step_by_step_log"].append(step_log)

        try:
            # Call the model here
            return state
    
        except Exception as e:
            error_log = f"❌ {self.name}: Failed to extract data - {str(e)}"
            state["step_by_step_log"].append(error_log)
            # Create fallback extracted data
            state["extracted_data"] = {
                "customer_name": "Unknown",
                "issue_summary": state['original_content'][:100] + "...",
                "issue_category": "general",
                "urgency_indicators": [],
                "specific_error_messages": [],
                "user_actions_taken": [],
                "desired_outcome": "Resolve issue",
                "technical_details": {},
                "sentiment": "neutral",
                "key_phrases": [],
                "error": str(e)
            }
            return state

        

# LangGraph Workflow Functions
def extract_data_step(state: TicketState) -> TicketState:
    agent = DataExtractionAgent(state["client"])
    return agent.extract_ticket_data(state)


# Create the workflow
def create_real_agentic_workflow():
    workflow = StateGraph(TicketState)

    # ✅ Add the node first
    workflow.add_node("extract_data", extract_data_step)

    # ✅ Then set entry point
    workflow.set_entry_point("extract_data")

    # ✅ Since it's a single-node workflow for now,
    # you must tell it where to end
    workflow.add_edge("extract_data", END)

    return workflow.compile(checkpointer=MemorySaver())


graph = create_real_agentic_workflow()


def run_agent(input_data: dict, client):
    return graph.invoke({**input_data, "client": client})