# Agent Data Flow and Architecture

The system operates using a multi-agent orchestration model centered around a shared **Knowledge Graph** (KG). The main orchestrator (`RunAgent`) launches **Target Agents** which control the red-team loop for specific assets, and these agents spawn specialized **Sub-Agents** for specific analytical tasks.

## High-Level Data Flow Diagram

```mermaid
flowchart TD
    %% Define Nodes
    Orchestrator[Orchestrator]
    KnowledgeGraph[(Knowledge Graph\nIn-Memory Mutex)]
    SQLite[(SQLite DB\nPersistent Logs)]
    
    %% Target Agent
    subgraph Target_Agent_Loop [Target Agent]
        SystemPrompt[System Prompt:\nRules, Role, Scope]
        Context[Current Intelligence:\nTargets, Ports, Vulns]
        LLM[Agent LLM\nHistory & Reasoning]
        Tools[Tool Execution\n(nmap, nuclei, etc.)]
    end

    %% Sub-Agents
    subgraph Sub_Agents [Specialized Sub-Agents]
        ExtractSub[Intelligence Extraction Agent]
        DecisionSub[Scope Decision Agent]
        HelperSub[Vulnerability Helper Agent]
    end

    %% Connections
    Orchestrator -->|Initializes| KnowledgeGraph
    Orchestrator -->|Spawns 1 per Target| Target_Agent_Loop
    
    %% Target Agent Flow
    KnowledgeGraph -.->|Reads snapshot| Context
    SystemPrompt --> LLM
    Context --> LLM
    LLM -->|Calls Tools| Tools
    Tools -->|Raw Output| ExtractSub
    
    %% Intelligence Extraction
    ExtractSub -->|Parses structured JSON| KnowledgeGraph
    ExtractSub -.->|Found new IPs/URLs| DecisionSub
    DecisionSub -->|Filters In-Scope IPs/URLs| KnowledgeGraph
    
    %% Tool Feedback Loop
    ExtractSub -->|Sends Tool Summary| LLM
    
    %% Helper Sub-Agent Flow
    LLM -->|Spawns for Vuln Validation| HelperSub
    KnowledgeGraph -.->|Full JSON Dump| HelperSub
    HelperSub -->|Validates & Logs| KnowledgeGraph
    HelperSub -->|Logs Exploits| SQLite
    HelperSub -->|Final Result Summary| LLM
    
    %% Persistent Storage
    KnowledgeGraph -->|Log Execution| SQLite
```

---

## 1. Target Agent (The Main Red Team Agent)
This is the primary autonomous agent spawned per target (e.g., a specific IP or Domain) in the `runTargetAgent` function.

- **How Prompts are Built**:
  - **System Prompt**: Built with the core rules of engagement, IP whitelist policies, and behavioral instructions (e.g., "Do not make assumptions").
  - **Dynamic Context**: Each iteration, the prompt is injected with a fresh "Current Intelligence Summary" built from a snapshot of the Knowledge Graph (showing known targets, phases, open ports, and vulnerability counts).
  - **Tool Injection**: The framework dynamically scores available tools based on the target's current phase (e.g., Reconnaissance, Exploitation) and injects only the top 15 most relevant tools into the prompt schema.
- **What is Sent**: The full conversation history (System Prompt + Intelligence Summary + past LLM responses + Tool results).
- **What it Stores in Conversation**: The agent's reasoning, the intent of the tool calls, and the summarized results of those tools. (It does *not* store the raw 10,000-line nmap output in its conversation context).
- **What it Stores in the KB**: Through tools, it indirectly mutates the Knowledge Graph (e.g., advancing target phases, marking tools as executed to prevent duplicate payloads).

## 2. Intelligence Extraction Sub-Agent (Implicit)
When a tool finishes executing, the raw output is sent to this sub-agent to prevent polluting the main agent's context window.

- **How Prompts are Built**: The prompt explicitly asks the LLM to act as an "intelligence extraction sub-agent". It is provided with the tool name, the target, and up to 30,000 characters of the raw tool output.
- **What is Sent**: The raw stdout/stderr of the executed tool.
- **What it Stores in Conversation**: Nothing. It runs as a one-shot query.
- **What it Stores in the KB**: It forces a strictly formatted JSON output (`discovered_ips`, `open_ports`, `harvested_tokens`, etc.). The Go backend parses this JSON and directly mutates the in-memory Knowledge Graph. It returns a 1-3 sentence summary that is fed back into the **Target Agent's** conversation history.

## 3. Scope Decision Sub-Agent (Implicit)
Called immediately after the Intelligence Extraction Sub-Agent if new IPs or URLs are discovered.

- **How Prompts are Built**: It is given the list of newly discovered assets and the rules of engagement/scope.
- **What is Sent**: A list of candidate IPs/URLs.
- **What it Stores in Conversation**: Nothing.
- **What it Stores in the KB**: It acts as a gatekeeper. Only assets it confirms as "in-scope" are appended to the Knowledge Graph.

## 4. Vulnerability Helper Sub-Agent
During the Vulnerability Analysis or Exploitation phases, the Target Agent spawns this helper to deeply investigate a *specific finding*.

- **How Prompts are Built**: The prompt instructs the agent to focus purely on validating the exploitability of one specific finding on one target.
- **What is Sent**: The prompt is injected with a **full JSON dump** of the entire Knowledge Graph (`kg.ToJSON()`), along with full access to all tools.
- **What it Stores in Conversation**: It runs its own isolated 5-turn mini-conversation. It stores its own reasoning, intermediate tool calls, and responses within its isolated context.
- **What it Stores in the KB**: It has direct tool access to call `log_vulnerability` and `query_knowledge_graph`. Calling `log_vulnerability` persists the exploit validation to the SQLite database and marks the vulnerability as "processed" in the Knowledge Graph.
- **How it Shares Info**: When the 5-turn loop ends, the entire text output (reasoning and conclusions) of the Helper Sub-Agent is appended as a System Message into the **Main Target Agent's** conversation history.
