# Framework Integration Quickstart

Step-by-step guides for integrating Vellaveto with popular AI agent frameworks.

## Prerequisites

```bash
# Start Vellaveto (pick one)
vellaveto serve --config examples/presets/dev-laptop.toml --port 3000

# Or with Docker
docker run -p 3000:3000 ghcr.io/paolovella/vellaveto:latest

# Or for stdio proxy mode (no HTTP server needed)
vellaveto-proxy --protect shield -- ./your-mcp-server

# Install Python SDK
pip install vellaveto-sdk[all]
```

---

## Anthropic SDK (Claude Tool Use)

Vellaveto evaluates every tool call before your code executes it.

```python
import anthropic
from vellaveto import VellavetoClient, PolicyDenied, ParameterRedactor

# Initialize clients
vellaveto = VellavetoClient(
    url="http://localhost:3000",
    redactor=ParameterRedactor(),  # strip secrets before sending to Vellaveto
)
anthropic_client = anthropic.Anthropic()

# Define tools for Claude
tools = [
    {
        "name": "read_file",
        "description": "Read a file from the filesystem",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to read"}
            },
            "required": ["path"],
        },
    },
    {
        "name": "run_sql",
        "description": "Execute a SQL query",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query to execute"}
            },
            "required": ["query"],
        },
    },
]


def execute_tool(name: str, input: dict) -> str:
    """Execute a tool after Vellaveto approval."""
    # Extract targets for richer policy evaluation
    target_paths = [input[k] for k in ("path", "file") if k in input and isinstance(input[k], str)]
    target_domains = [input[k] for k in ("url", "host") if k in input and isinstance(input[k], str)]

    # Evaluate with Vellaveto — raises PolicyDenied if blocked
    vellaveto.evaluate_or_raise(
        tool=name,
        function=name,
        parameters=input,
        target_paths=target_paths,
        target_domains=target_domains,
    )

    # Tool is allowed — execute it
    if name == "read_file":
        with open(input["path"]) as f:
            return f.read()
    elif name == "run_sql":
        return f"[executed: {input['query']}]"
    return "unknown tool"


# Agentic loop
messages = [{"role": "user", "content": "Read /etc/hostname and tell me the machine name"}]

while True:
    response = anthropic_client.messages.create(
        model="claude-sonnet-4-5-20250514",
        max_tokens=1024,
        tools=tools,
        messages=messages,
    )

    # Check for tool use
    if response.stop_reason == "tool_use":
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                try:
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
                except PolicyDenied as e:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": f"BLOCKED by security policy: {e.reason}",
                        "is_error": True,
                    })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
    else:
        # Final text response
        print(response.content[0].text)
        break
```

---

## OpenAI SDK (Function Calling)

Same pattern — evaluate each function call before execution.

```python
import json
from openai import OpenAI
from vellaveto import VellavetoClient, PolicyDenied, ParameterRedactor

# Initialize clients
vellaveto = VellavetoClient(
    url="http://localhost:3000",
    redactor=ParameterRedactor(),
)
openai_client = OpenAI()

# Define functions for GPT
tools = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the filesystem",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch content from a URL",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"}
                },
                "required": ["url"],
            },
        },
    },
]


def execute_function(name: str, arguments: dict) -> str:
    """Execute a function after Vellaveto approval."""
    target_paths = [arguments[k] for k in ("path", "file") if k in arguments and isinstance(arguments[k], str)]
    target_domains = [arguments[k] for k in ("url", "host") if k in arguments and isinstance(arguments[k], str)]

    vellaveto.evaluate_or_raise(
        tool=name,
        function=name,
        parameters=arguments,
        target_paths=target_paths,
        target_domains=target_domains,
    )

    if name == "read_file":
        with open(arguments["path"]) as f:
            return f.read()
    elif name == "fetch_url":
        import urllib.request
        with urllib.request.urlopen(arguments["url"]) as resp:
            return resp.read().decode()[:1000]
    return "unknown function"


# Agentic loop
messages = [{"role": "user", "content": "Read /tmp/notes.txt for me"}]

while True:
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        tools=tools,
        messages=messages,
    )

    choice = response.choices[0]

    if choice.finish_reason == "tool_calls":
        messages.append(choice.message)

        for tool_call in choice.message.tool_calls:
            fn_name = tool_call.function.name
            fn_args = json.loads(tool_call.function.arguments)

            try:
                result = execute_function(fn_name, fn_args)
            except PolicyDenied as e:
                result = f"BLOCKED by security policy: {e.reason}"

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })
    else:
        print(choice.message.content)
        break
```

---

## LangChain (Callback Handler)

The Python SDK provides native LangChain integration via a callback handler that automatically intercepts all tool calls.

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_react_agent, AgentExecutor
from langchain.tools import tool
from langchain import hub
from vellaveto import VellavetoClient
from vellaveto.langchain import VellavetoCallbackHandler

# Initialize
vellaveto = VellavetoClient(url="http://localhost:3000")
handler = VellavetoCallbackHandler(
    client=vellaveto,
    session_id="langchain-session-1",
    raise_on_deny=True,
)

# Define tools
@tool
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path) as f:
        return f.read()

@tool
def list_directory(path: str) -> str:
    """List files in a directory."""
    import os
    return "\n".join(os.listdir(path))

# Create agent
llm = ChatOpenAI(model="gpt-4o")
prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm, [read_file, list_directory], prompt)
executor = AgentExecutor(agent=agent, tools=[read_file, list_directory])

# Run — all tool calls are automatically evaluated by Vellaveto
result = executor.invoke(
    {"input": "List the files in /tmp and read any .txt file"},
    config={"callbacks": [handler]},
)
print(result["output"])
```

---

## LangGraph (Graph Node)

For LangGraph workflows, add a Vellaveto evaluation node between planning and execution.

```python
from typing import TypedDict, List, Optional, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.messages import BaseMessage, HumanMessage
from vellaveto import VellavetoClient
from vellaveto.langgraph import create_vellaveto_node, VellavetoState

# State schema
class AgentState(VellavetoState):
    messages: List[BaseMessage]

# Initialize
vellaveto = VellavetoClient(url="http://localhost:3000")
vellaveto_node = create_vellaveto_node(vellaveto, on_deny="block")

# Node functions
def plan_node(state: dict) -> dict:
    """Determine what tool to call next."""
    # Your planning logic here
    return {
        "pending_tool_name": "read_file",
        "pending_tool_input": {"path": "/tmp/data.txt"},
    }

def tool_node(state: dict) -> dict:
    """Execute the approved tool call."""
    name = state["pending_tool_name"]
    input = state["pending_tool_input"]
    # Execute tool...
    return {"messages": state.get("messages", []) + [HumanMessage(content="Done")]}

# Build graph
graph = StateGraph(AgentState)
graph.add_node("plan", plan_node)
graph.add_node("vellaveto", vellaveto_node)
graph.add_node("tools", tool_node)

graph.set_entry_point("plan")
graph.add_edge("plan", "vellaveto")
graph.add_conditional_edges(
    "vellaveto",
    lambda s: "blocked" if s.get("tool_blocked") else "allowed",
    {"blocked": END, "allowed": "tools"},
)
graph.add_edge("tools", END)

# Run
app = graph.compile()
result = app.invoke({"messages": [HumanMessage(content="Read the data")]})
```

---

## MCP Server Proxy (stdio)

For MCP-native tools, Vellaveto runs as a transparent proxy between the client and the MCP server.

```bash
# Quickest way — use a protection level (no config file needed):
vellaveto-proxy --protect shield -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects

# Or with a specific preset:
vellaveto-proxy --preset dev-laptop -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects

# Or with a custom config file:
vellaveto-proxy --config policy.toml -- npx -y @modelcontextprotocol/server-filesystem /home/user/projects
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`~/.config/Claude/claude_desktop_config.json` (Linux). Replace
`/home/user/projects` below with the directory you want the filesystem server to
serve.

> Windows is not a supported target — release binaries are built for Linux and
> macOS only. See [Platform support](../README.md#consumer-shield--protect-users-from-ai-providers).

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "shield",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "/home/user/projects"
      ]
    }
  }
}
```

### Cursor

Edit `.cursor/mcp.json` in your project directory:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "fortress",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "fortress",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

### OpenAI Codex CLI

Edit `~/.codex/config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vellaveto-proxy",
      "args": [
        "--protect", "shield",
        "--", "npx", "-y",
        "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

### VS Code (Copilot / Cline / Roo Code)

Add to your VS Code `settings.json`:

```json
{
  "mcp": {
    "servers": {
      "filesystem": {
        "command": "vellaveto-proxy",
        "args": [
          "--protect", "fortress",
          "--", "npx", "-y",
          "@modelcontextprotocol/server-filesystem", "."
        ]
      }
    }
  }
}
```

### VellaVeto Desktop (no config editing needed)

The [VellaVeto Desktop app](../packages/vellaveto-desktop/) auto-detects Claude Desktop, Claude Code, Cursor, Windsurf, VS Code (Copilot/Cline/Roo Code), OpenAI Codex CLI, Zed, Continue, Amazon Q Developer, and JetBrains AI — then wraps their MCP servers with one click.

Every tool call is evaluated against your policies before reaching the MCP server. Use `shield` for basic protection, `fortress` for stronger controls, or `vault` for deny-by-default.

---

## HTTP Reverse Proxy

For HTTP-based MCP servers, Vellaveto acts as a reverse proxy.

```bash
# Proxy all requests to an upstream MCP server
vellaveto-http-proxy \
  --config examples/presets/rag-agent.toml \
  --listen 0.0.0.0:3000 \
  --upstream http://localhost:9000
```

Your agent connects to `localhost:3000` instead of the upstream server directly. Vellaveto inspects every request and response.

HTTP MCP clients should send `MCP-Protocol-Version`. The default proxy policy
accepts `2025-11-25` and `2026-07-28` and denies missing or older versions.
When using `2026-07-28`, `Mcp-Method` and `Mcp-Name` headers must agree with
the JSON-RPC body.

---

## Parameter Redaction

By default, tool parameters are sent verbatim to Vellaveto for policy evaluation. Enable client-side redaction to strip secrets before they leave your process:

```python
from vellaveto import VellavetoClient, ParameterRedactor

# Keys-only mode (default): redacts values for known sensitive parameter names
redactor = ParameterRedactor()

# Values mode: also scans string values for secret patterns (sk-..., ghp_..., JWTs)
redactor = ParameterRedactor(mode="values")

# All mode: redacts every parameter value (sends only keys to Vellaveto)
redactor = ParameterRedactor(mode="all")

# Add custom sensitive keys
redactor = ParameterRedactor(extra_keys={"internal_token", "vault_path"})

# Use with client
client = VellavetoClient(url="http://localhost:3000", redactor=redactor)
```

Vellaveto's server-side DLP scanning and audit redaction still apply independently of client-side redaction.

---

## Choosing a Policy Preset

| Your Agent Does | Use This Preset | Key Protection |
|-----------------|-----------------|----------------|
| Reads/writes files, runs commands | `dev-laptop.toml` | Credential files blocked, destructive commands gated |
| Runs in CI/CD pipelines | `ci-agent.toml` | Network allowlisted, no interactive approvals |
| Queries vector DBs, search APIs | `rag-agent.toml` | Exfiltration prevention, injection detection |
| Runs SQL queries | `database-agent.toml` | DROP/TRUNCATE gated, credential protection |
| Automates browsers | `browser-agent.toml` | Malicious domains blocked, form submissions gated |

See [examples/presets/](../examples/presets/) for the full configurations.
