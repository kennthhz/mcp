# AWS Labs postgres MCP Server

An AWS Labs Model Context Protocol (MCP) server for postgres

## Instructions

Instructions for using this postgres MCP server. This can be used by clients to improve the LLM's understanding of available tools, resources, etc. It can be thought of like a 'hint' to the model. For example, this information MAY be added to the system prompt. Important to be clear, direct, and detailed.

## Build and install docker image

1. git clone https://github.com/kennthhz/mcp.git
2. Sync to branch pg_mcp_v1
3. Go to https://github.com/kennthhz/mcp/tree/pg_mcp_v1/src/postgres-mcp-server
4. Run docker build -t awslabs/postgres-mcp-server:latest .

## Add or update your LLM client's config with following:

<pre><code>```json 
{
  "mcpServers": {
    "awslabs.postgres-mcp-server": {
      "command": "docker",
      "args": [
        "run", 
        "-i", 
        "--rm",
        "-e", "AWS_ACCESS_KEY_ID=<your data>",
        "-e", "AWS_SECRET_ACCESS_KEY=<your data>",
        "-e", "AWS_REGION=<your data>",
        "awslabs/postgres-mcp-server:latest", 
        "--resource_arn", "<your data>",
        "--secret_arn", "<your data>",
        "--database", "<your data>",
	"--region", "<your data>"
      ]
    }
  }
}
```</code></pre>

## TODO (REMOVE AFTER COMPLETING)

* [ ] Optionally add an ["RFC issue"](https://github.com/awslabs/mcp/issues) for the community to review
* [ ] Generate a `uv.lock` file with `uv sync` -> See [Getting Started](https://docs.astral.sh/uv/getting-started/)
* [ ] Remove the example tools in `./awslabs/postgres_mcp_server/server.py`
* [ ] Add your own tool(s) following the [DESIGN_GUIDELINES.md](https://github.com/awslabs/mcp/blob/main/DESIGN_GUIDELINES.md)
* [ ] Keep test coverage at or above the `main` branch - NOTE: GitHub Actions run this command for CodeCov metrics `uv run --frozen pytest --cov --cov-branch --cov-report=term-missing`
* [ ] Document the MCP Server in this "README.md"
* [ ] Add a section for this postgres MCP Server at the top level of this repository "../../README.md"
* [ ] Create the "../../doc/servers/postgres-mcp-server.md" file with these contents:

    ```markdown
    ---
    title: postgres MCP Server
    ---

    {% include "../../src/postgres-mcp-server/README.md" %}
    ```
  
* [ ] Reference within the "../../doc/index.md" like this:

    ```markdown
    ### postgres MCP Server
    
    An AWS Labs Model Context Protocol (MCP) server for postgres
    
    **Features:**
    
    - Feature one
    - Feature two
    - ...

    Instructions for using this postgres MCP server. This can be used by clients to improve the LLM's understanding of available tools, resources, etc. It can be thought of like a 'hint' to the model. For example, this information MAY be added to the system prompt. Important to be clear, direct, and detailed.
    
    [Learn more about the postgres MCP Server](servers/postgres-mcp-server.md)
    ```

* [ ] Submit a PR and pass all the checks
