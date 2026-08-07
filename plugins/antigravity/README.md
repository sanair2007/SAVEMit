# SAVEMit for Antigravity

This plugin connects Antigravity to the local SAVEMit MCP server. It exposes tools for starting an investigation, polling its result, reading findings, and inspecting validation output.

## Local setup

1. Install the backend dependencies, including `fastmcp`:

   ```powershell
   & .\.venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt
   ```

2. Install the plugin into the project you want the agent to scan:

   ```powershell
   .\scripts\install-antigravity-plugin.ps1 -TargetWorkspace "C:\\path\\to\\project-to-scan"
   ```

   The script creates `.agents/plugins/savemit-security/` and the CLI-discoverable `.agents/mcp_config.json`, both with the correct local SAVEMit paths.

3. In Antigravity, open the agent panel, open **MCP Servers**, and reload `savemit-security`. Antigravity will start the local server using stdio.

4. Open the target project in Antigravity. In the agent panel, open **MCP Servers** and reload `savemit-security`.

5. Ask the agent: `Use SAVEMit to scan this workspace for vulnerable npm dependencies.`

For development, place this plugin directory under `.agents/plugins/savemit-security/` in a workspace or under `~/.gemini/config/plugins/` for a global Antigravity plugin. The MCP configuration remains project-specific because the local server must know where SAVEMit is installed.
