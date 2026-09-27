# File-System-MCP-Server
A fork of https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
## Usage
```json
{
  "mcpServers": {
    "File System": {
      "command": "npx",
      "args": [
        "--allow-git",
        "all",
        "-y",
        "github:Quicksilver0218/File-System-MCP-Server",
        "${env:VSCODE_CWD}" // or "%VSCODE_CWD%"
      ]
    }
  }
}
```
