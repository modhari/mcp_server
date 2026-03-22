from pathlib import Path

from mcp_server.api import McpAuthConfig, McpServerConfig, run_mcp_server


def main() -> None:
    config = McpServerConfig(
        auth=McpAuthConfig(
            auth_token="change_me",
            hmac_secret="change_me_too",
        ),
        audit_path=Path("/tmp/mcp_audit.jsonl"),
    )

    run_mcp_server(host="0.0.0.0", port=8080, config=config)


if __name__ == "__main__":
    main()
