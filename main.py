import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from mcp_server.api import McpAuthConfig, McpServerConfig, run_mcp_server


def main() -> None:
    config = McpServerConfig(
        auth=McpAuthConfig(
            auth_token="change_me",
            hmac_secret="change_me_too",
            allowed_clock_skew_seconds=60,
        )
    )
    run_mcp_server(host="0.0.0.0", port=8080, config=config)


if __name__ == "__main__":
    main()
