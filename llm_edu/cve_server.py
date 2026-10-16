"""사내 CVE 조회 MCP 서버."""
import sys

from mcp.server.mcpserver import MCPServer

CVE_DB = {
    "CVE-2021-44228": {"product": "Apache Log4j", "cvss": 10.0,
                       "affected": "2.0-beta9 ~ 2.14.1", "fixed_in": "2.17.1"},
    "CVE-2024-20337": {"product": "Cisco AnyConnect", "cvss": 8.2,
                       "affected": "~ 4.10.04065", "fixed_in": "4.10.07061"},
}

server = MCPServer(name="cve-lookup")


@server.tool()
def lookup_cve(cve_id: str) -> str:
    """사내 CVE 데이터베이스에서 CVE 정보를 조회한다."""
    info = CVE_DB.get(cve_id.upper())
    return str(info) if info else f"{cve_id}: 등록되지 않음"


@server.tool()
def list_cves() -> str:
    """등록된 CVE 번호를 모두 돌려준다."""
    return ", ".join(CVE_DB)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8931
    server.run(transport="streamable-http", host="127.0.0.1", port=port)
