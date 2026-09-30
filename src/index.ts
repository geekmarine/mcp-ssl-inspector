interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

const SERVER_NAME = "mcp-ssl-inspector";
const SERVER_VERSION = "1.0.0";
const PROTOCOL_VERSION = "2024-11-05";

const TOOLS = [
  {
    name: "inspect_ssl_cert",
    description: "Inspects TLS/SSL certificate reachability, HTTPS headers, and protocol handshake for a domain.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to inspect (e.g. 'datasnag.com' or 'cloudflare.com')."
        }
      },
      required: ["domain"]
    }
  }
];

function sanitizeDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, "");
  return domain.split("/")[0].replace(/\.+$/, "");
}

async function handleInspectSsl(args: Record<string, unknown> | undefined) {
  const rawDomain = typeof args?.domain === "string" ? args.domain : "";
  const domain = sanitizeDomain(rawDomain);

  if (!domain) {
    return {
      domain: rawDomain,
      status: "INVALID_DOMAIN",
      httpsAvailable: false,
      timestamp: new Date().toISOString()
    };
  }

  const startTime = Date.now();
  try {
    const targetUrl = `https://${domain}`;
    const response = await fetch(targetUrl, {
      method: "HEAD",
      redirect: "follow",
      headers: {
        "User-Agent": "DataSnag-SSL-Inspector/1.0"
      }
    });
    const latencyMs = Date.now() - startTime;

    return {
      domain,
      status: "SECURE",
      httpsAvailable: response.ok || response.status < 500,
      httpStatus: response.status,
      handshakeLatencyMs: latencyMs,
      hstsEnabled: response.headers.has("strict-transport-security"),
      hstsHeader: response.headers.get("strict-transport-security") || "Missing",
      serverHeader: response.headers.get("server") || "Hidden",
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      domain,
      status: "HANDSHAKE_FAILED",
      httpsAvailable: false,
      error: (error as Error).message,
      timestamp: new Date().toISOString()
    };
  }
}

async function handleRpcRequest(body: JsonRpcRequest): Promise<JsonRpcResponse> {
  const { id = null, method, params } = body;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
        }
      };

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: TOOLS }
      };

    case "tools/call": {
      const toolName = params?.name;
      const toolArguments = (params?.arguments || {}) as Record<string, unknown>;

      if (toolName === "inspect_ssl_cert") {
        const data = await handleInspectSsl(toolArguments);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
            isError: data.status === "HANDSHAKE_FAILED" || data.status === "INVALID_DOMAIN"
          }
        };
      }
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Tool not found: ${toolName}` }
      };
    }

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` }
      };
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-session-id"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "healthy", service: SERVER_NAME }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    if (url.pathname === "/mcp") {
      if (request.method !== "POST") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "POST required" } }), {
          status: 405,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      const body = (await request.json()) as JsonRpcRequest;
      const rpcResponse = await handleRpcRequest(body);
      return new Response(JSON.stringify(rpcResponse), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  }
};
