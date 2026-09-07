import "dotenv/config";
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { protectedResourceMetadata, requireEntraAuth } from "./auth";
import { authorizationServerMetadata, proxyAuthorize, proxyToken } from "./oauthProxy";

const PORT = Number(process.env.PORT ?? 5150);

function buildServer(): McpServer {
  const server = new McpServer({
    name: "tps-report-mcp",
    version: "1.0.0",
  });

  server.registerTool(
    "get_tps_report",
    {
      title: "Get TPS Report",
      description: "Returns a fake TPS report.",
      inputSchema: {},
    },
    async () => {
      const reportId = randomUUID().slice(0, 8).toUpperCase();
      const text = [
        `TPS REPORT #${reportId}`,
        `Date: ${new Date().toISOString().slice(0, 10)}`,
        `Cover Sheet: ATTACHED`,
        ``,
        `Status: All synergies actualized. No action items.`,
        `Approved by: Management`,
      ].join("\n");

      return {
        content: [{ type: "text", text }],
      };
    }
  );

  return server;
}

const app = express();
app.use((req, _res, next) => {
  console.log(`${req.method} ${req.originalUrl}`);
  next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);
app.get("/.well-known/oauth-authorization-server", authorizationServerMetadata);

app.get("/authorize", proxyAuthorize);
app.post("/token", proxyToken);

app.post("/mcp", requireEntraAuth, async (req, res) => {
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("Error handling MCP request:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

const methodNotAllowed = (_req: express.Request, res: express.Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Method not allowed." },
    id: null,
  });
};

app.get("/mcp", methodNotAllowed);
app.delete("/mcp", methodNotAllowed);

app.listen(PORT, () => {
  console.log(`TPS Report MCP server listening on port ${PORT}`);
});
