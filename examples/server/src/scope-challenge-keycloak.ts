#!/usr/bin/env node

/**
 * SUT for SEP-2350 server-side scope-challenge interop validation against
 * a Keycloak realm. Companion to panyam/mcpconformance PR 19's
 * scope-challenge scenario.
 *
 * Wires:
 *   - JWKS-aware JWT verifier (jose) against Keycloak realm
 *   - requireBearerAuth middleware from @modelcontextprotocol/express
 *   - McpServer with one scope-gated tool (admin_call requires admin-write)
 *   - NodeStreamableHTTPServerTransport with scopeChallenge config +
 *     sessionIdGenerator: undefined for SEP-2575 stateless wire
 *   - RFC 9728 PRM document at /.well-known/oauth-protected-resource/mcp
 *
 * Run:
 *   pnpm --filter @modelcontextprotocol/examples-server exec \
 *     tsx src/scope-challenge-keycloak.ts
 */

import {
  createMcpExpressApp,
  getOAuthProtectedResourceMetadataUrl,
  requireBearerAuth,
  mcpAuthMetadataRouter,
} from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer } from '@modelcontextprotocol/server';
import type { AuthInfo, OAuthTokenVerifier } from '@modelcontextprotocol/express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import * as z from 'zod/v4';

const PORT = parseInt(process.env.PORT || '3100', 10);
const REALM_URL = process.env.REALM_URL || 'http://localhost:8180/realms/mcpkit-test';
const RESOURCE_URL = new URL(`http://localhost:${PORT}/mcp`);

const JWKS = createRemoteJWKSet(new URL(`${REALM_URL}/protocol/openid-connect/certs`));

class KeycloakVerifier implements OAuthTokenVerifier {
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const { payload } = await jwtVerify(token, JWKS, { issuer: REALM_URL });
    const claims = payload as JWTPayload & { scope?: string; client_id?: string; azp?: string };
    const scopeStr = typeof claims.scope === 'string' ? claims.scope : '';
    return {
      token,
      clientId: claims.client_id ?? claims.azp ?? 'unknown',
      scopes: scopeStr.split(/\s+/).filter(Boolean),
      expiresAt: typeof claims.exp === 'number' ? claims.exp : 0,
    };
  }
}

const verifier = new KeycloakVerifier();
const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(RESOURCE_URL);

const server = new McpServer({ name: 'pr1624-keycloak', version: '0.1.0' });
server.registerTool(
  'admin_call',
  {
    description: 'Requires admin-write scope. The transport returns 403 + WWW-Authenticate before this handler runs when the token lacks the scope.',
    inputSchema: {},
    scopes: ['admin-write'],
  },
  async () => ({ content: [{ type: 'text' as const, text: 'admin_call: ok' }] }),
);

const transport = new NodeStreamableHTTPServerTransport({
  sessionIdGenerator: undefined, // SEP-2575 stateless wire
  scopeChallenge: {
    resourceMetadataUrl,
  },
});

await server.connect(transport);

const app = createMcpExpressApp({ host: 'localhost' });

app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: {
      issuer: REALM_URL,
      authorization_endpoint: `${REALM_URL}/protocol/openid-connect/auth`,
      token_endpoint: `${REALM_URL}/protocol/openid-connect/token`,
      jwks_uri: `${REALM_URL}/protocol/openid-connect/certs`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'client_credentials', 'password'],
      code_challenge_methods_supported: ['S256'],
    },
    resourceServerUrl: RESOURCE_URL,
    scopesSupported: ['tools-read', 'tools-call', 'admin-write'],
    resourceName: 'pr1624-keycloak',
  }),
);

const authMiddleware = requireBearerAuth({
  verifier,
  resourceMetadataUrl,
});

app.post('/mcp', authMiddleware, async (req, res) => {
  await transport.handleRequest(req, res, req.body);
});

// MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL is required because Keycloak
// runs on http://localhost in this fixture; mcpAuthMetadataRouter
// otherwise enforces HTTPS on the issuer URL.

app.listen(PORT, () => {
  console.log(`pr1624-keycloak SUT listening on ${RESOURCE_URL.href}`);
  console.log(`  AS issuer: ${REALM_URL}`);
  console.log(`  PRM URL:   ${resourceMetadataUrl}`);
  console.log(`  scope-gated tool: admin_call requires admin-write`);
});
