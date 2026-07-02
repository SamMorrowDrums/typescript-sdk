#!/usr/bin/env node

/**
 * Provider-neutral SUT for SEP-2350 server-side scope-challenge interop
 * validation. Drives the panyam/mcpconformance PR 19 scope-challenge scenario
 * against any RFC-compliant authorization server — point ISSUER at Keycloak,
 * Okta, Entra, etc. Per-provider token minting lives in that repo's
 * examples/auth-fixtures/<provider>.
 *
 * The scope-challenge wire shape (RFC 6750 §3.1 + RFC 9728) is provider-blind,
 * so a single SUT covers every AS. The two provider-specific bits are handled
 * generically:
 *   - AS endpoints (jwks_uri / authorization / token) are discovered from
 *     ISSUER's .well-known/openid-configuration.
 *   - Scopes are read from whichever claim the IdP emits: `scp` (array or
 *     string; Okta/Azure/Entra), `scope` (string; Keycloak/RFC 6749), or
 *     `scopes` (array).
 *
 * Env:
 *   ISSUER    AS issuer URL. Default: local Keycloak realm.
 *             Okta: https://<tenant>.okta.com/oauth2/default
 *   AUDIENCE  expected aud claim (empty = not checked). Okta needs api://default.
 *   PORT      listen port (default 3100).
 *
 * Run (Keycloak):
 *   MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true \
 *     pnpm --filter @modelcontextprotocol/examples-server exec tsx src/scopeChallenge.ts
 *
 * Run (Okta):
 *   source <mcpconformance>/examples/auth-fixtures/okta/okta.env
 *   ISSUER="$OKTA_ISSUER" AUDIENCE=api://default \
 *     pnpm --filter @modelcontextprotocol/examples-server exec tsx src/scopeChallenge.ts
 */

import type { OAuthTokenVerifier } from '@modelcontextprotocol/express';
import {
    createMcpExpressApp,
    getOAuthProtectedResourceMetadataUrl,
    mcpAuthMetadataRouter,
    requireBearerAuth
} from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import type { AuthInfo } from '@modelcontextprotocol/server';
import { McpServer } from '@modelcontextprotocol/server';
import type { JWTPayload } from 'jose';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const PORT = Number.parseInt(process.env.PORT || '3100', 10);
const ISSUER = (process.env.ISSUER || 'http://localhost:8180/realms/mcpkit-test').replace(/\/$/, '');
const AUDIENCE = process.env.AUDIENCE || '';
const RESOURCE_URL = new URL(`http://localhost:${PORT}/mcp`);

// Discover AS endpoints from the issuer's OIDC metadata (served by Keycloak
// realms and Okta custom authorization servers alike). Keeps the SUT free of
// provider-specific endpoint paths.
interface OidcMetadata {
    issuer: string;
    authorization_endpoint?: string;
    token_endpoint?: string;
    jwks_uri: string;
}
const discoveryUrl = `${ISSUER}/.well-known/openid-configuration`;
const discoveryResponse = await fetch(discoveryUrl);
const meta = (await discoveryResponse.json()) as OidcMetadata;

const JWKS = createRemoteJWKSet(new URL(meta.jwks_uri));

class ScopeAwareVerifier implements OAuthTokenVerifier {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: ISSUER,
            ...(AUDIENCE ? { audience: AUDIENCE } : {})
        });
        const claims = payload as JWTPayload & {
            scp?: string[] | string;
            scope?: string;
            scopes?: string[];
            cid?: string;
            client_id?: string;
            azp?: string;
        };
        let scopes: string[] = [];
        if (Array.isArray(claims.scopes)) {
            scopes = claims.scopes.filter((s): s is string => typeof s === 'string');
        } else if (Array.isArray(claims.scp)) {
            scopes = claims.scp.filter((s): s is string => typeof s === 'string');
        } else if (typeof claims.scp === 'string') {
            scopes = claims.scp.split(/\s+/).filter(Boolean);
        } else if (typeof claims.scope === 'string') {
            scopes = claims.scope.split(/\s+/).filter(Boolean);
        }
        return {
            token,
            clientId: claims.cid ?? claims.client_id ?? claims.azp ?? 'unknown',
            scopes,
            expiresAt: typeof claims.exp === 'number' ? claims.exp : 0
        };
    }
}

const verifier = new ScopeAwareVerifier();
const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(RESOURCE_URL);

const server = new McpServer({ name: 'pr1624-scope-challenge', version: '0.1.0' });
server.registerTool(
    'admin_call',
    {
        description:
            'Requires admin-write scope. The OR-hierarchy via `accepted` lets a token with the parent `admin` scope satisfy the gate too. The 403 challenge advertises only `required` (least-privilege).',
        scopes: { required: ['admin-write'], accepted: ['admin-write', 'admin'] }
    },
    async () => ({ content: [{ type: 'text' as const, text: 'admin_call: ok' }] })
);

const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // SEP-2575 stateless wire
    scopeChallenge: {
        resourceMetadataUrl
    }
});

await server.connect(transport);

const app = createMcpExpressApp({ host: 'localhost' });

app.use(
    mcpAuthMetadataRouter({
        oauthMetadata: {
            issuer: ISSUER,
            authorization_endpoint: meta.authorization_endpoint ?? `${ISSUER}/authorize`,
            token_endpoint: meta.token_endpoint ?? `${ISSUER}/token`,
            jwks_uri: meta.jwks_uri,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'client_credentials'],
            code_challenge_methods_supported: ['S256']
        },
        resourceServerUrl: RESOURCE_URL,
        scopesSupported: ['tools-read', 'tools-call', 'admin-write'],
        resourceName: 'pr1624-scope-challenge'
    })
);

const authMiddleware = requireBearerAuth({
    verifier,
    resourceMetadataUrl
});

app.post('/mcp', authMiddleware, async (req, res) => {
    await transport.handleRequest(req, res, req.body);
});

// Note: an http:// issuer (e.g. local Keycloak) requires
// MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=true or mcpAuthMetadataRouter
// rejects the issuer URL. Okta (https) needs no such flag.

app.listen(PORT, () => {
    console.log(`pr1624-scope-challenge SUT listening on ${RESOURCE_URL.href}`);
    console.log(`  AS issuer: ${ISSUER}`);
    console.log(`  audience:  ${AUDIENCE || '(unset — aud not validated)'}`);
    console.log(`  jwks_uri:  ${meta.jwks_uri}`);
    console.log(`  scope-gated tool: admin_call requires admin-write`);
});
