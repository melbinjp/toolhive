// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package tokenexchange

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiIssuerTokenValidator_ValidateJWTBearerAssertion(t *testing.T) {
	t.Parallel()

	selfJWKS := newTestJWKS(t)
	externalJWKS := newTestJWKS(t)
	jwksServer := startJWKSServer(t, externalJWKS)
	validator := newMultiValidator(t, selfJWKS, []TrustedIssuer{{
		IssuerURL:              testExternalIssuer,
		ExpectedAudience:       testExternalAudience,
		JWKSURL:                jwksServer.URL + "/jwks",
		AllowedDelegateClients: []string{anyDelegateClient},
	}})

	tests := []struct {
		name    string
		claims  func() jwt.Claims
		signer  *testJWKS
		wantErr string
	}{
		{
			name:   "valid assertion does not require delegation consent",
			claims: func() jwt.Claims { return jwtBearerExternalClaims() },
			signer: externalJWKS,
		},
		{
			name: "audience is accepted as long as it intersects the accepted set, even if multi-valued",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Audience = jwt.Audience{testTokenEndpoint, "https://other.example.com"}
				return claims
			},
			signer: externalJWKS,
		},
		{
			name: "audience is rejected when it matches none of the accepted authorization server identities",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Audience = jwt.Audience{"https://other.example.com"}
				return claims
			},
			signer:  externalJWKS,
			wantErr: "assertion audience must include one of the accepted authorization server identities",
		},
		{
			name: "subject is required",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Subject = ""
				return claims
			},
			signer:  externalJWKS,
			wantErr: "missing required 'sub'",
		},
		{
			name: "expiry is required",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Expiry = nil
				return claims
			},
			signer:  externalJWKS,
			wantErr: "missing required 'exp'",
		},
		{
			name: "expired assertion is rejected",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				return claims
			},
			signer:  externalJWKS,
			wantErr: "claims validation failed",
		},
		{
			name: "issuer must be trusted",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.Issuer = "https://untrusted.example.com"
				return claims
			},
			signer:  externalJWKS,
			wantErr: "untrusted assertion issuer",
		},
		{
			name: "issued at is required",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.IssuedAt = nil
				return claims
			},
			signer:  externalJWKS,
			wantErr: "missing required 'iat'",
		},
		{
			name: "missing JWT ID is accepted",
			claims: func() jwt.Claims {
				claims := jwtBearerExternalClaims()
				claims.ID = ""
				return claims
			},
			signer: externalJWKS,
		},
		{
			name:    "invalid signature is rejected",
			claims:  func() jwt.Claims { return jwtBearerExternalClaims() },
			signer:  newTestJWKS(t),
			wantErr: "signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw := tt.signer.signToken(t, tt.claims(), nil)
			claims, err := validator.ValidateJWTBearerAssertion(context.Background(), raw, testTokenEndpoint)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "ext-user-456", claims.Subject)
			assert.Equal(t, testExternalIssuer, claims.Issuer)
		})
	}
}

// TestMultiIssuerTokenValidator_ValidateJWTBearerAssertion_AcceptedAudiences
// covers JWTBearerGrant.AcceptedAudiences: it widens the accepted "aud" set
// beyond the literal token endpoint, e.g. so an issuer's assertion can carry
// an alternate identity for this AS (a migrated issuer URL) instead of the
// endpoint the caller happens to be calling.
func TestMultiIssuerTokenValidator_ValidateJWTBearerAssertion_AcceptedAudiences(t *testing.T) {
	t.Parallel()

	selfJWKS := newTestJWKS(t)
	externalJWKS := newTestJWKS(t)
	jwksServer := startJWKSServer(t, externalJWKS)
	const alternateASIdentity = "https://auth.example.com/legacy-token-endpoint"
	validator := newMultiValidator(t, selfJWKS, []TrustedIssuer{{
		IssuerURL:              testExternalIssuer,
		ExpectedAudience:       testExternalAudience,
		JWKSURL:                jwksServer.URL + "/jwks",
		AllowedDelegateClients: []string{anyDelegateClient},
		JWTBearerGrant: &JWTBearerGrantPolicy{
			MaxAssertionAge:   time.Hour.String(),
			AcceptedAudiences: []string{alternateASIdentity},
			SubjectBindings: []JWTBearerSubjectBinding{
				{Subject: "ext-user-456", AllowedResources: []string{"https://mcp.example.com"}},
			},
		},
	}})

	tests := []struct {
		name    string
		aud     jwt.Audience
		wantErr string
	}{
		{
			name:    "the configured alternate identity is accepted",
			aud:     jwt.Audience{alternateASIdentity},
			wantErr: "",
		},
		{
			name:    "the literal token endpoint is no longer accepted once AcceptedAudiences is configured",
			aud:     jwt.Audience{testTokenEndpoint},
			wantErr: "assertion audience must include one of the accepted authorization server identities",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := jwtBearerExternalClaims()
			claims.Audience = tt.aud
			raw := externalJWKS.signToken(t, claims, nil)

			validated, err := validator.ValidateJWTBearerAssertion(context.Background(), raw, testTokenEndpoint)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "ext-user-456", validated.Subject)
		})
	}
}

func jwtBearerExternalClaims() jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		Subject:  "ext-user-456",
		Issuer:   testExternalIssuer,
		Audience: jwt.Audience{testTokenEndpoint},
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       "jwt-bearer-jti",
	}
}
