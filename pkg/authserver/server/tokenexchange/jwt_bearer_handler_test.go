// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package tokenexchange

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/authserver/server"
	"github.com/stacklok/toolhive/pkg/authserver/server/session"
	"github.com/stacklok/toolhive/pkg/oauthproto"
)

const testTokenEndpoint = "https://auth.example.com/oauth/token"

type testJWTBearerAssertionValidator struct {
	calls int
	err   error
}

func (v *testJWTBearerAssertionValidator) ValidateJWTBearerAssertion(
	context.Context, string, string,
) (*ValidatedClaims, error) {
	v.calls++
	return &ValidatedClaims{}, v.err
}

func newJWTBearerRequest(form map[string][]string) *fosite.AccessRequest {
	req := fosite.NewAccessRequest(&session.Session{})
	req.GrantTypes = fosite.Arguments{oauthproto.GrantTypeJWTBearer}
	req.Form = form
	return req
}

func signAssertionWithType(t *testing.T, tj *testJWKS, typ any) string {
	t.Helper()

	options := &jose.SignerOptions{}
	if typ != nil {
		options.WithHeader(jose.HeaderType, typ)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: tj.jwk}, options)
	require.NoError(t, err)
	raw, err := jwt.Signed(signer).Claims(validClaims()).Serialize()
	require.NoError(t, err)
	return raw
}

func TestJWTBearerHandler_MatchingAndClientAuth(t *testing.T) {
	t.Parallel()

	tj := newTestJWKS(t)
	validator := &testJWTBearerAssertionValidator{}
	h, err := newJWTBearerHandler(validator, testTokenEndpoint)
	require.NoError(t, err)

	tests := []struct {
		name         string
		grantTypes   fosite.Arguments
		assertion    string
		wantHandles  bool
		wantSkipAuth bool
	}{
		{
			name:         "plain assertion matches and skips client authentication",
			grantTypes:   fosite.Arguments{oauthproto.GrantTypeJWTBearer},
			assertion:    signAssertionWithType(t, tj, nil),
			wantHandles:  true,
			wantSkipAuth: true,
		},
		{
			name:         "ID-JAG assertion is left for its bound handler",
			grantTypes:   fosite.Arguments{oauthproto.GrantTypeJWTBearer},
			assertion:    signAssertionWithType(t, tj, idJAGJWTType),
			wantHandles:  false,
			wantSkipAuth: false,
		},
		{
			name:         "other grant does not match",
			grantTypes:   fosite.Arguments{"client_credentials"},
			assertion:    signAssertionWithType(t, tj, nil),
			wantHandles:  false,
			wantSkipAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := newJWTBearerRequest(map[string][]string{"assertion": {tt.assertion}})
			req.GrantTypes = tt.grantTypes
			assert.Equal(t, tt.wantHandles, h.CanHandleTokenEndpointRequest(context.Background(), req))
			assert.Equal(t, tt.wantSkipAuth, h.CanSkipClientAuth(context.Background(), req))
		})
	}
}

func TestValidateJWTBearerPolicy_RejectsMalformedResourceURI(t *testing.T) {
	t.Parallel()

	now := time.Now()
	policy := &JWTBearerGrantPolicy{
		maxAssertionAge: time.Hour,
		SubjectBindings: []JWTBearerSubjectBinding{{
			Subject:          "external-subject",
			AllowedResources: []string{"not-a-uri"},
		}},
	}
	claims := &ValidatedClaims{
		Subject:  "external-subject",
		IssuedAt: now,
		Expiry:   now.Add(time.Minute),
	}

	_, err := validateJWTBearerPolicy(url.Values{"resource": {"not-a-uri"}}, claims, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, server.ErrInvalidTarget)
}

func TestJWTBearerHandler_AssertionFormAndType(t *testing.T) {
	t.Parallel()

	tj := newTestJWKS(t)
	tests := []struct {
		name           string
		assertions     []string
		wantCalls      int
		wantErrContain string
	}{
		{
			// newJWTBearerHandler alone (no policies/consumer wired) always
			// fails closed after validating the assertion — this handler is
			// never wired into a real token endpoint on its own; see its doc
			// comment. wantCalls == 1 proves form/type validation passed and
			// the validator ran.
			name:           "single plain assertion is validated but the unwired handler fails closed",
			assertions:     []string{signAssertionWithType(t, tj, nil)},
			wantCalls:      1,
			wantErrContain: "issuer is not enabled",
		},
		{
			name:           "missing assertion is rejected",
			wantErrContain: "required exactly once",
		},
		{
			name:           "empty assertion is rejected",
			assertions:     []string{""},
			wantErrContain: "required exactly once",
		},
		{
			name:           "repeated assertion is rejected",
			assertions:     []string{"first", "second"},
			wantErrContain: "required exactly once",
		},
		{
			name:           "malformed assertion is rejected",
			assertions:     []string{"not-a-jwt"},
			wantErrContain: "not a valid signed JWT",
		},
		{
			name:           "non string typ is rejected",
			assertions:     []string{signAssertionWithType(t, tj, 1)},
			wantErrContain: "typ header must be a string",
		},
		{
			name:           "unknown typ is rejected",
			assertions:     []string{signAssertionWithType(t, tj, "application/example+jwt")},
			wantErrContain: "typ header is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			validator := &testJWTBearerAssertionValidator{}
			h, err := newJWTBearerHandler(validator, testTokenEndpoint)
			require.NoError(t, err)
			req := newJWTBearerRequest(map[string][]string{"assertion": tt.assertions})

			err = h.HandleTokenEndpointRequest(context.Background(), req)
			if tt.wantErrContain != "" {
				require.Error(t, err)
				var rfcErr *fosite.RFC6749Error
				require.True(t, errors.As(err, &rfcErr), "expected fosite RFC6749Error")
				assert.Contains(t, rfcErr.Reason(), tt.wantErrContain)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCalls, validator.calls)
		})
	}
}

func TestNewJWTBearerHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		validator JWTBearerAssertionValidator
		endpoint  string
		wantErr   string
	}{
		{name: "nil validator", endpoint: testTokenEndpoint, wantErr: "must not be nil"},
		{name: "empty endpoint", validator: &testJWTBearerAssertionValidator{}, wantErr: "must not be empty"},
		{name: "invalid endpoint", validator: &testJWTBearerAssertionValidator{}, endpoint: "://", wantErr: "is invalid"},
		{name: "valid", validator: &testJWTBearerAssertionValidator{}, endpoint: testTokenEndpoint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, err := newJWTBearerHandler(tt.validator, tt.endpoint)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, h)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, h)
		})
	}
}
