// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package tokenexchange

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"

	"github.com/stacklok/toolhive/pkg/authserver/server"
	"github.com/stacklok/toolhive/pkg/authserver/server/session"
	"github.com/stacklok/toolhive/pkg/authserver/storage"
	"github.com/stacklok/toolhive/pkg/oauthproto"
)

const (
	idJAGJWTType           = "oauth-id-jag+jwt"
	jwtBearerReplayPurpose = "jwt-bearer"
)

// JWTBearerAssertionValidator verifies cryptographic and registered claims of a
// plain RFC 7523 JWT-bearer assertion.
type JWTBearerAssertionValidator interface {
	ValidateJWTBearerAssertion(ctx context.Context, rawToken, tokenEndpoint string) (*ValidatedClaims, error)
}

// JWTBearerHandler implements the unbound RFC 7523 JWT-bearer grant.
type JWTBearerHandler struct {
	*oauth2.HandleHelper
	validator     JWTBearerAssertionValidator
	tokenEndpoint string
	consumer      storage.AssertionJWTConsumer
	config        tokenExchangeConfig
	policies      map[string]*JWTBearerGrantPolicy
}

// NewJWTBearerHandler constructs a validation-only JWT-bearer handler. Production
// composition uses NewJWTBearerIssuanceHandler, which additionally requires replay
// storage and issuance dependencies.
func NewJWTBearerHandler(validator JWTBearerAssertionValidator, tokenEndpoint string) (*JWTBearerHandler, error) {
	if validator == nil {
		return nil, errors.New("JWT-bearer assertion validator must not be nil")
	}
	if tokenEndpoint == "" {
		return nil, errors.New("JWT-bearer token endpoint must not be empty")
	}
	endpoint, err := url.ParseRequestURI(tokenEndpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("JWT-bearer token endpoint is invalid: %q", tokenEndpoint)
	}
	return &JWTBearerHandler{validator: validator, tokenEndpoint: tokenEndpoint}, nil
}

func newJWTBearerIssuanceHandler(
	validator JWTBearerAssertionValidator, tokenEndpoint string, consumer storage.AssertionJWTConsumer,
	config *fosite.Config, strategy oauth2.AccessTokenStrategy, tokenStorage oauth2.AccessTokenStorage,
	trustedIssuers []TrustedIssuer,
) (*JWTBearerHandler, error) {
	handler, err := NewJWTBearerHandler(validator, tokenEndpoint)
	if err != nil {
		return nil, err
	}
	if consumer == nil {
		return nil, errors.New("JWT-bearer storage must implement storage.AssertionJWTConsumer")
	}
	if config == nil || strategy == nil || tokenStorage == nil {
		return nil, errors.New("JWT-bearer issuance dependencies must not be nil")
	}
	policies := make(map[string]*JWTBearerGrantPolicy)
	for _, issuer := range trustedIssuers {
		if issuer.JWTBearerGrant != nil {
			policies[issuer.IssuerURL] = issuer.JWTBearerGrant
		}
	}
	if len(policies) == 0 {
		return nil, errors.New("JWT-bearer issuance requires at least one enabled trusted issuer")
	}
	handler.HandleHelper = &oauth2.HandleHelper{
		AccessTokenStrategy: strategy,
		AccessTokenStorage:  tokenStorage,
		Config:              config,
	}
	handler.consumer = consumer
	handler.config = config
	handler.policies = policies
	return handler, nil
}

// CanHandleTokenEndpointRequest only claims plain assertions. A recognized ID-JAG
// assertion is intentionally left for a future bound handler; malformed and
// unsupported typ values remain this handler's responsibility to reject.
func (*JWTBearerHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(oauthproto.GrantTypeJWTBearer) &&
		assertionType(requester.GetRequestForm().Get("assertion")) != idJAGJWTType
}

// CanSkipClientAuth permits only plain JWT-bearer assertions.
func (*JWTBearerHandler) CanSkipClientAuth(_ context.Context, requester fosite.AccessRequester) bool {
	return assertionType(requester.GetRequestForm().Get("assertion")) != idJAGJWTType
}

// HandleTokenEndpointRequest validates policy and prepares a bounded access-token session.
func (h *JWTBearerHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}
	assertion, err := validateJWTBearerAssertionForm(requester.GetRequestForm())
	if err != nil {
		return err
	}
	if _, err := validateAssertionType(assertion); err != nil {
		return err
	}
	claims, err := h.validator.ValidateJWTBearerAssertion(ctx, assertion, h.tokenEndpoint)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion is invalid or could not be verified."))
	}
	if h.consumer == nil {
		return nil // validation-only constructor, retained for its focused seam tests.
	}
	policy, ok := h.policies[claims.Issuer]
	if !ok {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion issuer is not enabled for this grant."))
	}
	resource, err := validateJWTBearerPolicy(requester.GetRequestForm(), claims, policy)
	if err != nil {
		return err
	}
	// Consume before issuing. This intentionally fails closed: if issuance fails
	// after this point, the assertion remains consumed rather than becoming
	// replayable.
	if err := h.consumer.ConsumeAssertionJWT(ctx, jwtBearerReplayPurpose, claims.Issuer, claims.JWTID, claims.Expiry); err != nil {
		if errors.Is(err, fosite.ErrJTIKnown) {
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion has already been used."))
		}
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion could not be consumed."))
	}
	remaining := time.Until(claims.Expiry)
	if remaining <= 0 {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion has expired."))
	}
	lifetime := h.config.GetAccessTokenLifespan(ctx)
	if remaining < lifetime {
		lifetime = remaining
	}
	issuedSession := session.New(
		claims.Issuer+"#"+claims.Subject, "",
		jwtBearerClientID(claims.Issuer, claims.Subject), session.UserClaims{})
	issuedSession.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(lifetime))
	requester.GrantAudience(resource)
	requester.SetSession(issuedSession)
	return nil
}

func validateJWTBearerPolicy(form url.Values, claims *ValidatedClaims, policy *JWTBearerGrantPolicy) (string, error) {
	if claims.IssuedAt.IsZero() || claims.Expiry.IsZero() || claims.Expiry.Sub(claims.IssuedAt) > policy.maxAssertionAge {
		return "", errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion exceeds the configured maximum age."))
	}
	resources, present := form["resource"]
	if !present || len(resources) != 1 || resources[0] == "" {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Exactly one resource parameter is required for the JWT-bearer grant."))
	}
	if err := server.ValidateAudienceURI(resources[0]); err != nil {
		return "", errorsx.WithStack(err)
	}
	for _, binding := range policy.SubjectBindings {
		if binding.Subject == claims.Subject {
			for _, resource := range binding.AllowedResources {
				if resource == resources[0] {
					return resource, nil
				}
			}
			return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
				"The requested resource is not authorized for this JWT bearer subject."))
		}
	}
	return "", errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(
		"The JWT bearer assertion subject is not configured for this grant."))
}

// PopulateTokenEndpointResponse issues only an access token.
func (h *JWTBearerHandler) PopulateTokenEndpointResponse(
	ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder,
) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}
	if h.HandleHelper == nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("JWT-bearer token issuance is not configured."))
	}
	lifetime := h.config.GetAccessTokenLifespan(ctx)
	if expiry := requester.GetSession().GetExpiresAt(fosite.AccessToken); !expiry.IsZero() {
		remaining := time.Until(expiry)
		if remaining <= 0 {
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The JWT bearer assertion has expired."))
		}
		if remaining < lifetime {
			lifetime = remaining
		}
	}
	_, err := h.IssueAccessToken(ctx, lifetime, requester, responder)
	return err
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func jwtBearerClientID(issuer, subject string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "jwt-bearer-" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func validateJWTBearerAssertionForm(form url.Values) (string, error) {
	assertions, ok := form["assertion"]
	if !ok || len(assertions) != 1 || assertions[0] == "" {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"The 'assertion' parameter is required exactly once for the JWT-bearer grant."))
	}
	return assertions[0], nil
}

func validateAssertionType(assertion string) (string, error) {
	parsed, err := jwt.ParseSigned(assertion, allowedSignatureAlgorithms)
	if err != nil {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The assertion is not a valid signed JWT."))
	}
	if len(parsed.Headers) != 1 {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The assertion must contain exactly one JOSE signature."))
	}
	typ, ok := parsed.Headers[0].ExtraHeaders[jose.HeaderType]
	if !ok {
		return "", nil
	}
	value, ok := typ.(string)
	if !ok {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The assertion JOSE typ header must be a string."))
	}
	if value == "" || value == "JWT" || value == idJAGJWTType {
		return value, nil
	}
	return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The assertion JOSE typ header is not supported."))
}

func assertionType(assertion string) string {
	parsed, err := jwt.ParseSigned(assertion, allowedSignatureAlgorithms)
	if err != nil || len(parsed.Headers) != 1 {
		return ""
	}
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	return typ
}

func validateJWTBearerAssertionClaims(claims jwt.Claims, issuer, tokenEndpoint string) error {
	if claims.Expiry == nil {
		return errors.New("assertion is missing required 'exp' claim")
	}
	if claims.IssuedAt == nil {
		return errors.New("assertion is missing required 'iat' claim")
	}
	if claims.Subject == "" {
		return errors.New("assertion is missing required 'sub' claim")
	}
	if claims.ID == "" {
		return errors.New("assertion is missing required 'jti' claim")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != tokenEndpoint {
		return fmt.Errorf("assertion audience must be exactly token endpoint %q", tokenEndpoint)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer}, 0); err != nil {
		return fmt.Errorf("assertion claims validation failed: %w", err)
	}
	return nil
}

// JWTBearerIssuanceFactory builds the production RFC 7523 handler. It is only
// registered by composition when a trusted issuer opts into the grant.
func JWTBearerIssuanceFactory(trustedIssuers []TrustedIssuer) (server.Factory, error) {
	resolvedIssuers, err := ResolveJWTBearerGrantPolicies(trustedIssuers)
	if err != nil {
		return nil, fmt.Errorf("JWT-bearer trusted issuers: %w", err)
	}
	return func(config *server.AuthorizationServerConfig, rawStorage fosite.Storage, strategy any) (any, error) {
		consumer, ok := rawStorage.(storage.AssertionJWTConsumer)
		if !ok {
			return nil, fmt.Errorf("JWT-bearer storage %T does not implement storage.AssertionJWTConsumer", rawStorage)
		}
		atStrategy, ok := strategy.(oauth2.AccessTokenStrategy)
		if !ok {
			return nil, fmt.Errorf("JWT-bearer strategy does not implement oauth2.AccessTokenStrategy (got %T)", strategy)
		}
		atStorage, ok := rawStorage.(oauth2.AccessTokenStorage)
		if !ok {
			return nil, fmt.Errorf("JWT-bearer storage does not implement oauth2.AccessTokenStorage (got %T)", rawStorage)
		}
		for _, issuer := range resolvedIssuers {
			if issuer.JWTBearerGrant == nil {
				continue
			}
			for _, binding := range issuer.JWTBearerGrant.SubjectBindings {
				for _, resource := range binding.AllowedResources {
					if !containsString(config.AllowedAudiences, resource) {
						return nil, fmt.Errorf("JWT-bearer resource %q is not an allowed audience", resource)
					}
				}
			}
		}
		selfValidator, err := NewSelfIssuedTokenValidator(config.PublicJWKS(), config.GetAccessTokenIssuer(), config.AllowedAudiences)
		if err != nil {
			return nil, fmt.Errorf("JWT-bearer: failed to create self validator: %w", err)
		}
		validator, err := NewMultiIssuerTokenValidator(selfValidator, config.GetAccessTokenIssuer(), resolvedIssuers)
		if err != nil {
			return nil, fmt.Errorf("JWT-bearer: trusted_issuers: %w", err)
		}
		return newJWTBearerIssuanceHandler(validator, config.TokenURL, consumer, config.Config, atStrategy, atStorage, resolvedIssuers)
	}, nil
}

// JWTBearerFactory returns a validation-only handler for focused callers.
func JWTBearerFactory(validator JWTBearerAssertionValidator, tokenEndpoint string) (server.Factory, error) {
	handler, err := NewJWTBearerHandler(validator, tokenEndpoint)
	if err != nil {
		return nil, err
	}
	return func(*server.AuthorizationServerConfig, fosite.Storage, any) (any, error) { return handler, nil }, nil
}

var _ fosite.TokenEndpointHandler = (*JWTBearerHandler)(nil)
