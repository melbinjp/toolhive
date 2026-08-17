// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package virtualmcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	mcpv1beta1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1"
	"github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1/v1beta1test"
	"github.com/stacklok/toolhive/test/e2e/images"
)

var _ = ginkgo.Describe("MCPExternalAuthConfig JWT-bearer grant", ginkgo.Ordered, func() {
	const (
		timeout      = 5 * time.Minute
		pollInterval = 2 * time.Second
		externalSub  = "jwt-bearer-external-subject"
	)

	var (
		serverName, authConfigName, dexName, oidcName, oidcConfigName string
		hmacSecretName, signingKeySecretName                          string
		serverIssuer, oidcIssuer, resource                            string
		dexInfo                                                       *DexInfo
		oidcLocalPort                                                 int
		cleanupDexFn, oidcCleanupFn                                   func()
		oidcPortForwardCleanup                                        func()
	)

	ginkgo.BeforeAll(func() {
		suffix := fmt.Sprintf("%d-%d", ginkgo.GinkgoParallelProcess(), time.Now().UnixNano())
		serverName = "e2e-jwt-bearer-server-" + suffix
		authConfigName = "e2e-jwt-bearer-auth-" + suffix
		dexName = "e2e-jwt-bearer-dex-" + suffix
		oidcName = "e2e-jwt-bearer-oidc-" + suffix
		oidcConfigName = "e2e-jwt-bearer-oidccfg-" + suffix
		hmacSecretName = "e2e-jwt-bearer-hmac-" + suffix
		signingKeySecretName = "e2e-jwt-bearer-key-" + suffix
		serverIssuer = fmt.Sprintf("https://mcp-%s-proxy.%s.svc.cluster.local:8080", serverName, defaultNamespace)
		resource = serverIssuer

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: signingKeySecretName, Namespace: defaultNamespace},
			Data: map[string][]byte{"private-key": pem.EncodeToMemory(&pem.Block{
				Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})},
		})).To(gomega.Succeed())
		hmac := make([]byte, 32)
		_, err = rand.Read(hmac)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: hmacSecretName, Namespace: defaultNamespace},
			Data:       map[string][]byte{"hmac": hmac},
		})).To(gomega.Succeed())

		dexInfo, cleanupDexFn = deployDex(ctx, k8sClient, dexName, serverIssuer+"/oauth/callback")
		oidcIssuer, _, oidcCleanupFn = DeployParameterizedOIDCServer(ctx, k8sClient, oidcName, defaultNamespace, timeout, pollInterval)
		oidcLocalPort, oidcPortForwardCleanup, err = startRateLimitServicePortForward(oidcName, 80)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		ginkgo.By("creating an MCPOIDCConfig for the MCPServer authentication")
		gomega.Expect(k8sClient.Create(ctx, &mcpv1beta1.MCPOIDCConfig{
			ObjectMeta: metav1.ObjectMeta{Name: oidcConfigName, Namespace: defaultNamespace},
			Spec: mcpv1beta1.MCPOIDCConfigSpec{
				Type: mcpv1beta1.MCPOIDCConfigTypeInline,
				Inline: &mcpv1beta1.InlineOIDCSharedConfig{
					Issuer:             oidcIssuer,
					JWKSURL:            oidcIssuer + "/jwks",
					InsecureAllowHTTP:  true,
					JWKSAllowPrivateIP: true,
				},
			},
		})).To(gomega.Succeed())

		ginkgo.By("creating a grant-only trusted issuer through MCPExternalAuthConfig")
		gomega.Expect(k8sClient.Create(ctx, &mcpv1beta1.MCPExternalAuthConfig{
			ObjectMeta: metav1.ObjectMeta{Name: authConfigName, Namespace: defaultNamespace},
			Spec: mcpv1beta1.MCPExternalAuthConfigSpec{
				Type: mcpv1beta1.ExternalAuthTypeEmbeddedAuthServer,
				EmbeddedAuthServer: &mcpv1beta1.EmbeddedAuthServerConfig{
					Issuer:               serverIssuer,
					SigningKeySecretRefs: []mcpv1beta1.SecretKeyRef{{Name: signingKeySecretName, Key: "private-key"}},
					HMACSecretRefs:       []mcpv1beta1.SecretKeyRef{{Name: hmacSecretName, Key: "hmac"}},
					UpstreamProviders: []mcpv1beta1.UpstreamProviderConfig{{
						Name: "dex", Type: mcpv1beta1.UpstreamProviderTypeOAuth2,
						OAuth2Config: &mcpv1beta1.OAuth2UpstreamConfig{
							AuthorizationEndpoint: dexInfo.InClusterBaseURL + "/auth",
							TokenEndpoint:         dexInfo.InClusterBaseURL + "/token",
							ClientID:              "mcp-authserver",
							Scopes:                []string{"openid", "profile", "email", "offline_access"},
							InsecureAllowHTTP:     true,
							AllowPrivateIPs:       true,
						},
					}},
					TrustedIssuers: []mcpv1beta1.TrustedIssuerConfig{{
						IssuerURL:         oidcIssuer,
						JWKSURL:           oidcIssuer + "/jwks",
						InsecureAllowHTTP: true,
						AllowPrivateIPs:   true,
						JWTBearerGrant: &mcpv1beta1.JWTBearerGrantConfig{
							MaxAssertionAge: &metav1.Duration{Duration: time.Minute},
							SubjectBindings: []mcpv1beta1.JWTBearerSubjectBinding{{
								Subject: externalSub, AllowedResources: []string{resource},
							}},
						},
					}},
				},
			},
		})).To(gomega.Succeed())

		ginkgo.By("deploying an MCPServer proxy using the external auth configuration")
		server := v1beta1test.NewMCPServer(serverName, defaultNamespace,
			v1beta1test.WithImage(images.YardstickServerImage),
			v1beta1test.WithTransport("streamable-http"),
			v1beta1test.WithProxyPort(8080),
			v1beta1test.WithMCPPort(8080),
			v1beta1test.WithAuthServerRef("MCPExternalAuthConfig", authConfigName),
		)
		server.Spec.OIDCConfigRef = &mcpv1beta1.MCPOIDCConfigReference{
			Name:        oidcConfigName,
			Audience:    resource,
			ResourceURL: resource,
		}
		gomega.Expect(k8sClient.Create(ctx, server)).To(gomega.Succeed())
		gomega.Eventually(func() mcpv1beta1.MCPServerPhase {
			server := &mcpv1beta1.MCPServer{}
			gomega.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: serverName, Namespace: defaultNamespace}, server)).To(gomega.Succeed())
			return server.Status.Phase
		}, timeout, pollInterval).Should(gomega.Equal(mcpv1beta1.MCPServerPhaseReady))
	})

	ginkgo.AfterAll(func() {
		_ = k8sClient.Delete(ctx, v1beta1test.NewMCPServer(serverName, defaultNamespace))
		_ = k8sClient.Delete(ctx, &mcpv1beta1.MCPExternalAuthConfig{ObjectMeta: metav1.ObjectMeta{Name: authConfigName, Namespace: defaultNamespace}})
		_ = k8sClient.Delete(ctx, &mcpv1beta1.MCPOIDCConfig{ObjectMeta: metav1.ObjectMeta{Name: oidcConfigName, Namespace: defaultNamespace}})
		for _, name := range []string{hmacSecretName, signingKeySecretName} {
			_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: defaultNamespace}})
		}
		if oidcPortForwardCleanup != nil {
			oidcPortForwardCleanup()
		}
		if oidcCleanupFn != nil {
			oidcCleanupFn()
		}
		if cleanupDexFn != nil {
			cleanupDexFn()
		}
		gomega.Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Name: serverName, Namespace: defaultNamespace}, &mcpv1beta1.MCPServer{}))
		}, timeout, pollInterval).Should(gomega.BeTrue())
	})

	ginkgo.It("issues an access token without client authentication for the exact subject and resource", func() {
		port, cleanup, err := startRateLimitServicePortForward("mcp-"+serverName+"-proxy", 8080)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer cleanup()

		assertion := mintJWTBearerAssertion(oidcLocalPort, externalSub, tokenEndpointAudience(serverIssuer), "success-jti", time.Now())
		status, body := requestJWTBearerGrant(fmt.Sprintf("http://localhost:%d", port), assertion, resource)
		gomega.Expect(status).To(gomega.Equal(http.StatusOK), string(body))
		var response struct {
			AccessToken string `json:"access_token"`
		}
		gomega.Expect(json.Unmarshal(body, &response)).To(gomega.Succeed())
		gomega.Expect(response.AccessToken).NotTo(gomega.BeEmpty())
	})

	ginkgo.It("rejects an assertion requesting an unauthorized resource", func() {
		port, cleanup, err := startRateLimitServicePortForward("mcp-"+serverName+"-proxy", 8080)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer cleanup()

		assertion := mintJWTBearerAssertion(oidcLocalPort, externalSub, tokenEndpointAudience(serverIssuer), "wrong-resource-jti", time.Now())
		status, _ := requestJWTBearerGrant(fmt.Sprintf("http://localhost:%d", port), assertion, "https://resource.example/forbidden")
		gomega.Expect(status).NotTo(gomega.Equal(http.StatusOK))
	})

	ginkgo.It("rejects replay of a JWT-bearer assertion", func() {
		port, cleanup, err := startRateLimitServicePortForward("mcp-"+serverName+"-proxy", 8080)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		defer cleanup()

		endpoint := fmt.Sprintf("http://localhost:%d", port)
		assertion := mintJWTBearerAssertion(oidcLocalPort, externalSub, tokenEndpointAudience(serverIssuer), "replayed-jti", time.Now())
		status, body := requestJWTBearerGrant(endpoint, assertion, resource)
		gomega.Expect(status).To(gomega.Equal(http.StatusOK), string(body))
		status, _ = requestJWTBearerGrant(endpoint, assertion, resource)
		gomega.Expect(status).NotTo(gomega.Equal(http.StatusOK))
	})
})

func tokenEndpointAudience(issuer string) string {
	return issuer + "/oauth/token"
}

func mintJWTBearerAssertion(oidcLocalPort int, subject, audience, jti string, issuedAt time.Time) string {
	params := url.Values{
		"subject": {subject},
		"aud":     {audience},
		"jti":     {jti},
		"iat":     {fmt.Sprintf("%d", issuedAt.Unix())},
		"exp":     {fmt.Sprintf("%d", issuedAt.Add(30*time.Second).Unix())},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		fmt.Sprintf("http://localhost:%d/token?%s", oidcLocalPort, params.Encode()), nil)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	resp, err := http.DefaultClient.Do(req)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	defer resp.Body.Close()
	gomega.Expect(resp.StatusCode).To(gomega.Equal(http.StatusOK))
	var body struct {
		AccessToken string `json:"access_token"`
	}
	gomega.Expect(json.NewDecoder(resp.Body).Decode(&body)).To(gomega.Succeed())
	gomega.Expect(body.AccessToken).NotTo(gomega.BeEmpty())
	return body.AccessToken
}

func requestJWTBearerGrant(endpoint, assertion, resource string) (int, []byte) {
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
		"resource":   {resource},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint+"/oauth/token", strings.NewReader(form.Encode()))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return resp.StatusCode, body
}
