// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcpv1beta1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1"
)

var _ = Describe("MCPExternalAuthConfig JWT-bearer grant schema validation", Label("k8s", "validation"), func() {
	const namespace = "default"

	makeConfig := func(name string, maxAssertionAge time.Duration) *mcpv1beta1.MCPExternalAuthConfig {
		return &mcpv1beta1.MCPExternalAuthConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: mcpv1beta1.MCPExternalAuthConfigSpec{
				Type: mcpv1beta1.ExternalAuthTypeEmbeddedAuthServer,
				EmbeddedAuthServer: &mcpv1beta1.EmbeddedAuthServerConfig{
					Issuer: "https://auth.example.com",
					UpstreamProviders: []mcpv1beta1.UpstreamProviderConfig{{
						Name:       "upstream",
						Type:       mcpv1beta1.UpstreamProviderTypeOIDC,
						OIDCConfig: &mcpv1beta1.OIDCUpstreamConfig{IssuerURL: "https://upstream.example.com", ClientID: "client-id"},
					}},
					TrustedIssuers: []mcpv1beta1.TrustedIssuerConfig{{
						IssuerURL: "https://issuer.example.com",
						JWTBearerGrant: &mcpv1beta1.JWTBearerGrantConfig{
							MaxAssertionAge: &metav1.Duration{Duration: maxAssertionAge},
							SubjectBindings: []mcpv1beta1.JWTBearerSubjectBinding{{
								Subject:          "external-subject",
								AllowedResources: []string{"https://mcp.example.com"},
							}},
						},
					}},
				},
			},
		}
	}

	It("accepts a positive metav1.Duration", func() {
		Expect(k8sClient.Create(ctx, makeConfig("jwt-bearer-positive-age", time.Minute))).To(Succeed())
	})

	It("rejects a zero maxAssertionAge", func() {
		err := k8sClient.Create(ctx, makeConfig("jwt-bearer-zero-age", 0))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("maxAssertionAge"))
	})
})
