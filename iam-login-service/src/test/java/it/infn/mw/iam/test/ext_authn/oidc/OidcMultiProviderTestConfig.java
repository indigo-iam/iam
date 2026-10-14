/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.ext_authn.oidc;

import java.io.IOException;
import java.text.ParseException;
import java.time.Clock;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.core.IamThirdPartyIssuerService;
import it.infn.mw.iam.core.client.IssuerService;
import it.infn.mw.iam.core.jwk.IamJWKSetCacheService;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;
import it.infn.mw.iam.util.JwkSetLoader;

@Configuration
public class OidcMultiProviderTestConfig {

  public static final String TEST_OIDC_CLIENT_ID = "iam";

  public static final String TEST_OIDC_01_ISSUER = "http://oidc-01.test";
  public static final String TEST_OIDC_01_AUTHZ_ENDPOINT_URI = "http://oidc-01.test/authz";
  public static final String TEST_OIDC_01_TOKEN_ENDPOINT_URI = "http://oidc-01.test/token";
  public static final String TEST_OIDC_01_JWKS_URI = "http://oidc-01.test/jwk";
  public static final String TEST_OIDC_01_USERINFO_URI = "http://oidc-01.test/userinfo";

  public static final String TEST_OIDC_02_ISSUER = "http://oidc-02.test";
  public static final String TEST_OIDC_02_AUTHZ_ENDPOINT_URI = "http://oidc-02.test/authz";
  public static final String TEST_OIDC_02_TOKEN_ENDPOINT_URI = "http://oidc-02.test/token";
  public static final String TEST_OIDC_02_JWKS_URI = "http://oidc-02.test/jwk";
  public static final String TEST_OIDC_02_USERINFO_URI = "http://oidc-02.test/userinfo";

  @Bean
  @Primary
  RestTemplateFactory restTemplateFactory() {
    return new MockRestTemplateFactory();
  }

  @Bean
  @Primary
  IssuerService oidcIssuerService() {
    return new IamThirdPartyIssuerService();
  }


  @Bean
  @Primary
  OIDCProviderMetadataService mockOIDCProviderMetadata(DefaultOidcDiscoveryService discoveryService,
      RestTemplateFactory restTemplateFactory) {

    OIDCProviderMetadata op01 =
        new OIDCProviderMetadata(TEST_OIDC_01_ISSUER, TEST_OIDC_01_AUTHZ_ENDPOINT_URI,
            TEST_OIDC_01_TOKEN_ENDPOINT_URI, TEST_OIDC_01_JWKS_URI, TEST_OIDC_01_USERINFO_URI);

    OIDCProviderMetadata op02 =
        new OIDCProviderMetadata(TEST_OIDC_02_ISSUER, TEST_OIDC_02_AUTHZ_ENDPOINT_URI,
            TEST_OIDC_02_TOKEN_ENDPOINT_URI, TEST_OIDC_02_JWKS_URI, TEST_OIDC_02_USERINFO_URI);

    OIDCProviderMetadataService service = Mockito.mock(OIDCProviderMetadataService.class);
    Mockito.when(service.load(TEST_OIDC_01_ISSUER)).thenReturn(op01);
    Mockito.when(service.load(TEST_OIDC_02_ISSUER)).thenReturn(op02);

    return service;
  }

  @Bean
  @Primary
  IamJWKSetCacheService mockjwkSetCacheService() throws IOException, ParseException {

    JWTSigningAndValidationService signatureValidator =
        new IamJWTSigningService(mockOidcProviderKeyStore());

    IamJWKSetCacheService mockCacheService = Mockito.mock(IamJWKSetCacheService.class);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_01_JWKS_URI))
      .thenReturn(signatureValidator);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_02_JWKS_URI))
      .thenReturn(signatureValidator);

    return mockCacheService;
  }

  @Bean
  @Primary
  JwkKeyStore mockOidcProviderKeyStore() throws IOException, ParseException {
    ClassPathResource resource = new ClassPathResource("/oidc/mock_op_keys.jks");
    JWKSet jwkSet = JwkSetLoader.load(resource);
    return JwkKeyStore.from(jwkSet);
  }

  @Bean
  MockOIDCProvider mockOidcProvider(Clock clock, ObjectMapper mapper)
      throws IOException, ParseException {
    return new MockOIDCProvider(clock, mapper, mockOidcProviderKeyStore());
  }
}
