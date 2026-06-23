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
import java.util.LinkedHashMap;
import java.util.Map;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Sets;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.UserInfoFetcher;
import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;
import it.infn.mw.iam.util.JwkSetLoader;

@Configuration
public class OidcTestConfig {

  public static final String TEST_OIDC_CLIENT_ID = "iam";
  public static final String TEST_OIDC_ISSUER = "urn:test-oidc-issuer";
  public static final String TEST_OIDC_AUTHORIZATION_ENDPOINT_URI = "http://oidc.test/authz";
  public static final String TEST_OIDC_TOKEN_ENDPOINT_URI = "http://oidc.test/token";
  public static final String TEST_OIDC_JWKS_URI = "http://oidc.test/jwk";
  public static final String TEST_OIDC_USERINFO_URI = "http://oidc.test/userinfo";

  @Bean
  @Primary
  UserInfoFetcher userInfoFetcher() {

    UserInfoFetcher fetcher = Mockito.mock(UserInfoFetcher.class);
    return fetcher;
  }

  @Bean
  @Primary
  RestTemplateFactory restTemplateFactory() {
    return new MockRestTemplateFactory();
  }

  @Bean
  @Primary
  IssuerService oidcIssuerService() {

    StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
    issuerService.setIssuer(TEST_OIDC_ISSUER);

    return issuerService;
  }

  @Bean
  @Primary
  OIDCProviderMetadataService mockOIDCProviderMetadata(DefaultOidcDiscoveryService discoveryService,
      RestTemplateFactory restTemplateFactory) {

    ObjectNode raw = new ObjectMapper().createObjectNode();

    OIDCProviderMetadata op =
        new OIDCProviderMetadata(TEST_OIDC_ISSUER, TEST_OIDC_AUTHORIZATION_ENDPOINT_URI,
            TEST_OIDC_TOKEN_ENDPOINT_URI, TEST_OIDC_JWKS_URI, TEST_OIDC_USERINFO_URI, raw);

    OIDCProviderMetadataService service = Mockito.mock(OIDCProviderMetadataService.class);
    Mockito.when(service.load(TEST_OIDC_ISSUER)).thenReturn(op);

    return service;
  }

  @Bean
  @Primary
  JWKSetCacheService mockjwkSetCacheService() throws IOException, ParseException {

    JWTSigningAndValidationService signatureValidator =
        new IamJWTSigningService(mockOidcProviderKeyStore());

    JWKSetCacheService mockCacheService = Mockito.mock(JWKSetCacheService.class);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_JWKS_URI)).thenReturn(signatureValidator);

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
