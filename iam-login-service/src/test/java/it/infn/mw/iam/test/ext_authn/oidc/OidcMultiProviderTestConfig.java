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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.core.IamThirdPartyIssuerService;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@Configuration
public class OidcMultiProviderTestConfig {

  public static final String TEST_OIDC_CLIENT_ID = "iam";

  public static final String TEST_OIDC_01_ISSUER = "http://oidc-01.test";
  public static final String TEST_OIDC_01_AUTHZ_ENDPOINT_URI = "http://oidc-01.test/authz";
  public static final String TEST_OIDC_01_TOKEN_ENDPOINT_URI = "http://oidc-01.test/token";
  public static final String TEST_OIDC_01_JWKS_URI = "http://oidc-01.test/jwk";

  public static final String TEST_OIDC_02_ISSUER = "http://oidc-02.test";
  public static final String TEST_OIDC_02_AUTHZ_ENDPOINT_URI = "http://oidc-02.test/authz";
  public static final String TEST_OIDC_02_TOKEN_ENDPOINT_URI = "http://oidc-02.test/token";
  public static final String TEST_OIDC_02_JWKS_URI = "http://oidc-02.test/jwk";

  @Bean
  @Primary
  public UserInfoFetcher userInfoFetcher() {
    UserInfoFetcher fetcher = Mockito.mock(UserInfoFetcher.class);
    return fetcher;
  }

  @Bean
  @Primary
  public RestTemplateFactory restTemplateFactory() {
    return new MockRestTemplateFactory();
  }

  @Bean
  @Primary
  public IssuerService oidcIssuerService() {
    return new IamThirdPartyIssuerService();
  }


  @Bean
  @Primary
  public ServerConfigurationService mockServerConfigurationService() {

    ServerConfiguration sc01 = new ServerConfiguration();
    sc01.setIssuer(TEST_OIDC_01_ISSUER);
    sc01.setAuthorizationEndpointUri(TEST_OIDC_01_AUTHZ_ENDPOINT_URI);
    sc01.setTokenEndpointUri(TEST_OIDC_01_TOKEN_ENDPOINT_URI);
    sc01.setJwksUri(TEST_OIDC_01_JWKS_URI);

    ServerConfiguration sc02 = new ServerConfiguration();
    sc02.setIssuer(TEST_OIDC_02_ISSUER);
    sc02.setAuthorizationEndpointUri(TEST_OIDC_02_AUTHZ_ENDPOINT_URI);
    sc02.setTokenEndpointUri(TEST_OIDC_02_TOKEN_ENDPOINT_URI);
    sc02.setJwksUri(TEST_OIDC_02_JWKS_URI);

    Map<String, ServerConfiguration> servers = new LinkedHashMap<>();
    servers.put(TEST_OIDC_01_ISSUER, sc01);
    servers.put(TEST_OIDC_02_ISSUER, sc02);

    StaticServerConfigurationService service = new StaticServerConfigurationService();
    service.setServers(servers);

    return service;
  }

  @Bean
  @Primary
  public ClientConfigurationService staticClientConfiguration() {

    RegisteredClient rc = new RegisteredClient();
    rc.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    rc.setScope(Sets.newHashSet("openid profile email"));
    rc.setClientId(TEST_OIDC_CLIENT_ID);

    Map<String, RegisteredClient> clients = new LinkedHashMap<String, RegisteredClient>();
    clients.put(TEST_OIDC_01_ISSUER, rc);
    clients.put(TEST_OIDC_02_ISSUER, rc);

    StaticClientConfigurationService config = new StaticClientConfigurationService();
    config.setClients(clients);

    return config;
  }

  @Bean
  @Primary
  public JWKSetCacheService mockjwkSetCacheService()
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    JWTSigningAndValidationService signatureValidator =
        new IamJWTSigningService(mockOidcProviderKeyStore());

    JWKSetCacheService mockCacheService = Mockito.mock(JWKSetCacheService.class);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_01_JWKS_URI))
      .thenReturn(signatureValidator);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_02_JWKS_URI))
      .thenReturn(signatureValidator);

    return mockCacheService;
  }

  @Bean
  @Primary
  public JWKSetKeyStore mockOidcProviderKeyStore() {
    JWKSetKeyStore ks = new JWKSetKeyStore();
    ks.setLocation(new ClassPathResource("/oidc/mock_op_keys.jks"));
    return ks;
  }

  @Bean
  public MockOIDCProvider mockOidcProvider(ObjectMapper mapper) {
    return new MockOIDCProvider(mapper, mockOidcProviderKeyStore());
  }
}
