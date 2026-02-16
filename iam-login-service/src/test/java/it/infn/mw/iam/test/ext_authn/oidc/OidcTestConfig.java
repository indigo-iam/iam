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

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.oidc.RegisteredClient;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.configuration.ClientConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.StaticClientConfigurationService;
import it.infn.mw.iam.authn.oidc.model.ServerConfiguration;
import it.infn.mw.iam.authn.oidc.userinfo.UserInfoFetcher;
import it.infn.mw.iam.core.jwt.IamJwtSigningAndValidationService;
import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwkSetKeyStore;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;
import it.infn.mw.iam.core.oidc.service.IssuerService;
import it.infn.mw.iam.persistence.model.AuthMethod;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@Configuration
public class OidcTestConfig {

  public static final String TEST_OIDC_CLIENT_ID = "iam";
  public static final String TEST_OIDC_ISSUER = "urn:test-oidc-issuer";
  public static final String TEST_OIDC_AUTHORIZATION_ENDPOINT_URI = "http://oidc.test/authz";
  public static final String TEST_OIDC_TOKEN_ENDPOINT_URI = "http://oidc.test/token";
  public static final String TEST_OIDC_JWKS_URI = "http://oidc.test/jwk";

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
  ServerConfigurationService mockServerConfigurationService() {

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer(TEST_OIDC_ISSUER);
    sc.setAuthorizationEndpointUri(TEST_OIDC_AUTHORIZATION_ENDPOINT_URI);
    sc.setTokenEndpointUri(TEST_OIDC_TOKEN_ENDPOINT_URI);
    sc.setJwksUri(TEST_OIDC_JWKS_URI);


    ServerConfigurationService service = Mockito.mock(ServerConfigurationService.class);

    Mockito.when(service.getServerConfiguration(Mockito.anyString())).thenReturn(sc);

    return service;
  }

  @Bean
  @Primary
  ClientConfigurationService staticClientConfiguration() {

    RegisteredClient rc = new RegisteredClient();
    rc.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    rc.setScope(Sets.newHashSet("openid profile email"));
    rc.setClientId(TEST_OIDC_CLIENT_ID);

    Map<String, RegisteredClient> clients = new LinkedHashMap<String, RegisteredClient>();

    clients.put(TEST_OIDC_ISSUER, rc);

    return new StaticClientConfigurationService(clients);
  }

  @Bean
  @Primary
  JwkSetCacheService mockjwkSetCacheService()
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    JwtSigningAndValidationService signatureValidator =
        new IamJwtSigningAndValidationService(mockOidcProviderKeyStore());

    JwkSetCacheService mockCacheService = Mockito.mock(JwkSetCacheService.class);
    Mockito.when(mockCacheService.getValidator(TEST_OIDC_JWKS_URI)).thenReturn(signatureValidator);

    return mockCacheService;

  }

  @Bean
  @Primary
  JwkSetKeyStore mockOidcProviderKeyStore() {
    return new JwkSetKeyStore(new ClassPathResource("/oidc/mock_op_keys.jks"));
  }

  @Bean
  MockOIDCProvider mockOidcProvider(ObjectMapper mapper) {
    return new MockOIDCProvider(mapper, mockOidcProviderKeyStore());
  }

}
