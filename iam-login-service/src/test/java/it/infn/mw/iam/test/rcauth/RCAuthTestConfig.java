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
package it.infn.mw.iam.test.rcauth;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.text.ParseException;

import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.oauth.discovery.DefaultOidcDiscoveryService;

@Configuration
public class RCAuthTestConfig extends RCAuthTestSupport {

  public RCAuthTestConfig() throws IOException, ParseException {
    super();
  }

  @Bean
  @Primary
  OIDCProviderMetadataService mockOIDCProviderMetadata(DefaultOidcDiscoveryService discoveryService,
      RestTemplateFactory restTemplateFactory) {

    OIDCProviderMetadata op =
        new OIDCProviderMetadata(ISSUER, AUTHORIZATION_URI, TOKEN_URI, JWK_URI, USERINFO_URI);

    OIDCProviderMetadataService service = Mockito.mock(OIDCProviderMetadataService.class);
    Mockito.when(service.load(ISSUER)).thenReturn(op);

    return service;
  }

  @Bean
  @Primary
  JWKSetCacheService mockjwkSetCacheService() throws IOException, ParseException {

    IamJWTSigningService signatureValidator = new IamJWTSigningService(rcAuthKeyStore());

    JWKSetCacheService mockCacheService = mock(JWKSetCacheService.class);
    when(mockCacheService.getValidator(JWK_URI)).thenReturn(signatureValidator);

    return mockCacheService;
  }
}
