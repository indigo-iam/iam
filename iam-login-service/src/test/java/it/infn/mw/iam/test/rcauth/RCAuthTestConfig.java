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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.authn.oidc.model.ServerConfiguration;
import it.infn.mw.iam.core.jwt.IamJwtSigningAndValidationService;
import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;

@Configuration
class RCAuthTestConfig extends RCAuthTestSupport {

  @Bean
  @Primary
  ServerConfigurationService serverConfigService() {

    ServerConfigurationService scs = mock(ServerConfigurationService.class);
    ServerConfiguration sc = mock(ServerConfiguration.class);
    when(sc.getAuthorizationEndpointUri()).thenReturn(AUTHORIZATION_URI);
    when(sc.getTokenEndpointUri()).thenReturn(TOKEN_URI);
    when(sc.getJwksUri()).thenReturn(JWK_URI);

    when(scs.getServerConfiguration(RCAuthTestSupport.ISSUER)).thenReturn(sc);
    return scs;
  }

  @Bean
  @Primary
  JwkSetCacheService mockjwkSetCacheService()
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    JwtSigningAndValidationService signatureValidator = new IamJwtSigningAndValidationService(rcAuthKeyStore());

    JwkSetCacheService mockCacheService = mock(JwkSetCacheService.class);
    when(mockCacheService.getValidator(JWK_URI)).thenReturn(signatureValidator);

    return mockCacheService;
  }
}
