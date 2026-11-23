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
package it.infn.mw.iam.test.oauth.client_credentials;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import it.infn.mw.iam.core.oauth.granters.IamClientCredentialsTokenGranter;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@SuppressWarnings("deprecation")
class IamClientCredentialsTokenGranterTests {

  private static final String CLIENT_CREDENTIALS = "client_credentials";

  private final TestableTokenGranter granter = new TestableTokenGranter();

  @Test
  void rejectsClientCredentialsForPublicClient() {

    ClientDetailsEntity client = mock(ClientDetailsEntity.class);
    when(client.getTokenEndpointAuthMethod()).thenReturn(ClientAuthMethod.NONE);
    when(client.getAuthorizedGrantTypes()).thenReturn(Set.of(CLIENT_CREDENTIALS));

    assertThrows(UnauthorizedClientException.class,
        () -> granter.validate(CLIENT_CREDENTIALS, client));
  }

  @Test
  void allowsClientCredentialsForConfidentialClient() {

    ClientDetailsEntity client = mock(ClientDetailsEntity.class);
    when(client.getTokenEndpointAuthMethod()).thenReturn(ClientAuthMethod.SECRET_BASIC);
    when(client.getAuthorizedGrantTypes()).thenReturn(Set.of(CLIENT_CREDENTIALS));

    assertDoesNotThrow(() -> granter.validate(CLIENT_CREDENTIALS, client));
  }

  private static class TestableTokenGranter extends IamClientCredentialsTokenGranter {

    TestableTokenGranter() {
      super(mock(AuthorizationServerTokenServices.class), mock(ClientDetailsService.class),
          mock(OAuth2RequestFactory.class));
    }

    void validate(String grantType, ClientDetailsEntity client) {
      super.validateGrantType(grantType, client);
    }
  }
}
