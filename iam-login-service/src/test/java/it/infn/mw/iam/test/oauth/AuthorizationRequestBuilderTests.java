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
package it.infn.mw.iam.test.oauth;

import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.CONSENT_TRANSACTION_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import it.infn.mw.iam.core.oauth.AuthorizationRequestBuilder;
import it.infn.mw.iam.core.oauth.RequestObjectProcessor;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;

@SuppressWarnings("deprecation")
class AuthorizationRequestBuilderTests {

  private AuthorizationRequestBuilder builder;

  @BeforeEach
  void setUp() {
    builder = new AuthorizationRequestBuilder(mock(ClientDetailsService.class),
        mock(ScopeFilter.class), mock(RequestObjectProcessor.class));
  }

  @Test
  void generatesDifferentConsentTransactionIdsForNewRequests() {
    Map<String, String> params =
        Map.of("client_id", "client", "response_type", "code", "scope", "openid");

    AuthorizationRequest first = builder.build(params);
    AuthorizationRequest second = builder.build(params);

    builder.addExtensions(params, first);
    builder.addExtensions(params, second);

    String firstId = consentTransactionId(first);
    String secondId = consentTransactionId(second);

    assertValidUuid(firstId);
    assertValidUuid(secondId);
    assertNotEquals(firstId, secondId);
  }

  @Test
  void ignoresClientSuppliedConsentTransactionId() {
    String suppliedId = "00000000-0000-4000-8000-000000000001";

    Map<String, String> params = Map.of("client_id", "client", "response_type", "code", "scope",
        "openid", CONSENT_TRANSACTION_ID, suppliedId);

    AuthorizationRequest request = builder.build(params);

    builder.addExtensions(params, request);

    String generatedId = consentTransactionId(request);

    assertValidUuid(generatedId);
    assertNotEquals(suppliedId, generatedId);
  }

  private static String consentTransactionId(AuthorizationRequest request) {
    return (String) request.getExtensions().get(CONSENT_TRANSACTION_ID);
  }

  private static void assertValidUuid(String value) {
    assertNotNull(value);
    assertEquals(value, UUID.fromString(value).toString());
  }
}
