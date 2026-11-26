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
package it.infn.mw.iam.test.oauth.introspection.translation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.core.oauth.introspection.translation.IamIntrospectionTranslationService;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationContext;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationEngine;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationException;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;
import it.infn.mw.iam.persistence.repository.TranslationRuleRepository;

@ExtendWith(MockitoExtension.class)
class IamIntrospectionTranslationServiceTests {

  private static final String ISSUER = "https://issuer.example.org";
  private static final String RESOURCE_SERVER_ID = "my-resource-server";

  @Mock
  private TranslationRuleRepository ruleRepository;

  @Mock
  private TranslationEngine translationEngine;

  private IamIntrospectionTranslationService translationService;

  @BeforeEach
  void setUp() {
    translationService = new IamIntrospectionTranslationService(ruleRepository, translationEngine,
        new ObjectMapper());
  }

  @Test
  void shouldReturnInactiveWithoutExecutingTranslationWhenResponseIsInactive() {

    IntrospectionResponse response = IntrospectionResponse.inactive();

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    assertFalse(result.isActive());
    assertTrue(result.getAdditionalFields().isEmpty());

    verifyNoInteractions(ruleRepository, translationEngine);
  }

  @Test
  void shouldReturnOriginalClaimsWhenNoRulesAreFound() throws Exception {

    IntrospectionResponse response =
        activeResponse(Map.of("sub", "user123", "email", "user@example.org"));

    when(ruleRepository.findApplicableRules(ISSUER, RESOURCE_SERVER_ID)).thenReturn(List.of());

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    assertTrue(result.isActive());
    assertEquals(response, result);
    assertEquals("user123", result.getAdditionalFields().get("sub"));
    assertEquals("user@example.org", result.getAdditionalFields().get("email"));

    verify(ruleRepository).findApplicableRules(ISSUER, RESOURCE_SERVER_ID);
    verifyNoInteractions(translationEngine);
  }

  @Test
  void shouldApplyTranslationRulesToClaims() throws Exception {

    IntrospectionResponse response = activeResponse(Map.of("sub", "user123"));

    TranslationRuleEntity rule = new TranslationRuleEntity();

    when(ruleRepository.findApplicableRules(ISSUER, RESOURCE_SERVER_ID)).thenReturn(List.of(rule));

    doAnswer(invocation -> {
      Map<String, Object> claims = invocation.getArgument(0);
      claims.put("local_sub", "translated-user123");
      return null;
    }).when(translationEngine).execute(anyMap(), anyList(), any(TranslationContext.class));

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    assertTrue(result.isActive());
    assertEquals("user123", result.getAdditionalFields().get("sub"));
    assertEquals("translated-user123", result.getAdditionalFields().get("local_sub"));

    verify(translationEngine).execute(anyMap(), anyList(), any(TranslationContext.class));
  }

  @Test
  void shouldReturnInactiveWhenTranslationFails() throws Exception {

    IntrospectionResponse response = activeResponse(Map.of("sub", "user123"));

    TranslationRuleEntity rule = new TranslationRuleEntity();

    when(ruleRepository.findApplicableRules(ISSUER, RESOURCE_SERVER_ID)).thenReturn(List.of(rule));

    doThrow(new TranslationException("Invalid translation rule")).when(translationEngine)
      .execute(anyMap(), anyList(), any(TranslationContext.class));

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    assertFalse(result.isActive());
    assertTrue(result.getAdditionalFields().isEmpty());
  }

  @Test
  void shouldReturnInactiveWhenRepositoryFails() {

    IntrospectionResponse response = activeResponse(Map.of("sub", "user123"));

    when(ruleRepository.findApplicableRules(ISSUER, RESOURCE_SERVER_ID))
      .thenThrow(new IllegalStateException("Database unavailable"));

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    assertFalse(result.isActive());
    assertTrue(result.getAdditionalFields().isEmpty());

    verifyNoInteractions(translationEngine);
  }

  @Test
  @SuppressWarnings("unchecked")
  void shouldNotModifyOriginalClaimsWhenTranslationChangesNestedValues() throws Exception {

    List<String> originalEntitlements = new ArrayList<>(List.of("external:read", "external:write"));

    IntrospectionResponse response = activeResponse(Map.of("entitlements", originalEntitlements));

    TranslationRuleEntity rule = new TranslationRuleEntity();

    when(ruleRepository.findApplicableRules(ISSUER, RESOURCE_SERVER_ID)).thenReturn(List.of(rule));

    doAnswer(invocation -> {
      Map<String, Object> claims = invocation.getArgument(0);

      List<String> entitlements = (List<String>) claims.get("entitlements");

      entitlements.set(0, "local:read");

      return null;
    }).when(translationEngine).execute(anyMap(), anyList(), any(TranslationContext.class));

    IntrospectionResponse result =
        translationService.translate(response, ISSUER, RESOURCE_SERVER_ID);

    // The translated response contains the change
    List<String> translatedEntitlements =
        (List<String>) result.getAdditionalFields().get("entitlements");

    assertEquals("local:read", translatedEntitlements.get(0));

    // The original response must not be modified
    List<String> originalResponseEntitlements =
        (List<String>) response.getAdditionalFields().get("entitlements");

    assertEquals("external:read", originalResponseEntitlements.get(0));
    assertEquals("external:write", originalResponseEntitlements.get(1));
  }

  private IntrospectionResponse activeResponse(Map<String, Object> claims) {
    IntrospectionResponse.Builder builder = new IntrospectionResponse.Builder(true);

    claims.forEach(builder::addField);

    return builder.build();
  }
}
