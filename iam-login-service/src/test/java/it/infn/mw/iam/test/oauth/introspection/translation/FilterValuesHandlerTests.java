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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.introspection.translation.FilterValuesHandler;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationContext;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationException;
import it.infn.mw.iam.persistence.model.TranslationOperation;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;

class FilterValuesHandlerTests {

  private final ObjectMapper objectMapper = new ObjectMapper();

  private final FilterValuesHandler handler = new FilterValuesHandler(objectMapper);

  private final TranslationContext context =
      new TranslationContext("https://issuer.example", "resource-server");

  @Test
  void shouldKeepOnlyAllowedValues() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("alpha", "beta", "gamma"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": ["alpha", "beta"]
          }
        }
        """);

    assertEquals(List.of("alpha", "beta"), claims.get("entitlements"));
  }

  @Test
  void shouldRemoveClaimWhenNoValuesAreAllowed() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("alpha", "beta"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": ["gamma"]
          }
        }
        """);

    assertFalse(claims.containsKey("entitlements"));
  }

  @Test
  void shouldRemoveDuplicates() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("alpha", "alpha", "beta"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": ["alpha", "beta"]
          }
        }
        """);

    assertEquals(List.of("alpha", "beta"), claims.get("entitlements"));
  }

  @Test
  void shouldNotModifyClaimsWhenSourceIsMissing() {
    Map<String, Object> claims = new HashMap<>();

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": ["alpha"]
          }
        }
        """);

    assertTrue(claims.isEmpty());
  }

  @Test
  void shouldHandleScopeAsSpaceSeparatedString() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("scope", "openid profile email");

    execute(claims, """
        {
          "source": {
            "claim": "scope",
            "values": ["openid", "email"]
          }
        }
        """);

    assertEquals("openid email", claims.get("scope"));
  }

  @Test
  void shouldRemoveScopeWhenNoValuesAreAllowed() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("scope", "openid profile");

    execute(claims, """
        {
          "source": {
            "claim": "scope",
            "values": ["email"]
          }
        }
        """);

    assertFalse(claims.containsKey("scope"));
  }

  @Test
  void shouldRejectProtectedClaims() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("active", true);

    assertThrows(TranslationException.class, () -> execute(claims, """
        {
          "source": {
            "claim": "active",
            "values": ["true"]
          }
        }
        """));
  }

  @Test
  void shouldRejectInvalidFilterConfiguration() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("alpha"));

    assertThrows(TranslationException.class, () -> execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": "alpha"
          }
        }
        """));
  }

  private void execute(Map<String, Object> claims, String config) {
    TranslationRuleEntity rule = new TranslationRuleEntity();
    rule.setId(1L);
    rule.setOperation(TranslationOperation.FILTER_VALUES);
    rule.setRuleConfig(config);

    handler.execute(claims, rule, context);
  }
}
