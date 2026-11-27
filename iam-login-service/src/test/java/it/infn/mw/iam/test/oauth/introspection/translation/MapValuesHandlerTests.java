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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.introspection.translation.MapValuesHandler;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationContext;
import it.infn.mw.iam.core.oauth.introspection.translation.TranslationException;
import it.infn.mw.iam.persistence.model.TranslationOperation;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;

class MapValuesHandlerTests {

  private final ObjectMapper objectMapper = new ObjectMapper();

  private final MapValuesHandler handler = new MapValuesHandler(objectMapper);

  private final TranslationContext context =
      new TranslationContext("https://issuer.example", "resource-server");

  @Test
  void shouldReplaceMatchingValue() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("external:alpha"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {
              "external:alpha": ["local:alpha"]
            }
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """);

    assertEquals(List.of("local:alpha"), claims.get("entitlements"));
  }

  @Test
  void shouldKeepUnmatchedValues() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("external:alpha", "external:beta"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {
              "external:alpha": ["local:alpha"]
            }
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """);

    assertEquals(List.of("local:alpha", "external:beta"), claims.get("entitlements"));
  }

  @Test
  void shouldSupportOneToManyMapping() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("external:alpha"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {
              "external:alpha": [
                "local:alpha",
                "local:read"
              ]
            }
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """);

    assertEquals(List.of("local:alpha", "local:read"), claims.get("entitlements"));
  }

  @Test
  void shouldRemoveDuplicates() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("external:alpha", "local:alpha"));

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {
              "external:alpha": ["local:alpha"]
            }
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """);

    assertEquals(List.of("local:alpha"), claims.get("entitlements"));
  }

  @Test
  void shouldNotModifyClaimsWhenSourceIsMissing() {
    Map<String, Object> claims = new HashMap<>();

    execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {}
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """);

    assertTrue(claims.isEmpty());
  }

  @Test
  void shouldHandleScopeAsSpaceSeparatedString() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("scope", "read write");

    execute(claims, """
        {
          "source": {
            "claim": "scope",
            "values": {
              "read": ["openid"]
            }
          },
          "target": {
            "claim": "scope"
          }
        }
        """);

    assertEquals("openid write", claims.get("scope"));
  }

  @Test
  void shouldRejectProtectedTargetClaim() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("active", true);

    assertThrows(TranslationException.class, () -> execute(claims, """
        {
          "source": {
            "claim": "active",
            "values": {
              "true": ["false"]
            }
          },
          "target": {
            "claim": "active"
          }
        }
        """));
  }

  @Test
  void shouldRejectInvalidMappingConfiguration() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("entitlements", List.of("external:alpha"));

    assertThrows(TranslationException.class, () -> execute(claims, """
        {
          "source": {
            "claim": "entitlements",
            "values": {
              "external:alpha": "local:alpha"
            }
          },
          "target": {
            "claim": "entitlements"
          }
        }
        """));
  }

  @Test
  void shouldRejectExistingDifferentTargetClaim() {
    Map<String, Object> claims = new HashMap<>();
    claims.put("external_entitlements", List.of("external:alpha"));
    claims.put("local_entitlements", List.of("local:existing"));

    assertThrows(TranslationException.class, () -> execute(claims, """
        {
          "source": {
            "claim": "external_entitlements",
            "values": {
              "external:alpha": ["local:alpha"]
            }
          },
          "target": {
            "claim": "local_entitlements"
          }
        }
        """));
  }

  private void execute(Map<String, Object> claims, String config) {
    TranslationRuleEntity rule = new TranslationRuleEntity();
    rule.setId(1L);
    rule.setOperation(TranslationOperation.MAP_VALUES);
    rule.setRuleConfig(config);

    handler.execute(claims, rule, context);
  }
}
