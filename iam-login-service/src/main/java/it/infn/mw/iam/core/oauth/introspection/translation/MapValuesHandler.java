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
package it.infn.mw.iam.core.oauth.introspection.translation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.introspection.translation.utility.ClaimValueUtils;
import it.infn.mw.iam.core.oauth.introspection.translation.utility.ProtectedClaimUtils;
import it.infn.mw.iam.persistence.model.TranslationOperation;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;

@Component
public class MapValuesHandler implements TranslationOperationHandler {

  private final ObjectMapper objectMapper;

  public MapValuesHandler(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public TranslationOperation getOperation() {
    return TranslationOperation.MAP_VALUES;
  }

  @Override
  public void execute(Map<String, Object> claims, TranslationRuleEntity rule,
      TranslationContext context) {

    try {
      JsonNode config = objectMapper.readTree(rule.getRuleConfig());

      String sourceClaim = requiredText(config, "source", "claim");
      String targetClaim = requiredText(config, "target", "claim");

      ProtectedClaimUtils.validateModifiable(sourceClaim);
      ProtectedClaimUtils.validateSupportedForValueTransformation(targetClaim);

      if (!claims.containsKey(sourceClaim)) {
        return;
      }

      if (!sourceClaim.equals(targetClaim) && claims.containsKey(targetClaim)) {
        throw new TranslationException("Target claim already exists: " + targetClaim);
      }

      JsonNode mappingNode = config.path("source").path("values");

      if (!mappingNode.isObject()) {
        throw new TranslationException("source.values must be a JSON object");
      }

      Map<String, List<String>> mapping = parseMapping(mappingNode);

      Object originalValue = claims.get(sourceClaim);
      List<String> sourceValues = ClaimValueUtils.readValues(sourceClaim, originalValue);

      boolean originallyCollection =
          originalValue instanceof Collection<?> && !"scope".equals(sourceClaim);

      Set<String> translatedValues = new LinkedHashSet<>();

      for (String value : sourceValues) {
        List<String> replacements = mapping.get(value);

        if (replacements == null) {
          translatedValues.add(value);
        } else {
          translatedValues.addAll(replacements);
        }
      }

      Object result = ClaimValueUtils.writeValues(targetClaim, new ArrayList<>(translatedValues),
          originallyCollection);

      claims.put(targetClaim, result);

    } catch (TranslationException e) {
      throw e;
    } catch (Exception e) {
      throw new TranslationException("Invalid MAP_VALUES configuration for rule " + rule.getId(),
          e);
    }
  }

  private Map<String, List<String>> parseMapping(JsonNode mappingNode) {
    Map<String, List<String>> mapping = new LinkedHashMap<>();

    Iterator<Map.Entry<String, JsonNode>> fields = mappingNode.fields();

    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> field = fields.next();

      if (!field.getValue().isArray()) {
        throw new TranslationException("Mapping values must be JSON arrays");
      }

      List<String> replacements = new ArrayList<>();

      for (JsonNode replacement : field.getValue()) {
        if (!replacement.isTextual()) {
          throw new TranslationException("Mapping replacement values must be Strings");
        }

        replacements.add(replacement.asText());
      }

      mapping.put(field.getKey(), replacements);
    }

    return mapping;
  }

  private String requiredText(JsonNode config, String parent, String field) {

    JsonNode value = config.path(parent).path(field);

    if (!value.isTextual() || value.asText().isBlank()) {
      throw new TranslationException(
          "Missing or invalid configuration field: " + parent + "." + field);
    }

    return value.asText();
  }
}
