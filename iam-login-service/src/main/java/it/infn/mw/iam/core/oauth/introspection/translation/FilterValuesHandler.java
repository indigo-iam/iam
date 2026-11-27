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

import java.util.Collection;
import java.util.HashSet;
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
public class FilterValuesHandler implements TranslationOperationHandler {

  private final ObjectMapper objectMapper;

  public FilterValuesHandler(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public TranslationOperation getOperation() {
    return TranslationOperation.FILTER_VALUES;
  }

  @Override
  public void execute(Map<String, Object> claims, TranslationRuleEntity rule,
      TranslationContext context) {

    try {
      JsonNode config = objectMapper.readTree(rule.getRuleConfig());

      JsonNode claimNode = config.path("source").path("claim");

      if (!claimNode.isTextual() || claimNode.asText().isBlank()) {
        throw new TranslationException("Missing or invalid source.claim");
      }

      String claimName = claimNode.asText();

      ProtectedClaimUtils.validateSupportedForValueTransformation(claimName);

      if (!claims.containsKey(claimName)) {
        return;
      }

      JsonNode valuesNode = config.path("source").path("values");

      if (!valuesNode.isArray()) {
        throw new TranslationException("source.values must be a JSON array");
      }

      Set<String> allowedValues = new HashSet<>();

      for (JsonNode value : valuesNode) {
        if (!value.isTextual()) {
          throw new TranslationException("Filter values must be Strings");
        }

        allowedValues.add(value.asText());
      }

      Object originalValue = claims.get(claimName);

      List<String> sourceValues = ClaimValueUtils.readValues(claimName, originalValue);

      boolean originallyCollection =
          originalValue instanceof Collection<?> && !"scope".equals(claimName);

      List<String> filteredValues =
          sourceValues.stream().filter(allowedValues::contains).distinct().toList();

      if (filteredValues.isEmpty()) {
        claims.remove(claimName);
        return;
      }

      Object result = ClaimValueUtils.writeValues(claimName, filteredValues, originallyCollection);

      claims.put(claimName, result);

    } catch (TranslationException e) {
      throw e;
    } catch (Exception e) {
      throw new TranslationException("Invalid FILTER_VALUES configuration for rule " + rule.getId(),
          e);
    }
  }
}
