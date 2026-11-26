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

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.core.oauth.introspection.model.IntrospectionResponse;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;
import it.infn.mw.iam.persistence.repository.TranslationRuleRepository;

@Service
public class IamIntrospectionTranslationService {

  private static final Logger LOG =
      LoggerFactory.getLogger(IamIntrospectionTranslationService.class);

  private final TranslationRuleRepository ruleRepository;
  private final TranslationEngine translationEngine;
  private final ObjectMapper objectMapper;

  public IamIntrospectionTranslationService(TranslationRuleRepository ruleRepository,
      TranslationEngine translationEngine, ObjectMapper objectMapper) {
    this.ruleRepository = ruleRepository;
    this.translationEngine = translationEngine;
    this.objectMapper = objectMapper;
  }

  public IntrospectionResponse translate(IntrospectionResponse response, String issuer,
      String resourceServerId) {

    if (!response.isActive()) {
      return IntrospectionResponse.inactive();
    }

    try {
      List<TranslationRuleEntity> rules =
          ruleRepository.findApplicableRules(issuer, resourceServerId);

      if (rules.isEmpty()) {
        return response;
      }

      Map<String, Object> claims = objectMapper.convertValue(response.getAdditionalFields(),
          new TypeReference<Map<String, Object>>() {});

      TranslationContext context = new TranslationContext(issuer, resourceServerId);

      translationEngine.execute(claims, rules, context);

      return IntrospectionResponse.from(true, claims);

    } catch (Exception e) {
      LOG.error("Token introspection translation failed for issuer {} and RS {}", issuer,
          resourceServerId, e);

      return IntrospectionResponse.inactive();
    }
  }
}
