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
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.TranslationOperation;
import it.infn.mw.iam.persistence.model.TranslationRuleEntity;

@Service
public class TranslationEngine {

  private final Map<TranslationOperation, TranslationOperationHandler> handlers;

  public TranslationEngine(List<TranslationOperationHandler> handlers) {
    this.handlers = handlers.stream()
      .collect(Collectors.toMap(TranslationOperationHandler::getOperation, Function.identity()));
  }

  public void execute(Map<String, Object> claims, List<TranslationRuleEntity> rules,
      TranslationContext context) {

    for (TranslationRuleEntity rule : rules) {
      TranslationOperationHandler handler = handlers.get(rule.getOperation());

      if (handler == null) {
        throw new TranslationException(
            "No handler registered for operation: " + rule.getOperation());
      }

      try {
        handler.execute(claims, rule, context);
      } catch (TranslationException e) {
        throw e;
      } catch (Exception e) {
        throw new TranslationException("Error executing translation rule " + rule.getId(), e);
      }
    }
  }
}
