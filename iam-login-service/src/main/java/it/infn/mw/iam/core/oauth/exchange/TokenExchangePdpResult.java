/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.core.oauth.exchange;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

import java.util.Optional;

import it.infn.mw.iam.persistence.model.PolicyRule;



public class TokenExchangePdpResult {
  
  public static final String NOT_APPLICABLE_MSG = "No policy found authorizing this exchange";

  public enum Decision {
    PERMIT,
    DENY,
    NOT_APPLICABLE,
    INVALID_SCOPE
  }

  private final Decision decision;
  private final TokenExchangePolicy policy;
  private final String invalidScope;

  private final String message;

  private TokenExchangePdpResult(Decision decision, TokenExchangePolicy policy, String invalidScope,
      String message) {
    this.decision = decision;
    this.policy = policy;
    this.invalidScope = invalidScope;
    this.message = message;
  }

  private TokenExchangePdpResult(Decision decision, TokenExchangePolicy policy) {
    this(decision, policy, null, null);
  }

  public Decision decision() {
    return decision;
  }

  public Optional<TokenExchangePolicy> policy() {
    return Optional.ofNullable(policy);
  }

  public Optional<String> invalidScope() {
    return Optional.ofNullable(invalidScope);
  }

  public Optional<String> message() {
    return Optional.ofNullable(message);
  }

  public static TokenExchangePdpResult resultFromPolicy(TokenExchangePolicy policy) {
    checkNotNull(policy);
    if (PolicyRule.DENY.equals(policy.getRule())) {
      return new TokenExchangePdpResult(Decision.DENY, policy);
    } else {
      return new TokenExchangePdpResult(Decision.PERMIT, policy);
    }
  }

  public static TokenExchangePdpResult notApplicable() {
    return new TokenExchangePdpResult(Decision.NOT_APPLICABLE, null, null, NOT_APPLICABLE_MSG);
  }

  public static TokenExchangePdpResult invalidScope(TokenExchangePolicy policy, String invalidScope,
      String message) {
    checkNotNull(policy);
    checkArgument(!isNullOrEmpty(invalidScope));
    return new TokenExchangePdpResult(Decision.INVALID_SCOPE, policy, invalidScope, message);
  }

}
