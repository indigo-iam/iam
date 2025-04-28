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
package it.infn.mw.iam.core.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.DefaultClientService;
import it.infn.mw.iam.api.requests.GroupRequestUtils;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;

@SuppressWarnings("deprecation")
@Component
public class IamMethodSecurityExpressionHandler extends OAuth2MethodSecurityExpressionHandler {

  private final AccountUtils accountUtils;
  private final DefaultClientService clientService;
  private final GroupRequestUtils groupRequestUtils;
  private final OAuth2AuthenticationScopeResolver scopeResolver;

  public IamMethodSecurityExpressionHandler(AccountUtils accountUtils,
      DefaultClientService clientService, GroupRequestUtils groupRequestUtils,
      OAuth2AuthenticationScopeResolver scopeResolver) {
    this.accountUtils = accountUtils;
    this.clientService = clientService;
    this.groupRequestUtils = groupRequestUtils;
    this.scopeResolver = scopeResolver;
  }

  @Override
  public StandardEvaluationContext createEvaluationContextInternal(Authentication authentication,
      MethodInvocation mi) {

    StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, mi);
    ec.setVariable("iam", new IamSecurityExpressionMethods(authentication, accountUtils,
        clientService, groupRequestUtils, scopeResolver));
    return ec;
  }

}
