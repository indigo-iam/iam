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
package it.infn.mw.iam.core.oidc;

import static java.util.stream.Collectors.toSet;

import java.util.Set;

import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.exception.ValidationException;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mitre.openid.connect.service.impl.DefaultDynamicClientValidationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;


public class IamClientValidationService extends DefaultDynamicClientValidationService {

  private final ScopeMatcherRegistry scopeRegistry;

  @Autowired
  public IamClientValidationService(ScopeMatcherRegistry scopeRegistry,
      SystemScopeService scopeService,
      @Qualifier("clientAssertionValidator") AssertionValidator validator,
      BlacklistedSiteService blacklistService, ConfigurationPropertiesBean config,
      ClientDetailsEntityService clientService) {
    super(scopeService, validator, blacklistService, config, clientService);
    this.scopeRegistry = scopeRegistry;
  }

  @Override
  protected ClientDetailsEntity validateScopes(ClientDetailsEntity newClient)
      throws ValidationException {

    Set<ScopeMatcher> matchers = scopeService.getRestricted()
      .stream()
      .map(s -> scopeRegistry.findMatcherForScope(s.getValue()))
      .collect(toSet());

    Set<String> filteredClientScopes = newClient.getScope()
      .stream()
      .filter(s -> matchers.stream().noneMatch(m -> m.matches(s)))
      .collect(toSet());

    newClient.setScope(filteredClientScopes);

    return newClient;
  }
}
