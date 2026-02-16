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
package it.infn.mw.iam.core.oauth.scope;

import java.util.Set;

import it.infn.mw.iam.persistence.model.SystemScope;

public interface SystemScopeService {

  public static final String OFFLINE_ACCESS = "offline_access";
  public static final String OPENID_SCOPE = "openid";
  public static final String REGISTRATION_TOKEN_SCOPE = "registration-token";
  public static final String RESOURCE_TOKEN_SCOPE = "resource-token";
  public static final String UMA_PROTECTION_SCOPE = "uma_protection";
  public static final String UMA_AUTHORIZATION_SCOPE = "uma_authorization";

  public static final Set<SystemScope> reservedScopes =
      Set.of(new SystemScope(REGISTRATION_TOKEN_SCOPE), new SystemScope(RESOURCE_TOKEN_SCOPE));

  public Set<SystemScope> getAll();

  public Set<SystemScope> getDefaults();

  public Set<SystemScope> getReserved();

  public Set<SystemScope> getRestricted();

  public Set<SystemScope> getUnrestricted();

  public SystemScope getById(Long id);

  public SystemScope getByValue(String value);

  public void remove(SystemScope scope);

  public SystemScope save(SystemScope scope);

  public Set<SystemScope> fromStrings(Set<String> scope);

  public Set<String> toStrings(Set<SystemScope> scope);

  public boolean scopesMatch(Set<String> expected, Set<String> actual);

  public Set<SystemScope> removeRestrictedAndReservedScopes(Set<SystemScope> scopes);

  public Set<SystemScope> removeReservedScopes(Set<SystemScope> scopes);
}

