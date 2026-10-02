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

import java.util.Optional;
import java.util.Set;

import it.infn.mw.iam.persistence.model.SystemScope;

public interface SystemScopeService {

  public static final String OFFLINE_ACCESS_SCOPE = "offline_access";
  public static final String OPENID_SCOPE = "openid";
  public static final String REGISTRATION_TOKEN_SCOPE = "registration-token";
  public static final String RESOURCE_TOKEN_SCOPE = "resource-token";

  Set<SystemScope> getAll();

  Set<SystemScope> getDefaults();

  Set<SystemScope> getRestricted();

  Set<SystemScope> getUnrestricted();

  SystemScope getByValue(String value);

  void remove(SystemScope scope);

  Set<SystemScope> fromStrings(Set<String> scope);

  Set<String> toStrings(Set<SystemScope> scope);

  boolean scopesMatch(Set<String> expected, Set<String> actual);

  SystemScope create(SystemScope entity);

  SystemScope update(SystemScope entity);

  Optional<SystemScope> get(Long id);

  Set<SystemScope> getAllSorted();

}
