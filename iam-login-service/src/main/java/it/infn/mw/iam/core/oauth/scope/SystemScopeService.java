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

import java.util.List;
import java.util.Optional;
import java.util.Set;

import it.infn.mw.iam.persistence.model.SystemScope;

public interface SystemScopeService {

  /**
   * Get all scopes
   * 
   * @return
   */
  public List<SystemScope> getAll();

  /**
   * Get all scopes that are defaulted to new clients on this system
   * 
   * @return
   */
  public List<SystemScope> getDefaults();

  /**
   * Get all the reserved system scopes. These can't be used by clients directly, but are instead
   * tied to special system tokens like id tokens and registration access tokens.
   *
   * @return
   */
  public List<SystemScope> getReserved();

  /**
   * Get all the registered scopes that are restricted.
   * 
   * @return
   */
  public List<SystemScope> getRestricted();

  /**
   * Get all the registered scopes that aren't restricted.
   * 
   * @return
   */
  public List<SystemScope> getUnrestricted();

  /**
   * Get one scope by Id
   * 
   * @return
   */
  public Optional<SystemScope> getById(Long id);

  /**
   * Get one scope by its value
   * 
   * @return
   */
  public Optional<SystemScope> getByValue(String value);

  /**
   * Remove a scope
   * 
   * @return
   */
  public void remove(SystemScope scope);

  /**
   * Save/add a new scope
   * 
   * @return
   */
  public SystemScope save(SystemScope scope);

  /**
   * Test whether the scopes in both sets are compatible. All scopes in "actual" must exist in
   * "expected".
   */
  public boolean scopesMatch(Set<String> expected, Set<String> actual);

  /**
   * Remove any system-reserved or registered restricted scopes from the set and return the result.
   * 
   * @param scopes
   * @return
   */
  public List<SystemScope> getAllNoRestrictedOrReserved();

  /**
   * Remove any system-reserved scopes from the set and return the result.
   * 
   * @param scopes
   * @return
   */
  public List<SystemScope> getAllNoReserved();

}
