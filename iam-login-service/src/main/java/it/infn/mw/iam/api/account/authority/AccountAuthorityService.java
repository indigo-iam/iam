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
package it.infn.mw.iam.api.account.authority;

import java.util.Set;

import it.infn.mw.iam.persistence.model.IamAccount;

/**
 * The IAM Account authority service
 *
 */
public interface AccountAuthorityService {

  /**
   * Returns the authorities linked to an IAM account
   * 
   * @param account the IAM account
   * 
   * @return a {@link Set} of {@link String}s representing the authorities
   */
  Set<String> getAccountAuthorities(IamAccount account);

  /**
   * Adds an authority to a given {@link IamAccount}
   * 
   * @param account the IAM account
   * 
   * @param authority the authority to be added
   * 
   * @throws AuthorityAlreadyBoundError if the authority is already bound to the account
   */
  void addAuthorityToAccount(IamAccount account, String authority);

  /**
   * Removes an authority from a given {@link IamAccount}
   * 
   * @param account the IAM account
   * 
   * @param authority the authority to be removed
   */
  void removeAuthorityFromAccount(IamAccount account, String authority);

}
