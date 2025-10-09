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
package it.infn.mw.iam.core.oauth.profile;

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public interface UserInfoHelper {

  /**
   * Returns the list of claim names required to be added to the UserInfo response
   * 
   * @return the list of required claims
   */
  Set<String> getRequiredClaims();

  /**
   * Resolve scope to claim names and their value (if available)
   * 
   * @param scopes The collection of scopes from which computing the related claims
   * @param account The user account info
   * @param auth The current Authentication info that can contain also the external provider additionalInfo
   * @return the map of claim names and values
   */
  Map<String, Object> resolveScopeClaims(Set<String> scopes, IamAccount account,
      OAuth2Authentication auth);

}
