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
import java.util.Optional;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public interface ClaimValueHelper {

  /**
   * Resolve claim names to a value (if available)
   * 
   * @param claimName The claim name from which computing the related value
   * @param auth The current Authentication info that can contain also the external provider additionalInfo
   * @param account The user account info
   * @return the value of claim name
   */
  Object resolveClaim(String claimName, OAuth2Authentication auth, Optional<IamAccount> account);

  /**
   * Resolve claim names to a value (if available)
   * 
   * @param claimNames The collection of claim names from which computing the related values
   * @param auth The current Authentication info that can contain also the external provider additionalInfo
   * @param account The user account info
   * @return the map of claim names and values
   */
  Map<String, Object> resolveClaims(Set<String> claimNames, OAuth2Authentication auth, Optional<IamAccount> account);

  boolean isValidClaimValue(Object claimValue);
}
