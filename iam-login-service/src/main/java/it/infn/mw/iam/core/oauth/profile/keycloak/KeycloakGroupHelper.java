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
package it.infn.mw.iam.core.oauth.profile.keycloak;

import java.util.Set;
import java.util.stream.Collectors;

import it.infn.mw.iam.persistence.model.IamUserInfo;

public class KeycloakGroupHelper {

  public static final String KEYCLOAK_ROLES_CLAIM = "roles";

  public Set<String> resolveGroupNames(IamUserInfo userInfo) {

    return userInfo.getGroups().stream().map(g -> g.getName()).collect(Collectors.toSet());
  }

}
