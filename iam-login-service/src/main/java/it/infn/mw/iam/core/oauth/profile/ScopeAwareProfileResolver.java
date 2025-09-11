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

import static java.util.stream.Collectors.toCollection;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class ScopeAwareProfileResolver implements JWTProfileResolver {

  private final Map<String, JWTProfile> profileMap;
  private final JWTProfile defaultProfile;

  public ScopeAwareProfileResolver(JWTProfile defaultProfile, Map<String, JWTProfile> profileMap) {
    this.defaultProfile = defaultProfile;
    this.profileMap = profileMap;
  }

  @Override
  public JWTProfile resolveProfile(Set<String> clientScopes) {

    if (clientScopes == null) {
      throw new IllegalArgumentException("null list of scopes");
    }

    Set<JWTProfile> matchedProfiles = clientScopes
      .stream()
      .filter(profileMap.keySet()::contains)
      .map(profileMap::get)
      .collect(toCollection(LinkedHashSet::new));

    if (matchedProfiles.isEmpty() || matchedProfiles.size() > 1) {
      return defaultProfile;
    }

    return matchedProfiles.iterator().next();
  }
}
