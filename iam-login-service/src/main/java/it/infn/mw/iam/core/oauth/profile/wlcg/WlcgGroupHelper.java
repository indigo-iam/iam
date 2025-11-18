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
package it.infn.mw.iam.core.oauth.profile.wlcg;

import static java.lang.String.format;
import static java.util.stream.Collectors.toCollection;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings("deprecation")
public class WlcgGroupHelper {

  public static final String WLCG_GROUP_REGEXP_STR =
      "wlcg\\.groups(?::((?:\\/[a-zA-Z0-9][a-zA-Z0-9_.-]*)+))?$";
  public static final Pattern WLCG_GROUP_REGEXP = Pattern.compile(WLCG_GROUP_REGEXP_STR);

  public static final String QUALIFIED_WLCG_GROUPS_SCOPE = "wlcg.groups:/";
  public static final IamLabel OPTIONAL_GROUP_LABEL =
      IamLabel.builder().name("wlcg.optional-group").build();

  private WlcgGroupHelper() {
    // empty constructor
  }

  private static String prependSlashToGroupName(IamGroup g) {
    return format("/%s", g.getName());
  }

  private static boolean wantsImplicitGroups(Set<String> scopes) {
    return scopes.contains(WlcgOidcScopes.WLCG)
        || (scopes.stream().anyMatch(WlcgOidcScopes::isWlcgGroupScope)
            && !scopes.contains(WlcgOidcScopes.WLCG_GROUPS));
  }

  private static Stream<IamGroup> addCatchallGroupScope(Set<IamGroup> groups) {
    return groups.stream()
      .filter(g -> !g.getLabels().contains(OPTIONAL_GROUP_LABEL))
      .sorted((g1, g2) -> g1.getName().compareTo(g2.getName()));
  }

  private static Stream<IamGroup> handleGroupScope(String scope, Set<IamGroup> groups) {
    if (scope.startsWith(QUALIFIED_WLCG_GROUPS_SCOPE)) {
      final String groupName = scope.substring(QUALIFIED_WLCG_GROUPS_SCOPE.length());
      return groups.stream().filter(g -> g.getName().equals(groupName));
    }
    return addCatchallGroupScope(groups);
  }

  private static Stream<IamGroup> resolveGroupStream(Set<String> scopes, Set<IamGroup> groups) {
    Stream<IamGroup> groupStream = scopes.stream()
      .filter(WlcgOidcScopes::isWlcgGroupScope)
      .flatMap(s -> handleGroupScope(s, groups));

    if (wantsImplicitGroups(scopes)) {
      groupStream = Stream.concat(groupStream, addCatchallGroupScope(groups));
    }

    return groupStream;
  }

  public static Set<IamGroup> resolveGroups(Set<String> scopes, IamUserInfo userInfo) {

    return resolveGroups(scopes, userInfo.getGroups());
  }

  public static Set<IamGroup> resolveGroups(Set<String> scopes, Set<IamGroup> groups) {

    return resolveGroupStream(scopes, groups).collect(toCollection(LinkedHashSet::new));
  }

  public static Set<IamGroup> resolveGroups(OAuth2AccessTokenEntity token, IamUserInfo userInfo) {

    return resolveGroups(token.getScope(), userInfo);
  }

  public static Set<String> resolveGroupNames(OAuth2AccessTokenEntity token, IamUserInfo userInfo) {

    return resolveGroupNames(token.getScope(), userInfo.getGroups());
  }

  public static Set<String> resolveGroupNames(Set<String> scopes, Set<IamGroup> groups) {

    return resolveGroupStream(scopes, groups).map(WlcgGroupHelper::prependSlashToGroupName)
      .collect(toCollection(LinkedHashSet::new));
  }

  public static void validateGroupScope(String scope) {
    Matcher m = WLCG_GROUP_REGEXP.matcher(scope);

    if (!m.matches()) {
      throw new InvalidScopeException("Invalid WLCG group scope: " + scope);
    }
  }

  public static void validateGroupScopes(OAuth2Request request) {
    request.getScope()
      .stream()
      .filter(WlcgOidcScopes::isWlcgGroupScope)
      .forEach(WlcgGroupHelper::validateGroupScope);
  }

}
