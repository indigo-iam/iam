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
public class WLCGGroupHelper {

  public static final String WLCG_GROUP_REGEXP_STR = "wlcg\\.groups(?::((?:\\/[a-zA-Z0-9][a-zA-Z0-9_.-]*)+))?$";
  public static final Pattern WLCG_GROUP_REGEXP = Pattern.compile(WLCG_GROUP_REGEXP_STR);
  
  public static final String WLCG_GROUPS_SCOPE = "wlcg.groups";
  public static final String QUALIFIED_WLCG_GROUPS_SCOPE = "wlcg.groups:/";
  public static final IamLabel OPTIONAL_GROUP_LABEL =
      IamLabel.builder().name("wlcg.optional-group").build();



  private String prependSlashToGroupName(IamGroup g) {
    return format("/%s", g.getName());
  }

  private boolean wantsImplicitGroups(OAuth2AccessTokenEntity token) {
    return token.getScope().stream().anyMatch(this::isWlcgGroupScope)
        && !token.getScope().contains(WLCG_GROUPS_SCOPE);
  }

  private boolean isWlcgGroupScope(String scope) {
    return scope.startsWith(WLCG_GROUPS_SCOPE);
  }

  private Stream<IamGroup> addCatchallGroupScope(IamUserInfo userInfo) {
    return userInfo.getGroups()
      .stream()
      .filter(g -> !g.getLabels().contains(OPTIONAL_GROUP_LABEL))
      .sorted((g1, g2) -> g1.getName().compareTo(g2.getName()));
  }

  private Stream<IamGroup> handleGroupScope(String scope, IamUserInfo userInfo) {
    if (scope.startsWith(QUALIFIED_WLCG_GROUPS_SCOPE)) {
      final String groupName = scope.substring(QUALIFIED_WLCG_GROUPS_SCOPE.length());
      return userInfo.getGroups().stream().filter(g -> g.getName().equals(groupName));
    } else {
      return addCatchallGroupScope(userInfo);
    }
  }


  private Stream<IamGroup> resolveGroupStream(OAuth2AccessTokenEntity token, IamUserInfo userInfo) {
    Stream<IamGroup> groupStream = token.getScope()
      .stream()
      .filter(this::isWlcgGroupScope)
      .flatMap(s -> handleGroupScope(s, userInfo));

    if (wantsImplicitGroups(token)) {
      groupStream = Stream.concat(groupStream, addCatchallGroupScope(userInfo));
    }

    return groupStream;
  }

  public Set<IamGroup> resolveGroups(OAuth2AccessTokenEntity token, IamUserInfo userInfo) {

    return resolveGroupStream(token, userInfo).collect(toCollection(LinkedHashSet::new));
  }

  public Set<String> resolveGroupNames(OAuth2AccessTokenEntity token, IamUserInfo userInfo) {

    return resolveGroupStream(token, userInfo).map(this::prependSlashToGroupName)
      .collect(toCollection(LinkedHashSet::new));
  }


  public void validateGroupScope(String scope) {
    Matcher m = WLCG_GROUP_REGEXP.matcher(scope);
    
    if (!m.matches()) {
      throw new InvalidScopeException("Invalid WLCG group scope: "+scope);
    }
  }

  public void validateGroupScopes(OAuth2Request request) {
    request.getScope().stream().filter(this::isWlcgGroupScope).forEach(this::validateGroupScope);
  }

}
