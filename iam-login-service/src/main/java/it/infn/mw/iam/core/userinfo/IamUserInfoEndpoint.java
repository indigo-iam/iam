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
package it.infn.mw.iam.core.userinfo;

import static com.nimbusds.jwt.JWTClaimNames.SUBJECT;

import java.util.List;
import java.util.Set;

import javax.security.auth.login.AccountNotFoundException;
import javax.servlet.http.HttpServletRequest;

import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;

@SuppressWarnings("deprecation")
@RestController
public class IamUserInfoEndpoint {

  public static final String URL = "userinfo";

  private static final Logger LOG = LoggerFactory.getLogger(IamUserInfoEndpoint.class);
  private static final String ACCOUNT_NOT_FOUND_ERROR = "User '%s' not found";

  private static final String SCOPE_CLAIM = "scope";
  private static final String SSH_KEYS_CLAIM = "ssh_keys";

  private static final String PROFILE_SCOPE = "profile";
  private static final String SSH_KEYS_SCOPE = "ssh-keys";

  private final JWTProfileResolver profileResolver;
  private final OAuth2AuthenticationScopeResolver scopeResolver;

  public IamUserInfoEndpoint(JWTProfileResolver profileResolver,
      OAuth2AuthenticationScopeResolver scopeResolver) {
    this.profileResolver = profileResolver;
    this.scopeResolver = scopeResolver;
  }

  @PreAuthorize("hasRole('ROLE_USER') and #iam.hasScope('openid')")
  @GetMapping(path = "/" + URL, produces = {MediaType.APPLICATION_JSON_VALUE})
  public UserInfoResponse getInfo(OAuth2Authentication auth) throws AccountNotFoundException {

    JWTProfile profile = profileResolver.resolveProfile(auth.getOAuth2Request().getClientId());

    UserInfo userInfo = profile.getUserinfoHelper().resolveUserInfo(auth);

    if (userInfo == null) {
      String errorMsg = String.format(ACCOUNT_NOT_FOUND_ERROR, auth.getName());
      LOG.error(errorMsg);
      throw new AccountNotFoundException(errorMsg);
    }

    Set<String> scopes = scopeResolver.resolveScope(auth);
    UserInfoResponse.Builder builder = new UserInfoResponse.Builder(userInfo.getSub());
    if (scopes.contains(PROFILE_SCOPE)) {
      if (scopes.contains(SSH_KEYS_SCOPE)) {
        builder.addFieldsFromJson(userInfo.toJson(), List.of(SUBJECT, SCOPE_CLAIM));
      } else {
        builder.addFieldsFromJson(userInfo.toJson(), List.of(SUBJECT, SCOPE_CLAIM, SSH_KEYS_CLAIM));
      }
      builder.addField(SCOPE_CLAIM, scopes);
    }
    return builder.build();
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AccountNotFoundException.class)
  public ErrorDTO accountNotFound(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
