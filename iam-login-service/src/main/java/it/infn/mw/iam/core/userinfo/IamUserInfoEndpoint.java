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

import static com.google.common.base.Strings.isNullOrEmpty;

import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.UserInfoView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;

@SuppressWarnings("deprecation")
@Controller
@RequestMapping("/userinfo")
public class IamUserInfoEndpoint {

  private static final Logger LOG = LoggerFactory.getLogger(IamUserInfoEndpoint.class);

  private final JWTProfileResolver profileResolver;

  private final OAuth2AuthenticationScopeResolver scopeResolver;

  @Autowired
  public IamUserInfoEndpoint(JWTProfileResolver profileResolver,
      OAuth2AuthenticationScopeResolver scopeResolver) {
    this.profileResolver = profileResolver;
    this.scopeResolver = scopeResolver;
  }

  @PreAuthorize("hasRole('ROLE_USER') and #oauth2.hasScope('" + SystemScopeService.OPENID_SCOPE
      + "')")
  @RequestMapping(method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE})
  public String getInfo(
      @RequestParam(value = "claims", required = false) String claimsRequestJsonString,
      @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String acceptHeader,
      OAuth2Authentication auth, Model model) {

    JWTProfile profile = profileResolver.resolveProfile(auth.getOAuth2Request().getClientId());

    UserInfo userInfo = profile.getUserinfoHelper().resolveUserInfo(auth);

    if (userInfo == null) {
      LOG.error("user not found: {}", auth.getName());
      model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      return HttpCodeView.VIEWNAME;
    }
    model.addAttribute(UserInfoView.SCOPE, scopeResolver.resolveScope(auth));
    model.addAttribute(UserInfoView.AUTHORIZED_CLAIMS,
        auth.getOAuth2Request().getExtensions().get("claims"));

    if (!isNullOrEmpty(claimsRequestJsonString)) {
      model.addAttribute(UserInfoView.REQUESTED_CLAIMS, claimsRequestJsonString);
    }

    model.addAttribute(UserInfoView.USER_INFO, userInfo);

    return UserInfoView.VIEWNAME;

  }

}
