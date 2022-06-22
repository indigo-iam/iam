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

import static it.infn.mw.iam.core.oauth.profile.wlcg.WLCGUserInfoAdapter.forUserInfo;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.util.Optional;

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;

@SuppressWarnings("deprecation")
public class WLCGUserinfoHelper extends BaseUserinfoHelper {

  public static final Logger LOG = LoggerFactory.getLogger(WLCGUserinfoHelper.class);

  public WLCGUserinfoHelper(IamProperties props, UserInfoService userInfoService) {
    super(props, userInfoService);
  }


  private Optional<String[]> resolveGroupsFromToken(OAuth2Authentication authentication) {
    OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();

    if (isNull(details) || isNull(details.getTokenValue())) {
      return Optional.empty();
    }

    try {
      JWT accessToken = JWTParser.parse(details.getTokenValue());
      String[] resolvedGroups = accessToken.getJWTClaimsSet().getStringArrayClaim("wlcg.groups");

      return Optional.ofNullable(resolvedGroups);

    } catch (ParseException e) {
      LOG.error("Error parsing access token: {}", e.getMessage(), e);
      return Optional.empty();
    }
  }

  @Override
  public UserInfo resolveUserInfo(OAuth2Authentication authentication) {

    UserInfo ui = lookupUserinfo(authentication);

    if (isNull(ui)) {
      return null;
    }

    Optional<String[]> resolvedGroups = resolveGroupsFromToken(authentication);

    if (resolvedGroups.isPresent()) {
      return forUserInfo(ui, resolvedGroups.get());
    } else {
      return forUserInfo(ui);
    }

  }

}
