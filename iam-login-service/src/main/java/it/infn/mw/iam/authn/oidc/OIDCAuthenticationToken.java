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
package it.infn.mw.iam.authn.oidc;

import java.util.Collection;

import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.GrantedAuthority;

import com.nimbusds.jwt.JWT;

@SuppressWarnings("java:S2160")
public class OIDCAuthenticationToken extends BaseOIDCAuthenticationToken {

  private static final long serialVersionUID = 8085760433250417654L;

  private final UserInfo userInfo;

  public OIDCAuthenticationToken(String subject, String issuer, UserInfo userInfo,
      Collection<? extends GrantedAuthority> authorities, JWT idToken, String accessTokenValue) {

    super(subject, issuer, authorities, idToken, accessTokenValue);

    this.userInfo = userInfo;
    setAuthenticated(true);
  }


  public UserInfo getUserInfo() {
    return userInfo;
  }
}
