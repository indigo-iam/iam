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
package it.infn.mw.iam.util.test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;

public class OidcSecurityContextBuilder extends SecurityContextBuilderSupport {

  private UserInfo userInfo = null;
  private Map<String, String> stringClaims = Maps.newHashMap();

  public OidcSecurityContextBuilder() {
    issuer = "test-oidc-issuer";

    subject = "test-oidc-subject";

    username = "test-oidc-subject";

    userInfo = mock(UserInfo.class);
  }

  @Override
  public SecurityContext buildSecurityContext() {

    OIDCAuthenticationToken authToken = mock(OIDCAuthenticationToken.class);
    UserInfo ui = mock(UserInfo.class);
    when(authToken.getUserInfo()).thenReturn(ui);

    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

    builder.issuer(issuer).subject(subject);

    stringClaims.entrySet().forEach(e -> builder.claim(e.getKey(), e.getValue()));

    JWT idToken = new PlainJWT(builder.build());
    when(authToken.getIssuer()).thenReturn(issuer);
    when(authToken.getSub()).thenReturn(subject);
    when(authToken.getPrincipal()).thenReturn(subject + "@" + issuer);
    when(authToken.getName()).thenReturn(username);
    when(authToken.getIdToken()).thenReturn(idToken);
    
    
    if (expirationTime == null) {
      Calendar cal = Calendar.getInstance();
      cal.add(Calendar.HOUR, 2);
      expirationTime = cal.getTime();
    }

    OidcExternalAuthenticationToken token = new OidcExternalAuthenticationToken(authToken,
        expirationTime, authToken.getPrincipal(), "", authorities);
    
    
    when(ui.getGivenName()).thenReturn(stringClaims.get("given_name"));
    when(ui.getFamilyName()).thenReturn(stringClaims.get("family_name"));
    when(ui.getName()).thenReturn(stringClaims.get("name"));
    when(ui.getEmail()).thenReturn(stringClaims.get("email"));
    when(ui.getPreferredUsername()).thenReturn(username);
    
    


    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(token);
    return context;
  }


  public SecurityContextBuilderSupport name(String givenName, String familyName) {

    if (!Strings.isNullOrEmpty(givenName) && !Strings.isNullOrEmpty(familyName)) {
      when(userInfo.getGivenName()).thenReturn(givenName);
      when(userInfo.getFamilyName()).thenReturn(familyName);
      when(userInfo.getName()).thenReturn(givenName + " " + familyName);

      stringClaims.put("given_name", givenName);
      stringClaims.put("family_name", familyName);
      stringClaims.put("name", givenName + " " + familyName);
    }
    return this;
  }

  public SecurityContextBuilderSupport email(String email) {

    if (!Strings.isNullOrEmpty(email)) {
      stringClaims.put("email", email);
      when(userInfo.getEmail()).thenReturn(email);
    }
    return this;

  }

  @Override
  public OidcSecurityContextBuilder expirationTime(long unixTime) {
    if (unixTime > 0) {
      this.expirationTime = new Date(unixTime);
    }
    return this;
  }

  public OidcSecurityContextBuilder claim(String name, String value) {
    stringClaims.put(name, value);
    return this;
  }
}
