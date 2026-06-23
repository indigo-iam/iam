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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.ParseException;
import java.util.ArrayList;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;

public class PendingOIDCAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 22100073066377804L;

  private final ImmutableMap<String, String> principal;
  private final String accessTokenValue;
  private final String refreshTokenValue;
  private transient JWT idToken;
  private final String issuer;
  private final String sub;

  private final transient OIDCProviderMetadata serverConfiguration;

  public PendingOIDCAuthenticationToken(String subject, String issuer,
      OIDCProviderMetadata serverConfiguration, JWT idToken, String accessTokenValue,
      String refreshTokenValue) {

    super(new ArrayList<GrantedAuthority>(0));

    this.principal = ImmutableMap.of("sub", subject, "iss", issuer);
    this.sub = subject;
    this.issuer = issuer;
    this.idToken = idToken;
    this.accessTokenValue = accessTokenValue;
    this.refreshTokenValue = refreshTokenValue;
    this.serverConfiguration = serverConfiguration;

    setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return accessTokenValue;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }

  public String getSub() {
    return sub;
  }

  public JWT getIdToken() {
    return idToken;
  }

  public String getAccessTokenValue() {
    return accessTokenValue;
  }

  public String getRefreshTokenValue() {
    return refreshTokenValue;
  }

  public OIDCProviderMetadata getServerConfiguration() {
    return serverConfiguration;
  }

  public String getIssuer() {
    return issuer;
  }

  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (idToken == null) {
      out.writeObject(null);
    } else {
      out.writeObject(idToken.serialize());
    }
  }

  private void readObject(ObjectInputStream in)
      throws IOException, ClassNotFoundException, ParseException {
    in.defaultReadObject();
    Object o = in.readObject();
    if (o != null) {
      idToken = JWTParser.parse((String) o);
    }
  }

}
