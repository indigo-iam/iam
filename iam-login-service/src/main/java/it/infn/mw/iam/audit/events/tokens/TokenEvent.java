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
package it.infn.mw.iam.audit.events.tokens;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Maps;
import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.IamEventCategory;

@SuppressWarnings("deprecation")
public class TokenEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -1843180591267883819L;

  public static final Logger LOG = LoggerFactory.getLogger(TokenEvent.class);

  private final String subject;
  private final Set<String> scopes;
  private final String grantType;
  private transient Map<String, Object> payload;

  public TokenEvent(Object source, JWT token, AuthenticationHolderEntity authenticationHolder, String message) {
    super(IamEventCategory.TOKEN, source, message);

    // subject will contains user-name or client name
    this.subject = authenticationHolder.getAuthentication().getName();
    this.scopes = authenticationHolder.getScope();
    this.grantType = authenticationHolder.getAuthentication().getOAuth2Request().getGrantType();

    try {
      this.payload = token.getJWTClaimsSet().getClaims();
    } catch (ParseException e) {
      LOG.warn(e.getMessage(), e);
      this.payload = Maps.newHashMap();
    }
  }

  public String getSubject() {
    return subject;
  }

  public Set<String> getScopes() {
    return scopes;
  }

  public String getGrantType() {
    return grantType;
  }

  public Map<String, Object> getPayload() {
    return payload;
  }
}
