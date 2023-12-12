/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2023
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

import java.util.Date;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;

public abstract class TokenEvent extends IamAuditApplicationEvent {
  private static final long serialVersionUID = 1L;
  private final Date expiration;
  private final String clientId;
  private final Set<String> scopes;

  public TokenEvent(Object source, OAuth2AccessTokenEntity token, String message) {
    super(IamEventCategory.TOKEN, source, message);
    this.expiration = token.getExpiration();
    this.clientId = token.getClient().getClientId();
    this.scopes = token.getScope();
  }

  public Date getExpiration() {
    return expiration;
  }

  public String getClientId() {
    return clientId;
  }

  public Set<String> getScopes() {
    return scopes;
  }


}
