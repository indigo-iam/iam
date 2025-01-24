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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.nimbusds.jose.JWSHeader;

import it.infn.mw.iam.persistence.model.IamAccessToken;


@JsonPropertyOrder({"timestamp", "@type", "category", "principal", "message", "scopes", "subject",
    "grantType", "header", "payload", "refreshTokenJti", "source"})
public class AccessTokenIssuedEvent extends TokenEvent {

  private static final long serialVersionUID = -2089634827584887622L;

  private final HeaderDTO header = new HeaderDTO();
  private String refreshTokenJti;

  public AccessTokenIssuedEvent(Object source, IamAccessToken token) {
    super(source, token.getJwt(), token.getAuthenticationHolder(), "Issue access token");

    this.header.setAlg(token.getJwt().getHeader().getAlgorithm().getName());
    this.header.setKid(String.valueOf(((JWSHeader) token.getJwt().getHeader()).getKeyID()));

    if (token.getRefreshToken() != null) {
      try {
        this.refreshTokenJti = token.getRefreshToken().getJwt().getJWTClaimsSet().getJWTID();
      } catch (ParseException e) {
        LOG.warn(e.getMessage(), e);
        this.refreshTokenJti = null;
      }
    }
  }

  public HeaderDTO getHeader() {
    return header;
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public String getRefreshTokenJti() {
    return refreshTokenJti;
  }

}
