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
package it.infn.mw.iam.core.oauth.granters;

import java.text.ParseException;

import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.core.oauth.assertion.JwtAssertionAuthenticationToken;

@SuppressWarnings("deprecation")
public class JwtAssertionTokenGranter extends AbstractTokenGranter {

  public static final Logger LOG = LoggerFactory.getLogger(JwtAssertionTokenGranter.class);

  public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

  private final AssertionValidator assertionValidator;
  private final AssertionOAuth2RequestFactory assertionFactory;

  public JwtAssertionTokenGranter(OAuth2TokenEntityService tokenServices,
      ClientDetailsEntityService clientDetailsService, OAuth2RequestFactory requestFactory, AssertionOAuth2RequestFactory assertionFactory,
      @Qualifier("jwtAssertionValidator") AssertionValidator assertionValidator) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    this.assertionFactory = assertionFactory;
    this.assertionValidator = assertionValidator;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) throws AuthenticationException, InvalidTokenException {

    try {
      String incomingAssertionValue = tokenRequest.getRequestParameters().get("assertion");
      JWT assertion = JWTParser.parse(incomingAssertionValue);

      if (!assertionValidator.isValid(assertion)) {
        LOG.warn("Incoming assertion did not pass validator, rejecting");
        return null;
      }
      return new OAuth2Authentication(
          assertionFactory.createOAuth2Request(client, tokenRequest, assertion),
          new JwtAssertionAuthenticationToken(assertion, client.getAuthorities()));

    } catch (ParseException e) {
      LOG.warn("Unable to parse incoming assertion");
    }
    return null;
  }

}
