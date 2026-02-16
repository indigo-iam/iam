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
package it.infn.mw.iam.core.token;

import java.text.ParseException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.authn.jwt.JwtBearerAssertionAuthenticationToken;
import it.infn.mw.iam.core.OAuth2TokenEntityService;
import it.infn.mw.iam.core.jwt.assertion.AssertionOAuth2RequestFactory;
import it.infn.mw.iam.core.jwt.assertion.AssertionValidator;

@SuppressWarnings("deprecation")
@Component("jwtAssertionTokenGranter")
public class JwtAssertionTokenGranter extends AbstractTokenGranter {

  private static final String grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

  private final AssertionValidator validator;
  private final AssertionOAuth2RequestFactory assertionFactory;

  public JwtAssertionTokenGranter(OAuth2TokenEntityService tokenServices,
      ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory,
      AssertionValidator validator, AssertionOAuth2RequestFactory assertionFactory) {
    super(tokenServices, clientDetailsService, requestFactory, grantType);

    this.validator = validator;
    this.assertionFactory = assertionFactory;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails client,
      TokenRequest tokenRequest) throws AuthenticationException, InvalidTokenException {

    try {
      String incomingAssertionValue = tokenRequest.getRequestParameters().get("assertion");
      JWT assertion = JWTParser.parse(incomingAssertionValue);

      if (validator.isValid(assertion)) {

        return new OAuth2Authentication(
            assertionFactory.createOAuth2Request(client, tokenRequest, assertion),
            new JwtBearerAssertionAuthenticationToken(assertion, client.getAuthorities()));

      } else {
        logger.warn("Incoming assertion did not pass validator, rejecting");
        return null;
      }

    } catch (ParseException e) {
      logger.warn("Unable to parse incoming assertion");
    }

    return null;
  }
}
