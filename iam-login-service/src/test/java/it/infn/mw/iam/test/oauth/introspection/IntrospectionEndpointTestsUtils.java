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
package it.infn.mw.iam.test.oauth.introspection;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.Date;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;

public class IntrospectionEndpointTestsUtils extends TestTokensUtils {

  protected ResultActions introspect(String username, String password, String tokenToIntrospect,
      TokenTypeHint tokenTypeHint) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint.name()));
  }

  protected ResultActions introspect(String username, String password, String tokenToIntrospect)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect));
  }

  protected ResultActions introspect(String tokenToIntrospect, TokenTypeHint tokenTypeHint)
      throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(anonymous())
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint.name()));
  }

  protected ResultActions introspect(String username, String password, String tokenToIntrospect,
      String tokenTypeHint) throws Exception {

    return mvc.perform(post(INTROSPECTION_ENDPOINT).with(httpBasic(username, password))
      .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .param("token", tokenToIntrospect)
      .param("token_type_hint", tokenTypeHint));
  }

  protected String buildPlainJwt(String issuer, String subject, String clientId, String scopes) {

    Date now = new Date();
    Date exp = new Date(System.currentTimeMillis() + 3600_000L);

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(issuer)
      .subject(subject)
      .issueTime(now)
      .expirationTime(exp)
      .jwtID("jti-external-123")
      .claim("client_id", clientId)
      .claim("scope", scopes)
      .build();

    PlainJWT jwt = new PlainJWT(claims);
    return jwt.serialize();
  }

}
