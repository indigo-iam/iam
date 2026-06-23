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
package it.infn.mw.iam.core.web.loginpage;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.jwt.assertion.impl.SelfAssertionValidator;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Component
public class IamLogoutSuccessHandler implements LogoutSuccessHandler {

  private static final Logger LOG = LoggerFactory.getLogger(IamLogoutSuccessHandler.class);

  private IamClientRepository clientRepo;
  private SelfAssertionValidator validator;

  public IamLogoutSuccessHandler(IamClientRepository clientRepo,
      SelfAssertionValidator validator) {
    this.clientRepo = clientRepo;
    this.validator = validator;
  }

  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {

    String idTokenHint = request.getParameter("id_token_hint");
    String redirectUri = request.getParameter("post_logout_redirect_uri");
    String state = request.getParameter("state");

    String fallback = "/login?logout";

    if (idTokenHint == null || redirectUri == null) {
      LOG.debug("OIDC logout: missing id_token_hint or post_logout_redirect_uri");
      response.sendRedirect(fallback);
      return;
    }

    try {
      JWT idToken = JWTParser.parse(idTokenHint);

      if (!validator.isValid(idToken)) {
        LOG.debug("OIDC logout: id_token_hint validation failed");
        response.sendRedirect(fallback);
        return;
      }

      JWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();
      List<String> audience = idTokenClaims.getAudience();

      Optional<ClientDetailsEntity> client = audience.stream()
        .map(clientRepo::findByClientId)
        .filter(Optional::isPresent)
        .map(Optional::get)
        .findFirst();

      if (client.isEmpty()) {
        LOG.debug("OIDC logout: no matching client found in audiences {}", audience);
        response.sendRedirect(fallback);
        return;
      }

      if (!client.get().getPostLogoutRedirectUris().contains(redirectUri)) {
        LOG.debug("OIDC logout redirect denied: invalid redirect URI {}", redirectUri);
        response.sendRedirect(fallback);
        return;
      }

      UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(redirectUri);

      if (state != null) {
        uriBuilder.queryParam("state", state);
      }

      response.sendRedirect(uriBuilder.toUriString());

    } catch (ParseException e) {
      LOG.debug("OIDC logout: invalid id_token_hint format", e);
      response.sendRedirect(fallback);
    }
  }
}
