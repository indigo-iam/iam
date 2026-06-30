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
package it.infn.mw.iam.core.userinfo;

import java.util.Map;
import java.util.Set;

import javax.security.auth.message.AuthException;
import javax.servlet.http.HttpServletRequest;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.ParsedAccessToken;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@RestController
public class IamUserInfoEndpoint {

  public static final String URL = "/userinfo";

  private static final Logger LOG = LoggerFactory.getLogger(IamUserInfoEndpoint.class);

  private final JWTProfileResolver profileResolver;
  private final OAuth2AuthenticationScopeResolver scopeResolver;
  private final IamAccountRepository accountRepo;
  private final IamClientRepository clientRepo;
  private final TokenUtils tokenUtils;

  public IamUserInfoEndpoint(JWTProfileResolver profileResolver,
      OAuth2AuthenticationScopeResolver scopeResolver, IamAccountRepository accountRepo,
      IamClientRepository clientRepo, TokenUtils tokenUtils) {
    this.profileResolver = profileResolver;
    this.scopeResolver = scopeResolver;
    this.accountRepo = accountRepo;
    this.clientRepo = clientRepo;
    this.tokenUtils = tokenUtils;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(path = URL, produces = {MediaType.APPLICATION_JSON_VALUE})
  public UserInfoResponse getInfo(OAuth2Authentication auth) throws AuthException {

    String username = auth.getName();
    IamAccount account = accountRepo.findByUsername(username)
      .orElseThrow(() -> new AuthException("Account id not found"));
    String clientId = auth.getOAuth2Request().getClientId();
    ClientDetailsEntity client = clientRepo.findByClientId(clientId)
      .orElseThrow(() -> new AuthException("Client id not found"));
    LOG.debug("Userinfo endpoint: client [id={}] requested user [username={}] info", clientId,
        username);

    JWTProfile profile =
        profileResolver.resolveProfile(client.getScope(), auth.getOAuth2Request().getScope());
    Set<String> scopes = scopeResolver.resolveScope(auth);
    Map<String, Object> claims =
        profile.getUserinfoHelper().resolveScopeClaims(scopes, account, auth);

    addExternalAuthN(auth, claims);
    return new UserInfoResponse(claims);
  }

  private void addExternalAuthN(OAuth2Authentication auth, Map<String, Object> claims) {

    if (auth.getDetails() instanceof OAuth2AuthenticationDetails details
        && details.getTokenValue() != null) {
      ParsedAccessToken parsedToken = tokenUtils.parseAccessToken(details.getTokenValue());
      if (parsedToken.external() != null) {
        claims.put("external_authn", parsedToken.external());
      }
    }
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler({AuthException.class})
  public ErrorDTO accountNotFound(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
