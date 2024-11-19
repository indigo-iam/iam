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
package it.infn.mw.iam.test.api.tokens;

import static it.infn.mw.iam.api.tokens.TokensControllerSupport.APPLICATION_JSON_CONTENT_TYPE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.tokens.Constants;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.exception.IamAccountException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
public class TestTokensUtils {

  protected static final String REFRESH_TOKENS_BASE_PATH = Constants.REFRESH_TOKENS_ENDPOINT;
  protected static final String ACCESS_TOKENS_BASE_PATH = Constants.ACCESS_TOKENS_ENDPOINT;

  @Autowired
  protected IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  protected IamOAuthRefreshTokenRepository refreshTokenRepository;

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  protected IamAccountRepository accountRepository;

  @Autowired
  protected DefaultOAuth2ProviderTokenService tokenService;

  @Autowired
  protected IamAccountService accountService;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  protected MockMvc mvc;

  @Autowired
  protected PasswordEncoder encoder;

  private OAuth2Authentication oauth2Authentication(ClientDetailsEntity client, String username,
      String[] scopes) {

    Authentication userAuth = null;
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("grant_type", "authorization_code");

    if (username != null) {
      userAuth = new UsernamePasswordAuthenticationToken(username, "");
    }

    MockOAuth2Request req = new MockOAuth2Request(client.getClientId(), scopes);
    req.setRequestParameters(requestParameters);
    OAuth2Authentication auth = new OAuth2Authentication(req, userAuth);

    return auth;
  }

  public ClientDetailsEntity loadTestClient(String clientId) {
    return clientDetailsService.loadClientByClientId(clientId);
  }

  public IamAccount loadTestUser(String userId) {
    return accountRepository.findByUsername(userId)
        .orElseThrow(() -> new IamAccountException("User not found"));
  }

  public OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client, String username,
      String[] scopes) {
    OAuth2AccessTokenEntity token =
        tokenService.createAccessToken(oauth2Authentication(client, username, scopes));
    return token;
  }

  public OAuth2AccessTokenEntity buildExpiredAccessToken(ClientDetailsEntity client,
      String username, String[] scopes) {

    OAuth2AccessTokenEntity token =
        tokenService.createAccessToken(oauth2Authentication(client, username, scopes));
    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date());
    cal.add(Calendar.DATE, -10);
    token.setExpiration(cal.getTime());
    accessTokenRepository.save(token);
    return token;
  }

  public OAuth2AccessTokenEntity buildAccessTokenWithExpiredRefreshToken(ClientDetailsEntity client,
      String username, String[] scopes) {

    OAuth2AccessTokenEntity token =
        tokenService.createAccessToken(oauth2Authentication(client, username, scopes));
    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date());
    cal.add(Calendar.DATE, -10);
    OAuth2RefreshTokenEntity refreshToken = token.getRefreshToken();
    refreshToken.setExpiration(cal.getTime());
    refreshTokenRepository.save(refreshToken);
    return token;
  }

  public OAuth2AccessTokenEntity buildAccessToken(ClientDetailsEntity client, String[] scopes) {
    OAuth2AccessTokenEntity token =
        tokenService.createAccessToken(oauth2Authentication(client, null, scopes));
    return token;
  }

  public void clearAllTokens() {
    accessTokenRepository.deleteAll();
    refreshTokenRepository.deleteAll();
  }

  public Authentication anonymousAuthenticationToken() {
    return new AnonymousAuthenticationToken("key", "anonymous",
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
  }

  protected ListResponseDTO<AccessToken> getAccessTokenList() throws JsonParseException,
      JsonMappingException, UnsupportedEncodingException, IOException, Exception {

    return getAccessTokenList(new LinkedMultiValueMap<String, String>());
  }

  protected ListResponseDTO<AccessToken> getAccessTokenList(MultiValueMap<String, String> params)
      throws JsonParseException, JsonMappingException, UnsupportedEncodingException, IOException,
      Exception {

    /* @formatter:off */
    return mapper.readValue(
        mvc.perform(get(ACCESS_TOKENS_BASE_PATH)
            .contentType(APPLICATION_JSON_CONTENT_TYPE)
            .params(params))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<AccessToken>>() {});
    /* @formatter:on */
  }

  protected ListResponseDTO<RefreshToken> getRefreshTokenList() throws JsonParseException,
      JsonMappingException, UnsupportedEncodingException, IOException, Exception {

    return getRefreshTokenList(new LinkedMultiValueMap<String, String>());
  }

  protected ListResponseDTO<RefreshToken> getRefreshTokenList(MultiValueMap<String, String> params)
      throws JsonParseException, JsonMappingException, UnsupportedEncodingException, IOException,
      Exception {

    /* @formatter:off */
    return mapper.readValue(
        mvc.perform(get(REFRESH_TOKENS_BASE_PATH)
            .contentType(APPLICATION_JSON_CONTENT_TYPE)
            .params(params))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<RefreshToken>>() {});
    /* @formatter:on */
  }
}
