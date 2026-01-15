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

import static it.infn.mw.iam.api.account.search.AccountSearchController.ACCOUNT_SEARCH_ENDPOINT;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.ResultActions;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class TestExpiredToken extends TestTokensUtils {

  @Autowired
  IamClientRepository clientRepository;

  @Autowired
  protected AuthenticationHolderRepository authenticationHolderRepository;

  @Autowired
  protected JWTProfileResolver profileResolver;

  @Autowired
  protected JWTSigningAndValidationService jwtSigningService;

  private ResultActions getApi(String path, String accessToken) throws Exception {

    String authorizationHeader = String.format("Bearer %s", accessToken);
    return mvc.perform(get(path).header("Authorization", authorizationHeader));
  }

  private OAuth2Authentication oauth2Authentication(ClientDetailsEntity client,
      Set<GrantedAuthority> authorities, String[] scopes) {

    Authentication userAuth =
        new UsernamePasswordAuthenticationToken(client.getClientId(), client.getClientSecret());
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("grant_type", "client_credentials");

    OAuth2Request req = new OAuth2Request(requestParameters, client.getClientId(), authorities,
        true, Set.of(scopes), Set.of(), null, Set.of(ResponseType.TOKEN.toString()), Map.of());
    return new OAuth2Authentication(req, userAuth);
  }

  private OAuth2AccessTokenEntity buildExpiredAccessToken(ClientDetailsEntity client,
      Set<GrantedAuthority> authorities, String[] scopes, Date expiration) {

    OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();
    token.setClient(client);
    token.setScope(Set.of(scopes));
    token.setExpiration(expiration);
    OAuth2Authentication authn = oauth2Authentication(client, authorities, scopes);

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(authn);
    authHolder = authenticationHolderRepository.save(authHolder);

    token.setAuthenticationHolder(authHolder);

    JWTProfile profile = profileResolver.resolveProfile(Set.of(scopes));

    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(token, authn, Optional.empty(), expiration.toInstant());

    token.setJwt(signClaims(atClaims));
    token.hashMe();
    accessTokenRepository.save(token);

    return token;
  }

  private SignedJWT signClaims(JWTClaimsSet claims) {
    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();

    JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null,
        null, jwtSigningService.getDefaultSignerKeyId(), null, null);
    SignedJWT signedJWT = new SignedJWT(header, claims);

    jwtSigningService.signJwt(signedJWT);
    return signedJWT;
  }

  private Date getExpiredDate() {

    Calendar cal = Calendar.getInstance();
    cal.setTime(new Date());
    cal.add(Calendar.DATE, -10);
    return cal.getTime();
  }

  @Test
  public void testAccountSearchEndpointWithExpiredToken() throws Exception {

    ClientDetailsEntity client = clientRepository.findByClientId("client-cred").orElseThrow();

    OAuth2AccessTokenEntity accessToken =
        buildExpiredAccessToken(client, Set.of(new SimpleGrantedAuthority("ROLE_CLIENT")),
            new String[] {"iam:admin.read", "iam:admin.write"}, getExpiredDate());

    assertTrue(accessToken.isExpired());

    getApi(ACCOUNT_SEARCH_ENDPOINT, accessToken.getValue()).andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_token")))
      .andExpect(jsonPath("$.error_description", equalTo("The access token is expired")));

  }
}
