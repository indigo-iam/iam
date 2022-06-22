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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
public class AccessTokenIncludeScopeTests extends EndpointsTestUtils {
  private static final String CLIENT_CREDENTIALS_CLIENT_ID = "client-cred";
  private static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";
  
  private static final String SCOPES = "read-tasks";
  private static final String SCOPE_CLAIM = "scope";
  
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";

  @Test
  public void testScopeIncludedInAccessTokenClientCred() throws Exception {

    String accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .scope(SCOPES)
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);
    String scopeClaim = (String) token.getJWTClaimsSet().getClaim(SCOPE_CLAIM); 
    assertThat(scopeClaim, notNullValue());
    assertThat(scopeClaim, is(SCOPES));
  }
  
  @Test
  public void testScopeIncludedInPasswordFlow()  throws Exception {
    String accessToken = new AccessTokenGetter().grantType("password")
        .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
        .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
        .username(USERNAME)
        .password(PASSWORD)
        .scope(SCOPES)
        .getAccessTokenValue();
    
    JWT token = JWTParser.parse(accessToken);
    String scopeClaim = (String) token.getJWTClaimsSet().getClaim(SCOPE_CLAIM); 
    assertThat(scopeClaim, notNullValue());
    assertThat(scopeClaim, is(SCOPES));
  }
}
