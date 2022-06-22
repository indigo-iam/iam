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


import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.ImmutableList;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_authn_info=true"})
public class AccessTokenEnhancerTests extends EndpointsTestUtils {

  private static final String CLIENT_CREDENTIALS_CLIENT_ID = "token-lookup-client";
  private static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";

  private static final String CLIENT_ID = "password-grant";
  private static final String CLIENT_SECRET = "secret";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String EMAIL = "test@iam.test";
  private static final String ORGANISATION = "indigo-dc";
  private static final String NAME = "Test User";
  private static final List<String> GROUPS = ImmutableList.of("Production", "Analysis");

  private String getAccessTokenForUser(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("password").clientId(CLIENT_ID)
        .clientSecret(CLIENT_SECRET).username(USERNAME).password(PASSWORD).scope(scopes)
        .getAccessTokenValue();
  }

  private String getAccessTokenForClient(String scopes) throws Exception {

    return new AccessTokenGetter().grantType("client_credentials")
        .clientId(CLIENT_CREDENTIALS_CLIENT_ID).clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
        .scope(scopes).getAccessTokenValue();
  }

  @Test
  public void testEnhancedEmailOk() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForUser("openid email"));
    String email = (String) token.getJWTClaimsSet().getClaim("email");
    assertThat(email, is(notNullValue()));
    assertThat(email, is(EMAIL));
  }

  @Test
  public void testClientCredentialsAccessTokenIsNotEnhanced() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForClient("openid profile email"));
    assertThat(token.getJWTClaimsSet().getClaim("email"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("name"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("preferred_username"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("organisation_name"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), is(nullValue()));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testEnhancedProfileClaimsOk() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForUser("openid profile"));
    
    String name = (String) token.getJWTClaimsSet().getClaim("name");
    assertThat(name, is(notNullValue()));
    assertThat(name, is(NAME));
    
    String preferredUsername = (String) token.getJWTClaimsSet().getClaim("preferred_username");
    assertThat(preferredUsername, is(notNullValue()));
    assertThat(preferredUsername, is(USERNAME));
    
    String organisationName = (String) token.getJWTClaimsSet().getClaim("organisation_name");
    assertThat(organisationName, is(notNullValue()));
    assertThat(organisationName, is(ORGANISATION));
    
    List<String> groups = (List<String>) token.getJWTClaimsSet().getClaim("groups");
    assertThat(groups, is(notNullValue()));
    assertThat(groups, hasSize(2));
    
    assertThat(groups, hasItem(GROUPS.get(0)));
    assertThat(groups, hasItem(GROUPS.get(1)));
  }

  @Test
  public void testEnhancedEmailNotEnhanced() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForUser("openid"));
    assertThat(token.getJWTClaimsSet().getClaim("email"), is(nullValue()));
  }

  @Test
  public void testEnhancedProfileClaimsNotEnhanced() throws Exception {

    JWT token = JWTParser.parse(getAccessTokenForUser("openid"));
    assertThat(token.getJWTClaimsSet().getClaim("name"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("preferred_username"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("organisation_name"), is(nullValue()));
    assertThat(token.getJWTClaimsSet().getClaim("groups"), is(nullValue()));
  }
  
  public void accessTokenDoesNotIncludeNbfByDefault() throws Exception {
    JWT token = JWTParser.parse(getAccessTokenForUser("openid"));
    assertThat(token.getJWTClaimsSet().getNotBeforeTime(), nullValue());
  }

}
