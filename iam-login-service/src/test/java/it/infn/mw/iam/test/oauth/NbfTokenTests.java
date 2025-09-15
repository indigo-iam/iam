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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNull;

import java.time.Duration;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"iam.access_token.include_nbf=true"})
public class NbfTokenTests extends EndpointsTestUtils {

  private static final String CLIENT_CREDENTIALS_CLIENT_ID = "client-cred";
  private static final String CLIENT_CREDENTIALS_CLIENT_SECRET = "secret";

  @Autowired
  private IamProperties properties;

  @Test
  public void testNbfIncludedInAccessTokenClientCred() throws Exception {

    String accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);
    token.getJWTClaimsSet().getNotBeforeTime();

    assertThat(token.getJWTClaimsSet().getNotBeforeTime(), notNullValue());
    assertThat(token.getJWTClaimsSet().getNotBeforeTime(),
        equalTo(Date.from(token.getJWTClaimsSet()
          .getIssueTime()
          .toInstant()
          .minus(Duration.ofSeconds(properties.getAccessToken().getNbfOffsetSeconds())))));

  }

  @Test
  public void testNbfNotIncludedInAccessTokenClientCred() throws Exception {
    properties.getAccessToken().setIncludeNbf(false);
    String accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);
    token.getJWTClaimsSet().getNotBeforeTime();

    assertNull(token.getJWTClaimsSet().getNotBeforeTime());
    properties.getAccessToken().setIncludeNbf(true);
  }

  @Test
  public void testConfiguredNbfIncludedInAccessTokenClientCred() throws Exception {

    properties.getAccessToken().setNbfOffsetSeconds(100);
    String accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);
    token.getJWTClaimsSet().getNotBeforeTime();

    assertThat(token.getJWTClaimsSet().getNotBeforeTime(),
        equalTo(Date.from(token.getJWTClaimsSet()
          .getIssueTime()
          .toInstant()
          .minus(Duration.ofSeconds(properties.getAccessToken().getNbfOffsetSeconds())))));
  }

  @Test
  public void testNegativeValueNbfIncludedInAccessTokenClientCred() throws Exception {

    properties.getAccessToken().setNbfOffsetSeconds(-60);
    String accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .getAccessTokenValue();

    JWT token = JWTParser.parse(accessToken);
    token.getJWTClaimsSet().getNotBeforeTime();

    assertThat(token.getJWTClaimsSet().getNotBeforeTime(),
        equalTo(Date.from(token.getJWTClaimsSet().getIssueTime().toInstant())));
  }

}
