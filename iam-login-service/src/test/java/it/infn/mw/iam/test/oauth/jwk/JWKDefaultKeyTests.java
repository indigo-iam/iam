/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.test.oauth.jwk;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.CombinableMatcher.either;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.text.ParseException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebAppConfiguration
@Transactional
@TestPropertySource(properties = {"iam.jwk.default-key-id=iam1",
    "iam.jwk.keystore-location=classpath:/jwk/iam-keys.jwks"})
public class JWKDefaultKeyTests extends EndpointsTestUtils implements JWKTestSupport {

  @Before
  public void setup() {
    buildMockMvc();
  }

  private String getAccessTokenForUser() throws Exception {

    return new AccessTokenGetter().grantType("password")
      .clientId(CLIENT_ID)
      .clientSecret(CLIENT_SECRET)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .getAccessTokenValue();
  }

  @Test
  public void testAccessTokenKey() throws ParseException, Exception {

    SignedJWT token = (SignedJWT) JWTParser.parse(getAccessTokenForUser());
    assertThat(token.getHeader().getKeyID(), is("iam1"));

  }

  @Test
  public void testJwkEndpointResult() throws Exception {

    mvc.perform(get(JWK_ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
      .andExpect(jsonPath("$.keys", hasSize(2)))
      .andExpect(jsonPath("$.keys[0].kid", either(is("iam1")).or(is("iam2"))))
      .andExpect(jsonPath("$.keys[1].kid", either(is("iam1")).or(is("iam2"))));

  }


}
