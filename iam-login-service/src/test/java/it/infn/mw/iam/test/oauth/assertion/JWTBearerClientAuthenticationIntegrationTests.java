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
package it.infn.mw.iam.test.oauth.assertion;

import static java.util.Collections.singletonList;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class JWTBearerClientAuthenticationIntegrationTests
    extends JWTBearerClientAuthenticationIntegrationTestSupport {

  @Test
  public void testSymmetricJwtAuth() throws Exception {

    JWT jwt = createSymmetricClientAuthToken(CLIENT_ID_SECRET_JWT, Instant.now().plusSeconds(600));
    String serializedToken = jwt.serialize();

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_SECRET_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists());
  }

  @Test
  public void testAsymmetricJwtAuth() throws Exception {

    JWTSigningAndValidationService signer = loadSignerService();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(CLIENT_ID_PRIVATE_KEY_JWT)
      .issuer(CLIENT_ID_PRIVATE_KEY_JWT)
      .expirationTime(Date.from(Instant.now().plusSeconds(600)))
      .audience(singletonList(TOKEN_ENDPOINT_AUDIENCE))
      .jwtID(UUID.randomUUID().toString())
      .build();

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa1").build();

    SignedJWT jwt = new SignedJWT(header, claimsSet);
    signer.signJwt(jwt);
    String serializedToken = jwt.serialize();

    mvc
      .perform(post(TOKEN_ENDPOINT).param("client_id", CLIENT_ID_PRIVATE_KEY_JWT)
        .param("client_assertion_type", JWT_BEARER_ASSERTION_TYPE)
        .param("client_assertion", serializedToken)
        .param("grant_type", "client_credentials"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.access_token").exists());


  }

}
