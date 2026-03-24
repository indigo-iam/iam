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
package it.infn.mw.iam.test.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

class JwtIntrospectionNegativeTests extends OidcMockMvcTestSupport {

  private static final byte[] VALID_SECRET = "01234567890123456789012345678901".getBytes();

  private static final byte[] INVALID_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes();

  @Autowired
  ClientService clientService;

  @Autowired
  IamAccountService accountService;

  private String buildJwt(byte[] secret, String clientId, String subject, Instant expiration,
      boolean includeClientId) throws Exception {

    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer("http://localhost")
      .subject(subject)
      .issueTime(new Date())
      .expirationTime(Date.from(expiration));

    if (includeClientId) {
      claims.claim("client_id", clientId);
    }

    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());

    jwt.sign(new MACSigner(secret));
    return jwt.serialize();
  }

  @Test
  void invalidSignatureTokenIsInactive() throws Exception {

    String jwt = buildJwt(INVALID_SECRET, CLIENT_CREDENTIALS_CLIENT_ID, TEST_USERNAME,
        Instant.now().plusSeconds(300), true);

    JsonNode response = introspect(jwt);

    assertFalse(response.get("active").asBoolean());
  }

  @Test
  void tokenWithoutClientIdIsInactive() throws Exception {

    String jwt = buildJwt(VALID_SECRET, null, TEST_USERNAME, Instant.now().plusSeconds(300), false);

    JsonNode response = introspect(jwt);

    assertFalse(response.get("active").asBoolean());
  }

  @Test
  @Transactional
  void tokenWithDisabledClientIsInactive() throws Exception {

    ClientDetailsEntity client = clientService.findClientByClientId("client").orElseThrow();
    clientService.updateClientStatus(client, false, "test");

    String jwt =
        buildJwt(VALID_SECRET, "client", TEST_USERNAME, Instant.now().plusSeconds(300), true);

    JsonNode response = introspect(jwt);

    assertFalse(response.get("active").asBoolean());
  }

  @Test
  void expiredTokenIsInactive() throws Exception {

    String jwt = buildJwt(VALID_SECRET, CLIENT_CREDENTIALS_CLIENT_ID, TEST_USERNAME,
        Instant.now().minusSeconds(60), true);

    JsonNode response = introspect(jwt);

    assertFalse(response.get("active").asBoolean());
  }

  @Test
  @Transactional
  void tokenWithInactiveUserIsInactive() throws Exception {

    IamAccount account = accountService.findByUsername(TEST_USERNAME).orElseThrow();
    accountService.disableAccount(account);

    String jwt = buildJwt(VALID_SECRET, CLIENT_CREDENTIALS_CLIENT_ID, TEST_USERNAME,
        Instant.now().plusSeconds(300), true);

    JsonNode response = introspect(jwt);

    assertFalse(response.get("active").asBoolean());
  }
}
