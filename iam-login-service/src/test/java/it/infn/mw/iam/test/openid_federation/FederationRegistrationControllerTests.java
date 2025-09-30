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
package it.infn.mw.iam.test.openid_federation;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDate;
import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientFederationMetadataEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.config.TaskConfig;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class FederationRegistrationControllerTests {

  private static final String IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT =
      "/iam/api/oid-fed/client-registration";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private TaskConfig taskConfig;

  @MockBean
  TrustChainService trustChainService;

  TrustChain fakeChain;

  @Test
  public void testSuccessfullExplicitClientRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain("http://localhost:8080");
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(content().contentType("application/explicit-registration-response+jwt"));
  }

  @Test
  public void testInvalidAudienceDuringRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain("http://wrong-audience");
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_request")))
      .andExpect(jsonPath("$.error_description", equalTo("Invalid audience")));
  }

  @Test
  public void testClientDisabledWhenExpired() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(null);
    Optional<ClientDetailsEntity> client = clientRepo.findByClientId("client-cred");
    assertTrue(client.isPresent());

    LocalDate today = LocalDate.now();
    ClientFederationMetadataEntity entity = new ClientFederationMetadataEntity(client.get(),
        today.minusDays(1), fakeChain.getLeafSelfStatement().getEntityID().getValue());
    client.get().setFederationMetadata(entity);

    taskConfig.disableExpiredClients();
    assertFalse(client.get().isActive());

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", "client-cred")
        .param("client_secret", "secret"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Client is suspended: client-cred")));

    client.get().setActive(true);
  }

  @Test
  public void testClientDeletedAndRecreatedWhenAlreadyExists() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain("http://localhost:8080");
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(content().contentType("application/explicit-registration-response+jwt"));

    Optional<ClientDetailsEntity> client = clientRepo.findByEntityId(rpEC.getEntityID().getValue());
    assertTrue(client.isPresent());

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(content().contentType("application/explicit-registration-response+jwt"));

    Optional<ClientDetailsEntity> newClient =
        clientRepo.findByEntityId(rpEC.getEntityID().getValue());
    assertTrue(newClient.isPresent());
    assertNotEquals(client.get().getClientId(), newClient.get().getClientId());
  }
}
