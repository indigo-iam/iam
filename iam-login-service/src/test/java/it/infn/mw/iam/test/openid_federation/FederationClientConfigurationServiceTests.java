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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.api.openid_federation.FederationClientConfigurationService;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
public class FederationClientConfigurationServiceTests {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ClientConfigurationService clientConfigurationService;

  @Autowired
  private IamClientRepository clientRepo;

  @MockBean
  private RestTemplate restTemplate;

  @MockBean
  private ServerConfigurationService serverConfigurationService;

  @MockBean
  TrustChainService trustChainService;

  TrustChain fakeChain;

  @BeforeEach
  void setup() {

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer("https://op.example.com");
    sc.setAuthorizationEndpointUri("https://op.example.com/authorize");
    sc.setTokenEndpointUri("https://op.example.com/token");
    sc.setJwksUri("https://op.example.com/jwks");

    when(serverConfigurationService.getServerConfiguration("https://op.example.com"))
      .thenReturn(sc);
  }

  @Test
  void federationServiceIsLoaded() {
    assertThat(clientConfigurationService).isInstanceOf(FederationClientConfigurationService.class);
  }

  @Test
  void testOpRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createOpToTaChain(null, null,
        URI.create("https://op.example.com/callback"), null,
        URI.create("https://op.example.com/jwk"));
    when(trustChainService.validateFromEntityId(any())).thenReturn(fakeChain);

    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(restTemplate.postForObject(any(URI.class), any(HttpEntity.class), eq(String.class)))
      .thenReturn(rpJwt);

    mvc.perform(get("/openid_connect_login?iss=" + "https://op.example.com"))
      .andExpect(status().isFound());

    Optional<ClientDetailsEntity> client = clientRepo.findByEntityId(rpEC.getEntityID().getValue());
    assertTrue(client.isPresent());
    assertEquals("OIDFed OP client", client.get().getClientName());

    clientRepo.delete(client.get());
  }
}
