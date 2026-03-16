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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientRelyingPartyEntity;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.openid_federation.FederationClientConfigurationService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@SpringBootTest(
    classes = {IamLoginService.class, FederationClientConfigurationServiceTests.TestConfig.class},
    webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@Transactional
class FederationClientConfigurationServiceTests {

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    RestTemplateFactory mockRestTemplateFactory() {
      return new MockRestTemplateFactory();
    }
  }

  @Autowired
  MockMvc mvc;

  @Autowired
  ClientConfigurationService clientConfigurationService;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  RestTemplateFactory rtf;

  @MockBean
  ServerConfigurationService serverConfigurationService;

  @MockBean
  TrustChainService trustChainService;

  TrustChain fakeChain;

  MockRestTemplateFactory mockRtf;

  @BeforeEach
  void setup() {

    ServerConfiguration sc = new ServerConfiguration();
    sc.setIssuer("https://op.example.com");
    sc.setAuthorizationEndpointUri("https://op.example.com/authorize");
    sc.setTokenEndpointUri("https://op.example.com/token");
    sc.setJwksUri("https://op.example.com/jwks");

    when(serverConfigurationService.getServerConfiguration("https://op.example.com"))
      .thenReturn(sc);

    mockRtf = (MockRestTemplateFactory) rtf;
  }

  @Test
  void federationServiceIsLoaded() {
    assertThat(clientConfigurationService).isInstanceOf(FederationClientConfigurationService.class);
  }

  @Test
  void testOpRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createOpToTaChain(null,
        URI.create("https://op.example.com/jwk"), "https://trust-anchor.sandbox.eosc.grnet.gr");
    when(trustChainService.validateFromEntityId(any())).thenReturn(fakeChain);

    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    mockRtf.getMockServer()
      .expect(requestTo("https://op.example.com/fedreg"))
      .andExpect(method(HttpMethod.POST))
      .andRespond(withSuccess(rpJwt, MediaType.APPLICATION_JSON));

    mvc.perform(get("/openid_connect_login?iss=" + "https://op.example.com"))
      .andExpect(status().isFound());

    Optional<ClientDetailsEntity> client = clientRepo.findByEntityId(rpEC.getEntityID().getValue());
    assertTrue(client.isPresent());
    assertEquals("OIDFed OP client", client.get().getClientName());
  }

  @Test
  void testOpRegistrationFailureWhenCommonAuthorityHintsNotFound() throws Exception {
    fakeChain = TrustChainTestFactory.createOpToTaChain(null,
        URI.create("https://op.example.com/jwk"), "https://ta.example.com");
    when(trustChainService.validateFromEntityId(any())).thenReturn(fakeChain);

    MvcResult result = mvc.perform(get("/openid_connect_login?iss=https://op.example.com"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl("/login?error=true"))
      .andReturn();

    AuthenticationServiceException ex = (AuthenticationServiceException) result.getRequest()
      .getSession()
      .getAttribute(EXT_AUTH_ERROR_KEY);

    assertTrue(ex.getMessage().contains("Unable to register federated OP"));
  }

  @Test
  void testRegisteredOpRedirectsToAuthorize() throws Exception {
    Optional<ClientDetailsEntity> registeredOp = clientRepo.findByClientId("client");
    ClientRelyingPartyEntity client = new ClientRelyingPartyEntity();
    client.setEntityId("https://op.example.com");
    LocalDate today = LocalDate.now();
    LocalDate tomorrow = today.plusDays(1);
    Date tomorrowDate = Date.from(tomorrow.atStartOfDay(ZoneId.systemDefault()).toInstant());
    client.setExpiration(tomorrowDate);
    client.setClient(registeredOp.get());
    registeredOp.get().setClientRelyingParty(client);
    clientRepo.save(registeredOp.get());

    mvc.perform(get("/openid_connect_login?iss=" + "https://op.example.com"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrlPattern("https://op.example.com/authorize*"));
  }
}
