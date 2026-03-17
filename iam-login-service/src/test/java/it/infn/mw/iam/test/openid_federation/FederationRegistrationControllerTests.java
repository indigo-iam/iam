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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientRelyingPartyEntity;
import org.mitre.oauth2.model.ClientRelyingPartyEntity.ClientType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.client.ExpiredFederationClientScheduler;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"logging.level.it.infn.mw=DEBUG"})
class FederationRegistrationControllerTests {

  private static final String IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT =
      "/iam/api/oid-fed/client-registration";
  private static final String IAM_CLIENT_API_URL = "/iam/api/clients/";
  private static final URI REDIRECT_URI = URI.create("https://rp.example/callback");

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ExpiredFederationClientScheduler expiredClientScheduler;

  @Value("${iam.issuer}")
  private String issuer;

  @MockBean
  TrustChainService trustChainService;

  TrustChain fakeChain;

  @Test
  void testSuccessfullExplicitClientRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, REDIRECT_URI, null, null);
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

    // Check authorization code flow works
    ClientDetailsEntity client =
        clientRepo.findByEntityId(rpEC.getEntityID().getValue()).orElseThrow();

    var result = mvc
      .perform(get("/authorize").param("client_id", client.getClientId())
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI.toString()))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertEquals("http://localhost/login", result.getResponse().getHeader("Location"));

    MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

    var resultLogin = mvc
      .perform(post("/login").session(session)
        .param("username", "test")
        .param("password", "password")
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(header().exists("Location"))
      .andReturn();

    assertTrue(
        resultLogin.getResponse().getHeader("Location").startsWith("http://localhost/authorize"));

    mvc
      .perform(get("/authorize").session(session)
        .param("client_id", client.getClientId())
        .param("response_type", "code")
        .param("scope", "openid")
        .param("redirect_uri", REDIRECT_URI.toString()))
      .andExpect(status().isOk());

    var approveResult = mvc
      .perform(post("/authorize").session(session)
        .param("scope.openid", "true")
        .param("remember", "none")
        .param("user_oauth_approval", "true")
        .param("authorize", "Authorize"))
      .andExpect(status().isSeeOther())
      .andExpect(header().exists("Location"))
      .andReturn();

    String authorizeRedirect = approveResult.getResponse().getHeader("Location");
    assertTrue(authorizeRedirect.startsWith(REDIRECT_URI.toString()));

    String code = UriComponentsBuilder.fromUriString(authorizeRedirect)
      .build()
      .getQueryParams()
      .getFirst("code");

    // URL encode client_id and client_secret
    String encodedClientId = URLEncoder.encode(client.getClientId(), StandardCharsets.UTF_8);
    String encodedClientSecret =
        URLEncoder.encode(client.getClientSecret(), StandardCharsets.UTF_8);

    String credentials = Base64.getEncoder()
      .encodeToString(
          (encodedClientId + ":" + encodedClientSecret).getBytes(StandardCharsets.UTF_8));

    String tokenResponse = mvc
      .perform(post("/token").param("grant_type", "authorization_code")
        .param("code", code)
        .param("redirect_uri", REDIRECT_URI.toString())
        .header("Authorization", "Basic " + credentials))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode json = new ObjectMapper().readTree(tokenResponse);
    assertNotNull(json.get("access_token"));
  }

  @Test
  void testResponseTypesAreFiltered() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer,
        Set.of(ResponseType.CODE_IDTOKEN, ResponseType.CODE), REDIRECT_URI, null, null);
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
  void testUnsupportedResponseTypeError() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, Set.of(ResponseType.IDTOKEN),
        REDIRECT_URI, null, null);
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_client_metadata")))
      .andExpect(jsonPath("$.error_description", equalTo("Unsupported response type")));
  }

  @Test
  void testMissingRedirectUriCausesError() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, null, null, null);
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post(IAM_OIDFED_CLIENT_REGISTRATION_ENDPOINT)
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_redirect_uri")))
      .andExpect(jsonPath("$.error_description", equalTo("Missing redirect URIs")));
  }

  @Test
  @WithMockOAuthUser(user = "admin", scopes = "iam:admin.write")
  void testRelyingPartyClientUpdateThroughApiClientsEndpointReturnsException() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, REDIRECT_URI, null, null);
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

    RegisteredClientDTO clientDto = new RegisteredClientDTO();
    clientDto.setClientName("test-relying_party");
    clientDto.setScope(Set.of("openid"));

    mvc.perform(put(IAM_CLIENT_API_URL + client.get().getClientId()).contentType("application/json")
      .content(mapper.writeValueAsString(clientDto))).andExpect(status().isBadRequest());
  }

  @Test
  void testInvalidAudienceDuringRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain("http://wrong-audience", null, REDIRECT_URI,
        null, null);
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

  private int countInactiveClients() {
    int count = 0;
    for (ClientDetailsEntity c : clientRepo.findAll()) {
      if (!c.isActive()) {
        count++;
      }
    }
    return count;
  }

  @Test
  @Transactional
  void testClientDisabledWhenExpired() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(null, null, REDIRECT_URI, null, null);
    ClientDetailsEntity client = clientRepo.findByClientId("client-cred").orElseThrow();

    Date now = new Date();
    long oneDayInMillis = 24 * 60 * 60 * 1000;
    Date yesterday = new Date(now.getTime() - oneDayInMillis);
    ClientRelyingPartyEntity entity = new ClientRelyingPartyEntity(client, yesterday,
        fakeChain.getLeafSelfStatement().getEntityID().getValue(), ClientType.INTERNAL);
    client.setClientRelyingParty(entity);
    clientRepo.save(client);

    assertEquals(0, countInactiveClients());

    expiredClientScheduler.disableExpiredClients();
    client = clientRepo.findByClientId("client-cred").orElseThrow();
    Date lastUpdate = client.getStatusChangedOn();

    assertFalse(client.isActive());
    assertEquals(1, countInactiveClients());

    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", "client-cred")
        .param("client_secret", "secret"))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Client is suspended: client-cred")));

    expiredClientScheduler.disableExpiredClients();
    client = clientRepo.findByClientId("client-cred").orElseThrow();

    // check that the client has been disabled only once
    assertEquals(0, lastUpdate.compareTo(client.getStatusChangedOn()));
  }

  @Test
  void testClientDeletedAndRecreatedWhenAlreadyExists() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain(issuer, null, REDIRECT_URI, null, null);
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
