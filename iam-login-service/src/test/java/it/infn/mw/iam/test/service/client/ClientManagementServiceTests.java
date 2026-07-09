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
package it.infn.mw.iam.test.service.client;

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CODE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.DEVICE_CODE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.IMPLICIT;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.REDELEGATE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.REFRESH_TOKEN;
import static it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod.client_secret_basic;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.util.Set;

import javax.validation.ConstraintViolationException;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.clock.MutableClock;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.NONE)
@Transactional
class ClientManagementServiceTests {

  @Autowired
  ClientManagementService managementService;

  @Autowired
  ClientService clientService;

  @Autowired
  ClientRegistrationService registrationService;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  MutableClock clock;

  Authentication userAuth;

  @Test
  void testPagedClientLookup() {

    Sort sort = Sort.by(Direction.ASC, "clientId");
    Pageable pageable = PagingUtils.buildPageRequest(10, 1, 100, sort);

    ListResponseDTO<RegisteredClientDTO> clients = managementService.retrieveAllClients(pageable);

    assertEquals(clientRepo.count(), clients.getTotalResults());
    assertEquals(10, clients.getItemsPerPage());
    assertEquals(1, clients.getStartIndex());
    assertEquals("admin-client-ro", clients.getResources().get(0).getClientId());

  }

  @Test
  void testDynamicClientLookup() {
    Sort sort = Sort.by(Direction.ASC, "clientId");
    Pageable pageable = PagingUtils.buildPageRequest(10, 1, 100, sort);

    ListResponseDTO<RegisteredClientDTO> clients =
        managementService.retrieveAllDynamicallyRegisteredClients(pageable);

    assertEquals(0L, clients.getTotalResults());
    assertEquals(0, clients.getItemsPerPage());
    assertEquals(1, clients.getStartIndex());

  }


  @Test
  void testClientDelete() {
    managementService.deleteClientByClientId("client");
    assertTrue(managementService.retrieveClientByClientId("client").isEmpty());
  }

  @Test
  void testClientRetrieve() {
    RegisteredClientDTO client = managementService.retrieveClientByClientId("client").orElseThrow();

    assertEquals("client", client.getClientId());
    assertEquals("secret", client.getClientSecret());
    assertTrue(
        client.getGrantTypes().containsAll(Set.of(CODE, REDELEGATE, IMPLICIT, REFRESH_TOKEN)));
    assertTrue(client.getScope()
      .containsAll(Set.of("openid", "offline_access", "profile", "email", "address", "phone",
          "read-tasks", "write-tasks", "read:/", "write:/")));
    assertEquals(client_secret_basic, client.getTokenEndpointAuthMethod());
  }

  @Test
  void testClientCreationSuccess() throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertEquals(client.getClientId(), savedClient.getClientId());
    assertNotNull(savedClient.getClientSecret());
  }

  @Test
  void testClientWithJwkValue() throws ParseException {

    final String NOT_A_JSON_STRING = "This is not a JSON string";
    final String VALID_JSON_VALUE =
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"rsa1\",\"alg\":\"RS256\",\"n\":\"zTF0oJjUDvoEBK82Hb706nRRJakcqoz_w4zdCIiv0BR1oumtQE8teUoLaYK_aqf9y30wajXoIq40tJYMXKW7QIFm2GYZ3qknUKGIy8xdNFEnLA2DG-BwSisNpJTvmiG1nbjvDRk7_M7WRmNwQkpdAXri89e9lL7ctG9aOnUs6wpinCqXYX9xvJl9k1HOdj_qZKrpz6xe75bPabe2yrF2TRfSobI5SSqTBBFLg06kuaaqqzVWbzCv8hgV7NMrt1CYDlXrfS2v1Ejf3WIEtgMRSxDBav90kpkBybwFhvyy7E87hjMdyoNk-yyYuZA_uSJCPKWJwjPB_EXaw280rObZ5Q\"}]}";
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setJwk(NOT_A_JSON_STRING);

    ParseException e = assertThrows(ParseException.class, () -> {
      managementService.saveNewClient(client);
    });

    assertTrue(e.getMessage().contains("Invalid JSON object"));

    client.setJwk(VALID_JSON_VALUE);
    try {
      RegisteredClientDTO savedClient = managementService.saveNewClient(client);
      assertEquals(client.getClientId(), savedClient.getClientId());
      assertEquals(VALID_JSON_VALUE, savedClient.getJwk());
    } finally {
      managementService.deleteClientByClientId(client.getClientId());
    }
  }

  @Test
  void testClientWithJwksUri() throws ParseException {

    final String NOT_A_VALID_URI = "This is not a valid URI";
    final String VALID_URI = "https://host.domain.com/this/is/my/public-key";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setJwksUri(NOT_A_VALID_URI);

    ConstraintViolationException e = assertThrows(ConstraintViolationException.class, () -> {
      managementService.saveNewClient(client);
    });

    String expectedMessage = "saveNewClient.client.jwksUri:";
    String actualMessage = e.getMessage();

    assertTrue(actualMessage.contains(expectedMessage));

    client.setJwksUri(VALID_URI);
    try {
      RegisteredClientDTO savedClient = managementService.saveNewClient(client);
      assertEquals(client.getClientId(), savedClient.getClientId());
      assertEquals(VALID_URI, savedClient.getJwksUri());
    } finally {
      managementService.deleteClientByClientId(client.getClientId());
    }
  }

  @Test
  void testBasicClientValidation() {

    RegisteredClientDTO client = new RegisteredClientDTO();
    ConstraintViolationException exception =
        assertThrows(ConstraintViolationException.class, () -> {
          managementService.saveNewClient(client);
        });

    assertTrue(exception.getMessage().contains("should not be blank"));

    client.setClientName("client");
    client.setClientId("client");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));

    exception = assertThrows(ConstraintViolationException.class, () -> {
      managementService.saveNewClient(client);
    });

    assertTrue(exception.getMessage().contains("Client id not available"));
  }

  @Test
  void testDynamicallyRegisteredClientCanBeUpdated() throws ParseException {

    userAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(userAuth.getName()).thenReturn("test");
    when(userAuth.getAuthorities()).thenAnswer(x -> Set.of(Authorities.ROLE_USER));

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    RegisteredClientDTO response = registrationService.registerClient(request, userAuth);


    String clientId = response.getClientId();
    ClientDetailsEntity entity = clientService.findClientByClientId(clientId).orElseThrow();
    assertTrue(entity.isDynamicallyRegistered());

    RegisteredClientDTO client = managementService.retrieveClientByClientId(clientId).orElseThrow();

    client.getGrantTypes().add(DEVICE_CODE);
    RegisteredClientDTO updatedClient = managementService.updateClient(clientId, client);

    assertTrue(updatedClient.isDynamicallyRegistered());
    assertNotNull(updatedClient.getRegistrationClientUri());
    assertTrue(updatedClient.getGrantTypes().containsAll(Set.of(CLIENT_CREDENTIALS, DEVICE_CODE)));
  }

  @Test
  void testSwitchingFromBasicAuthnToPublicClientUnsetSecret() throws ParseException {

    userAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(userAuth.getName()).thenReturn("test");
    when(userAuth.getAuthorities()).thenAnswer(x -> Set.of(Authorities.ROLE_USER));

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    RegisteredClientDTO response = registrationService.registerClient(request, userAuth);

    String clientId = response.getClientId();
    RegisteredClientDTO client = managementService.retrieveClientByClientId(clientId).orElseThrow();
    assertNotNull(client.getClientSecret());

    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    RegisteredClientDTO updatedClient = managementService.updateClient(clientId, client);

    assertEquals(TokenEndpointAuthenticationMethod.none, updatedClient.getTokenEndpointAuthMethod());
    assertNull(updatedClient.getClientSecret());
  }

  @Test
  void testSwitchingFromPublicClientToBasicAuthnRotatesSecret() throws ParseException {

    userAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(userAuth.getName()).thenReturn("test");
    when(userAuth.getAuthorities()).thenAnswer(x -> Set.of(Authorities.ROLE_USER));

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    request.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    RegisteredClientDTO response = registrationService.registerClient(request, userAuth);

    String clientId = response.getClientId();
    RegisteredClientDTO client = managementService.retrieveClientByClientId(clientId).orElseThrow();
    assertNull(client.getClientSecret());
    assertEquals(TokenEndpointAuthenticationMethod.none, client.getTokenEndpointAuthMethod());

    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    RegisteredClientDTO updatedClient = managementService.updateClient(clientId, client);

    assertEquals(TokenEndpointAuthenticationMethod.client_secret_basic, updatedClient.getTokenEndpointAuthMethod());
    assertNotNull(updatedClient.getClientSecret());
  }

  @Test
  void testSecretRotation() throws ParseException {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertEquals(client.getClientId(), savedClient.getClientId());
    assertNotNull(savedClient.getClientSecret());


    managementService.generateNewClientSecret(client.getClientId());
    RegisteredClientDTO updatedClient =
        managementService.retrieveClientByClientId(client.getClientId()).orElseThrow();

    assertNotEquals(savedClient.getClientSecret(), updatedClient.getClientSecret());
  }

  @Test
  void testRatRotation() throws ParseException {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-rat-rotation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertNotNull(savedClient.getClientId());
    assertNull(savedClient.getRegistrationAccessToken());

    RegisteredClientDTO updatedClient =
        managementService.rotateRegistrationAccessToken(savedClient.getClientId());

    assertNotNull(updatedClient.getRegistrationAccessToken());

    RegisteredClientDTO retrievedClient =
        managementService.retrieveClientByClientId(savedClient.getClientId()).orElseThrow();
    assertNull(retrievedClient.getRegistrationAccessToken());
  }

  @Test
  void testClientOwnerAssignRemove() throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertEquals(client.getClientId(), savedClient.getClientId());
    assertNotNull(savedClient.getClientSecret());

    ListResponseDTO<ScimUser> owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertEquals(0L, owners.getTotalResults());

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    IamAccount otherAccount = accountRepo.findByUsername("test_100").orElseThrow();

    managementService.assignClientOwner(savedClient.getClientId(), testAccount.getUuid());
    managementService.assignClientOwner(savedClient.getClientId(), otherAccount.getUuid());
    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertEquals(2L, owners.getTotalResults());
    assertEquals(testAccount.getUuid(), owners.getResources().get(0).getId());
    assertEquals(otherAccount.getUuid(), owners.getResources().get(1).getId());

    managementService.removeClientOwner(savedClient.getClientId(), testAccount.getUuid());
    // Calling removal multiple times for the same account shouldn't harm
    managementService.removeClientOwner(savedClient.getClientId(), testAccount.getUuid());

    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertEquals(1L, owners.getTotalResults());
    assertEquals(otherAccount.getUuid(), owners.getResources().get(0).getId());
    managementService.removeClientOwner(savedClient.getClientId(), otherAccount.getUuid());

    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertEquals(0L, owners.getTotalResults());
  }

  @Test
  void testClientStatusChange() {
    managementService.updateClientStatus("client", false, "userUUID");
    RegisteredClientDTO client = managementService.retrieveClientByClientId("client").get();

    assertFalse(client.isActive());
    assertTrue(client.getStatusChangedOn().equals(clock.now()));
    assertEquals("userUUID", client.getStatusChangedBy());
  }

  @Test
  void testClientStatusChangeWithContacts() {
    managementService.updateClientStatus("device-code-client", false, "userUUID");
    RegisteredClientDTO client =
        managementService.retrieveClientByClientId("device-code-client").get();

    assertFalse(client.isActive());
    assertEquals(clock.now(), client.getStatusChangedOn());
    assertEquals("userUUID", client.getStatusChangedBy());
  }

  @Test
  void testClientStatusChangeWithoutOwners() {
    managementService.updateClientStatus("client-cred", false, "userUUID");
    RegisteredClientDTO client = managementService.retrieveClientByClientId("client-cred").get();

    assertFalse(client.isActive());
    assertEquals(clock.now(), client.getStatusChangedOn());
    assertEquals("userUUID", client.getStatusChangedBy());
  }
}
