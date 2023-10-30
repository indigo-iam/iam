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

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CODE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.IMPLICIT;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.REDELEGATE;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.REFRESH_TOKEN;
import static it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod.client_secret_basic;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.text.ParseException;

import javax.validation.ConstraintViolationException;

import org.junit.jupiter.api.Assertions;
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
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.testcontainers.shaded.com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;


@IamNoMvcTest
@SpringBootTest(classes = {IamLoginService.class, ClientTestConfig.class},
    webEnvironment = WebEnvironment.NONE)
public class ClientManagementServiceTests {

  @Autowired
  private ClientManagementService managementService;

  @Autowired
  private ClientService clientService;

  @Autowired
  private ClientRegistrationService registrationService;

  @Autowired
  private IamAccountRepository accountRepo;

  private Authentication userAuth;

  private OAuth2Authentication ratAuth;

  private OAuth2Request oauthRequest;

  private OAuth2AuthenticationDetails oauthDetails;

  @Test
  public void testPagedClientLookup() {

    Sort sort = Sort.by(Direction.ASC, "clientId");
    Pageable pageable = PagingUtils.buildPageRequest(10, 1, 100, sort);
    
    ListResponseDTO<RegisteredClientDTO> clients = managementService.retrieveAllClients(pageable);

    assertThat(clients.getTotalResults(), is(18L));
    assertThat(clients.getItemsPerPage(), is(10));
    assertThat(clients.getStartIndex(), is(1));
    assertThat(clients.getResources().get(0).getClientId(), is("admin-client-ro"));

  }

  @Test
  public void testDynamicClientLookup() {
    Sort sort = Sort.by(Direction.ASC, "clientId");
    Pageable pageable = PagingUtils.buildPageRequest(10, 1, 100, sort);

    ListResponseDTO<RegisteredClientDTO> clients =
        managementService.retrieveAllDynamicallyRegisteredClients(pageable);

    assertThat(clients.getTotalResults(), is(0L));
    assertThat(clients.getItemsPerPage(), is(0));
    assertThat(clients.getStartIndex(), is(1));

  }


  @Test
  public void testClientDelete() {
    managementService.deleteClientByClientId("client");
    assertTrue(managementService.retrieveClientByClientId("client").isEmpty());
  }

  @Test
  public void testClientRetrieve() {
    RegisteredClientDTO client = managementService.retrieveClientByClientId("client").orElseThrow();

    assertThat(client.getClientId(), is("client"));
    assertThat(client.getClientSecret(), is("secret"));
    assertThat(client.getGrantTypes(), hasItems(CODE, REDELEGATE, IMPLICIT, REFRESH_TOKEN));
    assertThat(client.getScope(), hasItems("openid", "offline_access", "profile", "email",
        "address", "phone", "read-tasks", "write-tasks", "read:/", "write:/"));
    assertThat(client.getTokenEndpointAuthMethod(), is(client_secret_basic));
  }

  @Test
  public void testClientCreationSuccess() throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertThat(savedClient.getClientId(), is(client.getClientId()));
    assertThat(savedClient.getClientSecret(), notNullValue());
  }

  @Test
  public void testClientWithJwkValue() throws ParseException {

    final String NOT_A_JSON_STRING = "This is not a JSON string";
    final String VALID_JSON_VALUE =
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"rsa1\",\"alg\":\"RS256\",\"n\":\"zTF0oJjUDvoEBK82Hb706nRRJakcqoz_w4zdCIiv0BR1oumtQE8teUoLaYK_aqf9y30wajXoIq40tJYMXKW7QIFm2GYZ3qknUKGIy8xdNFEnLA2DG-BwSisNpJTvmiG1nbjvDRk7_M7WRmNwQkpdAXri89e9lL7ctG9aOnUs6wpinCqXYX9xvJl9k1HOdj_qZKrpz6xe75bPabe2yrF2TRfSobI5SSqTBBFLg06kuaaqqzVWbzCv8hgV7NMrt1CYDlXrfS2v1Ejf3WIEtgMRSxDBav90kpkBybwFhvyy7E87hjMdyoNk-yyYuZA_uSJCPKWJwjPB_EXaw280rObZ5Q\"}]}";
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setJwk(NOT_A_JSON_STRING);

    ParseException e = assertThrows(ParseException.class, () -> {
      managementService.saveNewClient(client);
    });

    String expectedMessage = "Invalid JSON: Unexpected token " + NOT_A_JSON_STRING;
    String actualMessage = e.getMessage();

    assertTrue(actualMessage.contains(expectedMessage));

    client.setJwk(VALID_JSON_VALUE);
    try {
      RegisteredClientDTO savedClient = managementService.saveNewClient(client);
      assertThat(savedClient.getClientId(), is(client.getClientId()));
      assertThat(savedClient.getJwk(), is(VALID_JSON_VALUE));
    } finally {
      managementService.deleteClientByClientId(client.getClientId());
    }
  }

  @Test
  public void testClientWithJwksUri() throws ParseException {

    final String NOT_A_VALID_URI = "This is not a valid URI";
    final String VALID_URI = "https://host.domain.com/this/is/my/public-key";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
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
      assertThat(savedClient.getClientId(), is(client.getClientId()));
      assertThat(savedClient.getJwksUri(), is(VALID_URI));
    } finally {
      managementService.deleteClientByClientId(client.getClientId());
    }
  }

  @Test
  public void testBasicClientValidation() {

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO client = new RegisteredClientDTO();
          managementService.saveNewClient(client);
        });

    assertThat(exception.getMessage(), containsString("should not be blank"));

    exception = Assertions.assertThrows(ConstraintViolationException.class, () -> {
      RegisteredClientDTO client = new RegisteredClientDTO();
      client.setClientName("client");
      client.setClientId("client");
      client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
      managementService.saveNewClient(client);
    });

    assertThat(exception.getMessage(), containsString("Client id not available"));

  }

  @Test
  public void testDynamicallyRegisteredClientCanBeUpdated()
      throws ParseException {

    userAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(userAuth.getName()).thenReturn("test");
    when(userAuth.getAuthorities()).thenAnswer(x -> Sets.newHashSet(Authorities.ROLE_USER));

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = registrationService.registerClient(request, userAuth);

    
    String clientId = response.getClientId();
    ClientDetailsEntity entity = clientService.findClientByClientId(clientId).orElseThrow();
    assertThat(entity.isDynamicallyRegistered(), is(true));

    RegisteredClientDTO client = managementService.retrieveClientByClientId(clientId).orElseThrow();

    client.getGrantTypes().add(AuthorizationGrantType.DEVICE_CODE);
    RegisteredClientDTO updatedClient = managementService.updateClient(clientId, client);

    assertThat(updatedClient.isDynamicallyRegistered(), is(true));
    assertThat(updatedClient.getRegistrationClientUri(), notNullValue());
    assertThat(updatedClient.getGrantTypes(),
        hasItems(AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.DEVICE_CODE));

  }

  @Test
  public void testSecretRotation() throws ParseException {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertThat(savedClient.getClientId(), is(client.getClientId()));
    assertThat(savedClient.getClientSecret(), notNullValue());


    managementService.generateNewClientSecret(client.getClientId());
    RegisteredClientDTO updatedClient =
        managementService.retrieveClientByClientId(client.getClientId()).orElseThrow();

    assertThat(updatedClient.getClientSecret(),
        not(equalTo(savedClient.getClientSecret())));
  }

  @Test
  public void testRatRotation() throws ParseException {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-rat-rotation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertThat(savedClient.getClientId(), notNullValue());
    assertThat(savedClient.getRegistrationAccessToken(), nullValue());

    RegisteredClientDTO updatedClient =
        managementService.rotateRegistrationAccessToken(savedClient.getClientId());

    assertThat(updatedClient.getRegistrationAccessToken(), notNullValue());

    RegisteredClientDTO retrievedClient =
        managementService.retrieveClientByClientId(savedClient.getClientId()).orElseThrow();
    assertThat(retrievedClient.getRegistrationAccessToken(), nullValue());
  }

  @Test
  public void testClientOwnerAssignRemove() throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));

    RegisteredClientDTO savedClient = managementService.saveNewClient(client);
    assertThat(savedClient.getClientId(), is(client.getClientId()));
    assertThat(savedClient.getClientSecret(), notNullValue());
    
    ListResponseDTO<ScimUser> owners =
    managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertThat(owners.getTotalResults(), is(0L));

    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    IamAccount otherAccount = accountRepo.findByUsername("test_100").orElseThrow();

    managementService.assignClientOwner(savedClient.getClientId(), testAccount.getUuid());
    managementService.assignClientOwner(savedClient.getClientId(), otherAccount.getUuid());
    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertThat(owners.getTotalResults(), is(2L));
    assertThat(owners.getResources().get(0).getId(), is(testAccount.getUuid()));
    assertThat(owners.getResources().get(1).getId(), is(otherAccount.getUuid()));

    managementService.removeClientOwner(savedClient.getClientId(), testAccount.getUuid());
    // Calling removal multiple times for the same account shouldn't harm
    managementService.removeClientOwner(savedClient.getClientId(), testAccount.getUuid());

    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertThat(owners.getTotalResults(), is(1L));
    assertThat(owners.getResources().get(0).getId(), is(otherAccount.getUuid()));
    managementService.removeClientOwner(savedClient.getClientId(), otherAccount.getUuid());

    owners = managementService.getClientOwners(savedClient.getClientId(),
        PagingUtils.buildUnpagedPageRequest());

    assertThat(owners.getTotalResults(), is(0L));
  }


  @Test
  public void testCodeChallengeValidation() {

    String[] invalidCodeChallengeValues = {" ", "invalid", "S512"};

    for (String value : invalidCodeChallengeValues) {
      ConstraintViolationException exception =
          Assertions.assertThrows(ConstraintViolationException.class, () -> {
            RegisteredClientDTO client = new RegisteredClientDTO();
            client.setClientName("test-client-creation");
            client.setClientId("test-client-creation");
            client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
            client.setScope(Sets.newHashSet("test"));
            client.setCodeChallengeMethod(value);

            managementService.saveNewClient(client);

          });

      assertThat(exception.getMessage(), containsString("S256"));
    }

    String[] validCodeChallengeValues = {"", "none", "plain", "S256"};
    for (String value : validCodeChallengeValues) {
      Assertions.assertDoesNotThrow(() -> {
        RegisteredClientDTO client = new RegisteredClientDTO();
        client.setClientName("test-client-creation");
        client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
        client.setScope(Sets.newHashSet("test"));
        client.setCodeChallengeMethod(value);

        RegisteredClientDTO response = managementService.saveNewClient(client);

        assertThat(response.getCodeChallengeMethod(), is(value));
      });
    }
  }

}
