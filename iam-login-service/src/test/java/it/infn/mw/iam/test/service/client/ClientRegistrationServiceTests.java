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


import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ADMINISTRATORS;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.REGISTERED_USERS;
import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.validation.ConstraintViolationException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.shaded.com.google.common.collect.Sets;

import com.mercateo.test.clock.TestClock;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.client.error.NoSuchClient;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientDefaultsProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy;
import it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@SuppressWarnings("deprecation")
@IamNoMvcTest
@SpringBootTest(classes = {IamLoginService.class, ClientTestConfig.class},
    webEnvironment = WebEnvironment.NONE)
@ActiveProfiles({"h2", "wlcg-scopes"})
public class ClientRegistrationServiceTests {

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ClientRegistrationService service;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private Clock clock;

  @MockBean
  private BlacklistedSiteService blsService;

  @MockBean
  private ClientRegistrationProperties clientRegProps;

  @SpyBean
  private AccountUtils accountUtils;

  private Authentication noAuth;

  private Authentication userAuth;

  private Authentication anotherUserAuth;

  private Authentication adminAuth;

  private OAuth2Authentication ratAuth;

  private OAuth2Request oauthRequest;

  private OAuth2AuthenticationDetails oauthDetails;

  private IamAccount testAccount;
  private IamAccount test100Account;

  private IamAccount adminAccount;

  @BeforeEach
  public void beforeEach() {

    userAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(userAuth.getName()).thenReturn("test");
    when(userAuth.getAuthorities()).thenAnswer(x -> Sets.newHashSet(Authorities.ROLE_USER));

    anotherUserAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(anotherUserAuth.getName()).thenReturn("test_100");
    when(anotherUserAuth.getAuthorities()).thenAnswer(x -> Sets.newHashSet(Authorities.ROLE_USER));

    adminAuth = Mockito.mock(UsernamePasswordAuthenticationToken.class);
    when(adminAuth.getName()).thenReturn("admin");
    when(adminAuth.getAuthorities())
      .thenAnswer(x -> Sets.newHashSet(Authorities.ROLE_USER, Authorities.ROLE_ADMIN));

    noAuth = Mockito.mock(AnonymousAuthenticationToken.class);

    testAccount = accountRepo.findByUsername("test").orElseThrow();
    test100Account = accountRepo.findByUsername("test_100").orElseThrow();
    adminAccount = accountRepo.findByUsername("admin").orElseThrow();

    doReturn(Optional.of(testAccount)).when(accountUtils).getAuthenticatedUserAccount(userAuth);
    doReturn(Optional.of(test100Account)).when(accountUtils)
      .getAuthenticatedUserAccount(anotherUserAuth);
    doReturn(Optional.of(adminAccount)).when(accountUtils).getAuthenticatedUserAccount(adminAuth);

    ratAuth = Mockito.mock(OAuth2Authentication.class);
    oauthRequest = Mockito.mock(OAuth2Request.class);
    oauthDetails = Mockito.mock(OAuth2AuthenticationDetails.class);

    when(ratAuth.getOAuth2Request()).thenReturn(oauthRequest);
    when(ratAuth.getDetails()).thenReturn(oauthDetails);

    when(clientRegProps.getAllowFor()).thenReturn(ClientRegistrationAuthorizationPolicy.ANYONE);

    when(clientRegProps.getClientDefaults()).thenReturn(new ClientDefaultsProperties());

  }

  @Test
  public void testRegistrationRequestRequiresClientName() {

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientId(null);
          request.setClientDescription(null);
          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(), containsString("should not be blank"));

  }

  @Test
  public void testNoRedirectUriWithAuthzCodeValidation() {

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));

          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(),
        containsString("Authorization code requires a valid redirect uri"));

  }

  @Test
  public void testScopeValidation() {
    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
          request.setScope(Sets.newHashSet(""));

          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(), containsString("must not include blank strings"));
  }

  @Test
  public void testRedirectUrisValidation() {

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
          request.setRedirectUris(Sets.newHashSet("not-a-uri"));

          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(), containsString("Invalid redirect URI"));


    exception = Assertions.assertThrows(ConstraintViolationException.class, () -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet(" "));

      service.registerClient(request, userAuth);
    });

    assertThat(exception.getMessage(), containsString("Invalid redirect URI"));


    Assertions.assertDoesNotThrow(() -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet("myapp://redirect"));
      service.registerClient(request, userAuth);
    });

    Assertions.assertDoesNotThrow(() -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet("edu.kit.data.oidc-agent:/redirect"));
      service.registerClient(request, userAuth);
    });



  }


  @Test
  public void testBlacklistedUriValidation() {

    when(blsService.isBlacklisted("https://deny.example/cb")).thenReturn(true);

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
          request.setRedirectUris(Sets.newHashSet("https://deny.example/cb"));

          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(), containsString("https://deny.example/cb is not allowed"));

  }

  @Test
  public void testAllowedGrantTypeChecks() throws ParseException {

    // ask exchange grant type as user
    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(
              Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.TOKEN_EXCHANGE));
          request.setRedirectUris(Sets.newHashSet("https://example/cb"));
          service.registerClient(request, userAuth);
        });

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.TOKEN_EXCHANGE.getGrantType()));

    // ask exchange grant type as anonymous
    exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          RegisteredClientDTO request = new RegisteredClientDTO();
          request.setClientName("example");
          request.setGrantTypes(
              Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.TOKEN_EXCHANGE));
          request.setRedirectUris(Sets.newHashSet("https://example/cb"));
          service.registerClient(request, noAuth);
        });

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.TOKEN_EXCHANGE.getGrantType()));

    // ask password grant type as user
    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(
          Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.PASSWORD));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      service.registerClient(request, userAuth);
    });

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.PASSWORD.getGrantType()));

    // ask password grant type as anonymous
    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(
          Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.PASSWORD));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      service.registerClient(request, noAuth);
    });

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.PASSWORD.getGrantType()));

    // ask client credentials grant type as anonymous
    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(
          Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.CLIENT_CREDENTIALS));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      service.registerClient(request, noAuth);
    });

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.CLIENT_CREDENTIALS.getGrantType()));

    // ask client credentials grant type as user
    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(
        Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.CLIENT_CREDENTIALS));
    request.setRedirectUris(Sets.newHashSet("https://example/cb"));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    assertThat(exception.getMessage(), containsString(
        "Grant type not allowed: " + AuthorizationGrantType.CLIENT_CREDENTIALS.getGrantType()));
    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), notNullValue());
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(),
        hasItems(AuthorizationGrantType.CODE, AuthorizationGrantType.CLIENT_CREDENTIALS));

    assertThat(response.getRegistrationAccessToken(), nullValue());
    assertThat(response.getClientSecret(), notNullValue());

    // ask password, client credentials and exchange grant types as admin
    request = new RegisteredClientDTO();
    request.setClientName("example");
    request
      .setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE, AuthorizationGrantType.PASSWORD,
          AuthorizationGrantType.TOKEN_EXCHANGE, AuthorizationGrantType.CLIENT_CREDENTIALS));
    request.setRedirectUris(Sets.newHashSet("https://example/cb"));

    response = service.registerClient(request, adminAuth);
    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), notNullValue());
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(),
        hasItems(AuthorizationGrantType.CODE, AuthorizationGrantType.TOKEN_EXCHANGE,
            AuthorizationGrantType.PASSWORD, AuthorizationGrantType.CLIENT_CREDENTIALS));

    assertThat(response.getRegistrationAccessToken(), nullValue());
    assertThat(response.getClientSecret(), notNullValue());
    assertThat(response.getContacts(), hasItem(adminAccount.getUserInfo().getEmail()));

  }

  @Test
  public void testRestrictedScopesAreFilteredOut() {

    scopeService.getRestricted().forEach(ss -> {
      final String restrictedScope = ss.getValue();
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName(String.format("test-registration %s", ss.getValue()));
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      request.setScope(Sets.newHashSet(restrictedScope, "openid"));

      RegisteredClientDTO response = null;
      try {
        response = service.registerClient(request, userAuth);
      } catch (ParseException e1) {
        fail("Unexpected JSON parsing problem");
      }

      ClientDetailsEntity client = clientRepo.findByClientId(response.getClientId()).orElseThrow();

      assertThat(response.getScope(), hasItem("openid"));
      assertThat(response.getScope(), not(hasItem(restrictedScope)));
      assertThat(client.getScope(), hasItem("openid"));
      assertThat(client.getScope(), not(hasItem(restrictedScope)));


      response.getScope().add(restrictedScope);
      try {
        response = service.updateClient(response.getClientId(), response, userAuth);
      } catch (ParseException e) {
        fail("Unexpected JSON parsing problem");
      }
      assertThat(response.getScope(), not(hasItem(restrictedScope)));

    });
  }

  @Test
  public void testRestrictedScopesAreFilteredOutWithMatchers() throws ParseException {

    String restrictedScope1 = "storage.read:/whatever";
    String restrictedScope2 = "storage.read:/";

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://example/cb"));
    request.setScope(Sets.newHashSet(restrictedScope1, restrictedScope2, "openid"));

    RegisteredClientDTO response = service.registerClient(request, userAuth);

    assertThat(response.getScope(), hasItem("openid"));
    assertThat(response.getScope(), not(hasItems(restrictedScope1, restrictedScope2)));

    response.getScope().add(restrictedScope1);
    response.getScope().add(restrictedScope2);
    response = service.updateClient(response.getClientId(), response, userAuth);

    assertThat(response.getScope(), hasItem("openid"));
    assertThat(response.getScope(), not(hasItems(restrictedScope1, restrictedScope2)));
  }

  @Test
  public void testReservedScopesAreFilteredOut() {

    scopeService.getReserved().forEach(ss -> {
      final String reservedScope = ss.getValue();
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      request.setScope(Sets.newHashSet(reservedScope, "openid"));

      RegisteredClientDTO response = null;
      try {
        response = service.registerClient(request, userAuth);
      } catch (ParseException e) {
        fail("Unexpected JSON mapping problem");
      }

      assertThat(response.getScope(), hasItem("openid"));
      assertThat(response.getScope(), not(hasItem(reservedScope)));

      response.getScope().add(reservedScope);
      try {
        response = service.updateClient(response.getClientId(), response, userAuth);
      } catch (ParseException e) {
        fail("Unexpected JSON mapping problem");
      }
      assertThat(response.getScope(), not(hasItem(reservedScope)));

    });
  }

  @Test
  public void testAdminCanRegisterClientWithRestrictedScope() {
    scopeService.getRestricted().forEach(ss -> {
      final String restrictedScope = ss.getValue();
      RegisteredClientDTO request = new RegisteredClientDTO();
      request.setClientName("example");
      request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
      request.setRedirectUris(Sets.newHashSet("https://example/cb"));
      request.setScope(Sets.newHashSet(restrictedScope, "openid"));

      RegisteredClientDTO response = null;
      try {
        response = service.registerClient(request, adminAuth);
      } catch (ParseException e) {
        fail("Unexpected JSON mapping problem");
      }
      assertThat(response.getClientName(), is("example"));
      assertThat(response.getClientId(), notNullValue());
      assertThat(response.getTokenEndpointAuthMethod(),
          is(TokenEndpointAuthenticationMethod.client_secret_basic));
      assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.CODE));
      assertThat(response.getRegistrationAccessToken(), nullValue());
      assertThat(response.getClientSecret(), notNullValue());

      assertThat(response.getScope(), hasItem("openid"));
      assertThat(response.getScope(), hasItem(restrictedScope));
      assertThat(response.getContacts(), hasItem(adminAccount.getUserInfo().getEmail()));
    });
  }

  @Test
  public void testAnonymousRequestYeldsRegistrationAccessToken() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    RegisteredClientDTO response = service.registerClient(request, noAuth);

    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), notNullValue());
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.DEVICE_CODE));
    assertThat(response.getRegistrationAccessToken(), notNullValue());
    assertThat(response.getRegistrationClientUri(),
        is("http://localhost:8080/iam/api/client-registration/" + response.getClientId()));
  }

  @Test
  public void testSuccesfullRegistration() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), notNullValue());
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.CLIENT_CREDENTIALS));
    assertThat(response.getRegistrationAccessToken(), nullValue());
    assertThat(response.getClientSecret(), notNullValue());
    assertThat(response.getContacts(), hasItem(testAccount.getUserInfo().getEmail()));
    assertThat(response.getRegistrationClientUri(),
        is("http://localhost:8080/iam/api/client-registration/" + response.getClientId()));
  }

  @Test
  public void noScopeYeldsDefaultScopes() throws ParseException {

    Set<String> defaultScopes = scopeService.toStrings(scopeService.getDefaults());

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    defaultScopes.forEach(s -> assertThat(response.getScope(), hasItem(s)));

  }

  @Test
  public void testRegisteredUserAuthzPolicy() {

    when(clientRegProps.getAllowFor()).thenReturn(REGISTERED_USERS);
    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));

    AccessDeniedException exception = Assertions.assertThrows(AccessDeniedException.class, () -> {
      service.registerClient(request, noAuth);
    });

    assertThat(exception.getMessage(), containsString("You do not have enough privileges"));

    Assertions.assertDoesNotThrow(() -> {
      RegisteredClientDTO userResponse = service.registerClient(request, userAuth);
      RegisteredClientDTO adminResponse = service.registerClient(request, adminAuth);
      assertThat(userResponse.getClientId(), notNullValue());
      assertThat(adminResponse.getClientId(), notNullValue());
    });

  }

  @Test
  public void testAdministratorsAuthzPolicy() {

    when(clientRegProps.getAllowFor()).thenReturn(ADMINISTRATORS);
    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));

    AccessDeniedException exception = Assertions.assertThrows(AccessDeniedException.class, () -> {
      service.registerClient(request, noAuth);
    });

    assertThat(exception.getMessage(), containsString("You do not have enough privileges"));

    exception = Assertions.assertThrows(AccessDeniedException.class, () -> {
      service.registerClient(request, userAuth);
    });

    assertThat(exception.getMessage(), containsString("You do not have enough privileges"));

    Assertions.assertDoesNotThrow(() -> {
      RegisteredClientDTO adminResponse = service.registerClient(request, adminAuth);
      assertThat(adminResponse.getClientId(), notNullValue());
    });

  }

  @Test
  public void testAuthzComesBeforeLookupForRetrieveClient() {

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          service.retrieveClient("invalid-client-id", noAuth);
        });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

    NoSuchClient notFoundException = Assertions.assertThrows(NoSuchClient.class, () -> {
      service.retrieveClient("invalid-client-id", userAuth);
    });

    assertThat(notFoundException.getMessage(), containsString("Client not found"));
  }

  @Test
  public void testRegisterAndRetrieveWorksForUser() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO registerResponse = service.registerClient(request, userAuth);

    RegisteredClientDTO response = service.retrieveClient(registerResponse.getClientId(), userAuth);

    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), notNullValue());
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.CLIENT_CREDENTIALS));
    assertThat(response.getRegistrationAccessToken(), nullValue());
    assertThat(response.getClientSecret(), notNullValue());
    assertThat(response.getContacts(), hasItem(testAccount.getUserInfo().getEmail()));
    assertThat(response.getRegistrationClientUri(),
        is("http://localhost:8080/iam/api/client-registration/" + response.getClientId()));

  }


  @Test
  public void testRegisterAndRetrieveWorksForAnonymousUser() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    RegisteredClientDTO registerResponse = service.registerClient(request, noAuth);
    assertThat(registerResponse.getRegistrationAccessToken(), notNullValue());

    when(oauthRequest.getClientId()).thenReturn(registerResponse.getClientId());
    when(oauthRequest.getScope())
      .thenReturn(Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));

    RegisteredClientDTO response = service.retrieveClient(registerResponse.getClientId(), ratAuth);

    assertThat(response.getClientName(), is("example"));
    assertThat(response.getClientId(), is(registerResponse.getClientId()));
    assertThat(response.getTokenEndpointAuthMethod(),
        is(TokenEndpointAuthenticationMethod.client_secret_basic));
    assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.DEVICE_CODE));
    assertThat(response.getClientSecret(), notNullValue());
    assertThat(response.getRegistrationClientUri(),
        is("http://localhost:8080/iam/api/client-registration/" + response.getClientId()));

  }


  @Test
  public void testRatClientIdAndScopesAreChecked() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    RegisteredClientDTO registerResponse = service.registerClient(request, noAuth);
    assertThat(registerResponse.getRegistrationAccessToken(), notNullValue());

    when(oauthRequest.getClientId()).thenReturn("some-other-id");
    when(oauthRequest.getScope())
      .thenReturn(Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          service.retrieveClient(registerResponse.getClientId(), ratAuth);
        });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

    when(oauthRequest.getClientId()).thenReturn(registerResponse.getClientId());
    when(oauthRequest.getScope()).thenReturn(Sets.newHashSet());

    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      service.retrieveClient(registerResponse.getClientId(), ratAuth);
    });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

  }


  @Test
  public void testSuccesfullDelete() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          service.deleteClient(response.getClientId(), noAuth);
        });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

    service.deleteClient(response.getClientId(), userAuth);

    NoSuchClient notFoundException = Assertions.assertThrows(NoSuchClient.class, () -> {
      service.retrieveClient(response.getClientId(), userAuth);
    });

    assertThat(notFoundException.getMessage(), containsString("Client not found"));

  }

  @Test
  public void testAccountAuthzForClientManagement() throws ParseException {
    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    NoSuchClient exception = Assertions.assertThrows(NoSuchClient.class, () -> {
      service.retrieveClient(response.getClientId(), anotherUserAuth);
    });

    assertThat(exception.getMessage(), containsString("Client not found"));

    exception = Assertions.assertThrows(NoSuchClient.class, () -> {
      service.deleteClient(response.getClientId(), anotherUserAuth);
    });

    assertThat(exception.getMessage(), containsString("Client not found"));
  }

  @Test
  public void testGranTypesAreCheckedOnUpdate() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO response = service.registerClient(request, userAuth);

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          RegisteredClientDTO updateRequest = response;
          updateRequest.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS,
              AuthorizationGrantType.TOKEN_EXCHANGE));
          service.updateClient(response.getClientId(), updateRequest, userAuth);

        });

    assertThat(exception.getMessage(), containsString("Grant type not allowed"));

    // update client grant types as admin

    RegisteredClientDTO reqClient = new RegisteredClientDTO();
    reqClient.setClientName("example2");
    reqClient.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    RegisteredClientDTO respClient = service.registerClient(reqClient, adminAuth);

    RegisteredClientDTO updateReq = respClient;
    updateReq.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS,
        AuthorizationGrantType.TOKEN_EXCHANGE));
    RegisteredClientDTO updateResponse = service.updateClient(respClient.getClientId(), updateReq, adminAuth);

    assertThat(updateResponse.getGrantTypes(), hasItems(AuthorizationGrantType.CLIENT_CREDENTIALS,
        AuthorizationGrantType.TOKEN_EXCHANGE));

  }

  @Test
  public void testRedirectUrisAreCheckedOnUpdate() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, userAuth);

    ConstraintViolationException exception =
        Assertions.assertThrows(ConstraintViolationException.class, () -> {
          RegisteredClientDTO updateRequest = response;
          updateRequest.setRedirectUris(emptySet());
          service.updateClient(response.getClientId(), updateRequest, userAuth);

        });

    assertThat(exception.getMessage(), containsString("code requires a valid redirect uri"));
  }


  @Test
  public void testRatIsUpdated() throws ParseException {

    TestClock testClock = (TestClock) clock;
    ClientDefaultsProperties props = new ClientDefaultsProperties();
    props.setDefaultRegistrationAccessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(1));

    when(clientRegProps.getClientDefaults()).thenReturn(props);


    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, noAuth);

    when(oauthDetails.getTokenValue()).thenReturn(response.getRegistrationAccessToken());
    when(oauthRequest.getClientId()).thenReturn(response.getClientId());
    when(oauthRequest.getScope())
      .thenReturn(Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));

    RegisteredClientDTO updateRequest = response;
    response.setClientDescription("Whatever");

    testClock.fastForward(Duration.ofDays(2));

    RegisteredClientDTO updateResponse =
        service.updateClient(response.getClientId(), updateRequest, ratAuth);

    assertThat(updateResponse.getRegistrationAccessToken(), notNullValue());
    assertThat(updateResponse.getRegistrationAccessToken(),
        not(equalTo(response.getRegistrationAccessToken())));

  }

  @Test
  public void testPrivilegedGrantTypesArePreservedOnUpdate() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, noAuth);

    when(oauthDetails.getTokenValue()).thenReturn(response.getRegistrationAccessToken());
    when(oauthRequest.getClientId()).thenReturn(response.getClientId());
    when(oauthRequest.getScope())
      .thenReturn(Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));

    ClientDetailsEntity clientEntity =
        clientRepo.findByClientId(response.getClientId()).orElseThrow();

    clientEntity.getGrantTypes().add(TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE);
    clientRepo.save(clientEntity);

    response = service.retrieveClient(response.getClientId(), ratAuth);
    assertThat(response.getGrantTypes(), hasItem(AuthorizationGrantType.TOKEN_EXCHANGE));

    request = response;

    RegisteredClientDTO updateResponse =
        service.updateClient(response.getClientId(), request, ratAuth);
    assertThat(updateResponse.getGrantTypes(), hasItem(AuthorizationGrantType.TOKEN_EXCHANGE));
    assertThat(updateResponse.getGrantTypes(), hasItem(AuthorizationGrantType.CODE));
  }

  @Test
  public void testPrivilegedGrantTypesAreCheckedOnUpdateForAnonymousUser() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("example");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, noAuth);

    when(oauthDetails.getTokenValue()).thenReturn(response.getRegistrationAccessToken());
    when(oauthRequest.getClientId()).thenReturn(response.getClientId());
    when(oauthRequest.getScope())
      .thenReturn(Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          RegisteredClientDTO updateRequest = response;
          updateRequest.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
          service.updateClient(response.getClientId(), updateRequest, ratAuth);

        });

    assertThat(exception.getMessage(), containsString("Grant type not allowed"));
  }

  @Test
  public void testRestrictedScopesArePreserved() throws ParseException {

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("restricted-scopes-preserved");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, userAuth);

    ClientDetailsEntity clientEntity =
        clientRepo.findByClientId(response.getClientId()).orElseThrow();

    clientEntity.getScope().add("scim:read");
    clientEntity.getScope().add("storage.read:/example");
    clientRepo.save(clientEntity);

    response = service.retrieveClient(response.getClientId(), userAuth);
    assertThat(response.getScope(), hasItems("scim:read", "storage.read:/example"));
    response.getScope().add("entitlements");
    response.getContacts().add("test@example.org");
    RegisteredClientDTO updateResponse =
        service.updateClient(response.getClientId(), response, userAuth);

    assertThat(updateResponse.getScope(),
        hasItems("scim:read", "storage.read:/example", "entitlements"));
  }


  @Test
  public void testRedeemClient() throws ParseException {

    TestClock testClock = (TestClock) clock;
    ClientDefaultsProperties props = new ClientDefaultsProperties();
    props.setDefaultRegistrationAccessTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(1));

    when(clientRegProps.getClientDefaults()).thenReturn(props);

    RegisteredClientDTO request = new RegisteredClientDTO();
    request.setClientName("redeem-client-test");
    request.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CODE));
    request.setRedirectUris(Sets.newHashSet("https://test.example/cb"));

    RegisteredClientDTO response = service.registerClient(request, noAuth);
    RegisteredClientDTO response2 = service.registerClient(request, noAuth);

    InvalidClientRegistrationRequest exception =
        Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
          service.redeemClient(response.getClientId(), response.getRegistrationAccessToken(),
              noAuth);
        });

    assertThat(exception.getMessage(), containsString("No authenticated user found"));

    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      service.redeemClient(response.getClientId(), "invalid-token", userAuth);
    });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

    // Test with rat linked to another client
    exception = Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      service.redeemClient(response.getClientId(), response2.getRegistrationAccessToken(),
          userAuth);
    });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));

    service.redeemClient(response.getClientId(), response.getRegistrationAccessToken(), userAuth);

    RegisteredClientDTO redeemedResponse = service.retrieveClient(response.getClientId(), userAuth);

    assertThat(redeemedResponse.getClientId(), is(response.getClientId()));

    testClock.fastForward(Duration.ofDays(2));

    Assertions.assertThrows(InvalidClientRegistrationRequest.class, () -> {
      service.redeemClient(response.getClientId(), response.getRegistrationAccessToken(),
          anotherUserAuth);
    });

    assertThat(exception.getMessage(), containsString("Invalid registration access token"));
  }

  @Test
  public void testClientWithJwkValue() throws ParseException {

    final String NOT_A_JSON_STRING = "This is not a JSON string";
    final String VALID_JSON_VALUE =
        "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"rsa1\",\"alg\":\"RS256\",\"n\":\"zTF0oJjUDvoEBK82Hb706nRRJakcqoz_w4zdCIiv0BR1oumtQE8teUoLaYK_aqf9y30wajXoIq40tJYMXKW7QIFm2GYZ3qknUKGIy8xdNFEnLA2DG-BwSisNpJTvmiG1nbjvDRk7_M7WRmNwQkpdAXri89e9lL7ctG9aOnUs6wpinCqXYX9xvJl9k1HOdj_qZKrpz6xe75bPabe2yrF2TRfSobI5SSqTBBFLg06kuaaqqzVWbzCv8hgV7NMrt1CYDlXrfS2v1Ejf3WIEtgMRSxDBav90kpkBybwFhvyy7E87hjMdyoNk-yyYuZA_uSJCPKWJwjPB_EXaw280rObZ5Q\"}]}";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setJwk(NOT_A_JSON_STRING);

    ParseException e = assertThrows(ParseException.class, () -> {
      service.registerClient(client, userAuth);
    });

    assertTrue(e.getMessage().contains("Invalid JSON:"));

    RegisteredClientDTO savedClient = null;
    client.setJwk(VALID_JSON_VALUE);
    try {
      savedClient = service.registerClient(client, userAuth);
      assertThat(savedClient.getClientId(), is(savedClient.getClientId()));
      assertThat(savedClient.getJwk(), is(VALID_JSON_VALUE));
    } finally {
      service.deleteClient(savedClient.getClientId(), userAuth);
    }
  }

  @Test
  public void testClientWithJwksUri() throws ParseException {

    final String NOT_A_VALID_URI = "This is not a valid URI";
    final String VALID_URI = "https://host.domain.com/this/is/my/public-key";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setJwksUri(NOT_A_VALID_URI);

    ConstraintViolationException e = assertThrows(ConstraintViolationException.class, () -> {
      service.registerClient(client, userAuth);
    });

    String expectedMessage = "registerClient.request.jwksUri:";
    String actualMessage = e.getMessage();

    assertTrue(actualMessage.contains(expectedMessage));

    RegisteredClientDTO savedClient = null;
    client.setJwksUri(VALID_URI);
    try {
      savedClient = service.registerClient(client, userAuth);
      assertThat(savedClient.getClientId(), is(savedClient.getClientId()));
      assertThat(savedClient.getJwksUri(), is(VALID_URI));
    } finally {
      service.deleteClient(savedClient.getClientId(), userAuth);
    }
  }

}
