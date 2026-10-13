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
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ADD_SECRET_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.AUTHENTICATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REMOVAL_OPTIONS_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRemovalDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true",
    "mfa.passkey.max-credentials-per-account=2"})
class PasskeyControllerTests extends PasskeyTestSupport {

  private static final String TEST_USER = "test";
  private static final String TEST_USER_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  private static final String UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamPasskeyRepository passkeyRepository;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private Clock clock;

  private final ObjectMapper mapper = new ObjectMapper();

  private IamPasskey storedPasskeyFor(String username, PasskeyTestAuthenticator authenticator) {
    IamAccount account = accountRepository.findByUsername(username).orElseThrow();
    return passkeyRepository.save(registeredPasskey(account, authenticator, clock.instant()));
  }

  private PasskeyRegistrationOptionsDTO registrationOptions(MockHttpSession session)
      throws Exception {
    return registrationOptions(session, TEST_USER);
  }

  private PasskeyRegistrationOptionsDTO registrationOptions(MockHttpSession session,
      String expectedUsername) throws Exception {
    String body = mvc.perform(post(REGISTRATION_OPTIONS_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.rp.id", is(TEST_RP_ID)))
      .andExpect(jsonPath("$.user.name", is(expectedUsername)))
      .andExpect(jsonPath("$.challenge", notNullValue()))
      .andExpect(jsonPath("$.attestation", is("none")))
      .andReturn()
      .getResponse()
      .getContentAsString();
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE), notNullValue());
    return mapper.readValue(body, PasskeyRegistrationOptionsDTO.class);
  }

  private PasskeyDTO register(MockHttpSession session, PasskeyTestAuthenticator authenticator,
      String label) throws Exception {
    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    PasskeyRegistrationDTO registration = registrationFor(authenticator, options.getChallenge(),
        TEST_ORIGIN, false, List.of("internal"), label);

    String body = mvc
      .perform(post(REGISTRATION_URL).session(session)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(registration)))
      .andExpect(status().isCreated())
      .andExpect(jsonPath("$.uuid", notNullValue()))
      .andExpect(jsonPath("$.label", is(label)))
      .andExpect(jsonPath("$.transports[0]", is("internal")))
      .andReturn()
      .getResponse()
      .getContentAsString();
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE),
        nullValue());
    return mapper.readValue(body, PasskeyDTO.class);
  }

  private PasskeyRemovalDTO removalProof(MockHttpSession session,
      PasskeyTestAuthenticator authenticator, long signCount) throws Exception {
    String body = mvc.perform(post(REMOVAL_OPTIONS_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.challenge", notNullValue()))
      .andReturn()
      .getResponse()
      .getContentAsString();
    PasskeyAssertionOptionsDTO options = mapper.readValue(body, PasskeyAssertionOptionsDTO.class);
    PasskeyRemovalDTO proof = new PasskeyRemovalDTO();
    proof.setAssertion(
        assertionFor(authenticator, options.getChallenge(), TEST_ORIGIN, false, signCount, null));
    return proof;
  }

  private MockHttpServletRequestBuilder removal(MockHttpSession session, String uuid,
      PasskeyRemovalDTO proof) throws Exception {
    return delete(BASE_URL + "/" + uuid).session(session)
      .contentType(MediaType.APPLICATION_JSON)
      .content(mapper.writeValueAsString(proof));
  }

  @Test
  @WithAnonymousUser
  void anonymousAccessIsUnauthorized() throws Exception {
    mvc.perform(get(BASE_URL)).andExpect(status().isUnauthorized());
    mvc.perform(post(REGISTRATION_OPTIONS_URL)).andExpect(status().isUnauthorized());
    mvc.perform(post(REGISTRATION_URL).contentType(MediaType.APPLICATION_JSON).content("{}"))
      .andExpect(status().isUnauthorized());
    mvc.perform(post(AUTHENTICATION_OPTIONS_URL)).andExpect(status().isUnauthorized());
    mvc.perform(delete(BASE_URL + "/" + UNKNOWN_UUID)).andExpect(status().isUnauthorized());
    mvc.perform(delete(BASE_URL + "/reset/" + TEST_USER_UUID))
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"PRE_AUTHENTICATED"})
  void preAuthenticatedUserCanOnlyEnrolAndRequestAssertionOptions() throws Exception {
    mvc.perform(get(BASE_URL)).andExpect(status().isForbidden());
    mvc.perform(delete(BASE_URL + "/" + UNKNOWN_UUID)).andExpect(status().isForbidden());
    mvc.perform(delete(BASE_URL + "/reset/" + TEST_USER_UUID)).andExpect(status().isForbidden());
    mvc.perform(post(REGISTRATION_OPTIONS_URL)).andExpect(status().isOk());

    MockHttpSession session = new MockHttpSession();
    mvc.perform(post(AUTHENTICATION_OPTIONS_URL).session(session))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.rpId", is(TEST_RP_ID)))
      .andExpect(jsonPath("$.challenge", notNullValue()));
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE), notNullValue());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"PRE_AUTHENTICATED"})
  void preAuthenticatedUserWithAnActiveFactorCannotEnrolAnotherOne() throws Exception {
    storedPasskeyFor(TEST_USER, new PasskeyTestAuthenticator(Algorithm.ES256));

    // neither a passkey...
    mvc.perform(post(REGISTRATION_OPTIONS_URL)).andExpect(status().isForbidden());
    mvc.perform(post(REGISTRATION_URL).contentType(MediaType.APPLICATION_JSON).content("{}"))
      .andExpect(status().isForbidden());
    // ...nor an authenticator app can be enrolled before the second factor is verified
    mvc.perform(put(ADD_SECRET_URL)).andExpect(status().isForbidden());
    mvc.perform(post(ENABLE_URL).param("code", "123456")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void fullyAuthenticatedUserCannotRequestAssertionOptions() throws Exception {
    mvc.perform(post(AUTHENTICATION_OPTIONS_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void adminEndpointIsForbiddenToUsers() throws Exception {
    mvc.perform(delete(BASE_URL + "/reset/" + TEST_USER_UUID)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registerListAndRemovePasskey() throws Exception {
    mvc.perform(get(BASE_URL)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
    mvc.perform(get(MULTI_FACTOR_SETTINGS_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.authenticatorAppActive", is(false)))
      .andExpect(jsonPath("$.passkeyActive", is(false)));

    MockHttpSession session = new MockHttpSession();
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyDTO passkey = register(session, authenticator, "my key");

    mvc.perform(get(BASE_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(1)))
      .andExpect(jsonPath("$[0].uuid", is(passkey.getUuid())))
      .andExpect(jsonPath("$[0].label", is("my key")))
      .andExpect(jsonPath("$[0].creationTime", notNullValue()))
      .andExpect(jsonPath("$[0].credentialId").doesNotExist())
      .andExpect(jsonPath("$[0].attestedCredentialData").doesNotExist());

    mvc.perform(get(MULTI_FACTOR_SETTINGS_URL))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.passkeyActive", is(true)));

    List<IamPasskey> stored = passkeyRepository.findByAccountUsername(TEST_USER);
    assertThat(stored, hasSize(1));
    assertThat(stored.get(0).getCredentialId(), equalTo(authenticator.getCredentialIdBase64Url()));
    assertThat(stored.get(0).getAaguid(), equalTo(authenticator.getAaguid().toString()));

    // the registration options now exclude the registered credential
    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    assertThat(options.getExcludeCredentials(), hasSize(1));
    assertThat(options.getExcludeCredentials().get(0).getId(),
        equalTo(authenticator.getCredentialIdBase64Url()));

    // The removal needs a proof of possession: none, an empty one, or a code of an authenticator
    // app that is not active are refused
    mvc.perform(delete(BASE_URL + "/" + passkey.getUuid()).session(session))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.REMOVAL_PROOF_REQUIRED_MESSAGE)));
    mvc.perform(removal(session, passkey.getUuid(), new PasskeyRemovalDTO()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.REMOVAL_PROOF_REQUIRED_MESSAGE)));
    PasskeyRemovalDTO totp = new PasskeyRemovalDTO();
    totp.setTotp("123456");
    mvc.perform(removal(session, passkey.getUuid(), totp))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.REMOVAL_PROOF_REQUIRED_MESSAGE)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), hasSize(1));

    // An assertion of the passkey proves it; the removal challenge is consumed with it
    mvc.perform(removal(session, passkey.getUuid(), removalProof(session, authenticator, 1)))
      .andExpect(status().isNoContent());
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE), nullValue());
    mvc.perform(get(BASE_URL)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), empty());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void removalProofIsSingleUseAndBoundToTheRemovalChallenge() throws Exception {
    MockHttpSession session = new MockHttpSession();
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyDTO passkey = register(session, authenticator, "my key");

    // A tampered assertion fails and consumes the challenge: the same proof is then refused for
    // want of a challenge, and only a fresh one goes through
    PasskeyRemovalDTO proof = removalProof(session, authenticator, 1);
    proof.getAssertion().getResponse().setSignature(
        PasskeyTestAuthenticator.base64Url(PasskeyTestAuthenticator.randomBytes(64)));
    mvc.perform(removal(session, passkey.getUuid(), proof))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Passkey verification failed")));
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE), nullValue());

    mvc.perform(removal(session, passkey.getUuid(), removalProof(session, authenticator, 1)))
      .andExpect(status().isNoContent());
    mvc.perform(removal(session, passkey.getUuid(), proof))
      .andExpect(status().isNotFound());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), empty());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"PRE_AUTHENTICATED"})
  void removalIsNotAvailableToPreAuthenticatedUsers() throws Exception {
    IamPasskey stored =
        storedPasskeyFor(TEST_USER, new PasskeyTestAuthenticator(Algorithm.ES256));

    mvc.perform(post(REMOVAL_OPTIONS_URL)).andExpect(status().isForbidden());
    mvc.perform(delete(BASE_URL + "/" + stored.getUuid())).andExpect(status().isForbidden());
    assertThat(passkeyRepository.findByUuid(stored.getUuid()).isPresent(), is(true));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registrationWithoutChallengeIsRejected() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        PasskeyTestAuthenticator.base64Url(new byte[32]), TEST_ORIGIN, false, List.of());

    mvc
      .perform(post(REGISTRATION_URL).session(new MockHttpSession())
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(registration)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.CHALLENGE_MISSING_MESSAGE)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), empty());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registrationWithWrongChallengeIsRejectedAndConsumesChallenge() throws Exception {
    MockHttpSession session = new MockHttpSession();
    registrationOptions(session);
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyRegistrationDTO registration = registrationFor(authenticator,
        PasskeyTestAuthenticator.base64Url(new byte[32]), TEST_ORIGIN, false, List.of());

    mvc
      .perform(post(REGISTRATION_URL).session(session)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(registration)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("registration failed")));
    assertThat(session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE),
        nullValue());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), empty());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registrationCannotBeReplayed() throws Exception {
    MockHttpSession session = new MockHttpSession();
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    PasskeyRegistrationDTO registration = registrationFor(authenticator, options.getChallenge(),
        TEST_ORIGIN, false, List.of());
    String json = mapper.writeValueAsString(registration);

    mvc.perform(post(REGISTRATION_URL).session(session).contentType(MediaType.APPLICATION_JSON)
      .content(json)).andExpect(status().isCreated());
    mvc.perform(post(REGISTRATION_URL).session(session).contentType(MediaType.APPLICATION_JSON)
      .content(json))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.CHALLENGE_MISSING_MESSAGE)));

    // a fresh challenge does not allow registering the same credential again either
    registrationOptions(session);
    mvc.perform(post(REGISTRATION_URL).session(session).contentType(MediaType.APPLICATION_JSON)
      .content(json)).andExpect(status().isBadRequest());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), hasSize(1));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registrationRequiresLabel() throws Exception {
    MockHttpSession session = new MockHttpSession();
    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    PasskeyRegistrationDTO registration = registrationFor(
        new PasskeyTestAuthenticator(Algorithm.ES256), options.getChallenge(), TEST_ORIGIN, false,
        List.of(), " ");

    mvc
      .perform(post(REGISTRATION_URL).session(session)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(registration)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Invalid passkey registration")));

    registrationOptions(session);
    mvc
      .perform(post(REGISTRATION_URL).session(session)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"label\":\"x\"}"))
      .andExpect(status().isBadRequest());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), empty());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void registrationBeyondLimitIsRejected() throws Exception {
    MockHttpSession session = new MockHttpSession();
    register(session, new PasskeyTestAuthenticator(Algorithm.ES256), "first");
    register(session, new PasskeyTestAuthenticator(Algorithm.RS256), "second");

    PasskeyRegistrationOptionsDTO options = registrationOptions(session);
    PasskeyRegistrationDTO registration = registrationFor(
        new PasskeyTestAuthenticator(Algorithm.ES256), options.getChallenge(), TEST_ORIGIN, false,
        List.of(), "third");

    mvc
      .perform(post(REGISTRATION_URL).session(session)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(registration)))
      .andExpect(status().isConflict())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.LIMIT_EXCEEDED_MESSAGE)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USER), hasSize(2));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void removingUnknownPasskeyIsNotFound() throws Exception {
    mvc.perform(delete(BASE_URL + "/" + UNKNOWN_UUID))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.error", is(DefaultIamPasskeyService.PASSKEY_NOT_FOUND_MESSAGE)));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER"})
  void usersCannotRemovePasskeysOfOtherAccounts() throws Exception {
    IamPasskey foreign = storedPasskeyFor("admin", new PasskeyTestAuthenticator(Algorithm.ES256));

    mvc.perform(delete(BASE_URL + "/" + foreign.getUuid())).andExpect(status().isNotFound());
    mvc.perform(get(BASE_URL)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));
    assertThat(passkeyRepository.findByUuid(foreign.getUuid()).isPresent(), is(true));
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"PRE_AUTHENTICATED"})
  void authenticationOptionsListRegisteredCredentials() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    storedPasskeyFor(TEST_USER, authenticator);
    MockHttpSession session = new MockHttpSession();

    String body = mvc.perform(post(AUTHENTICATION_OPTIONS_URL).session(session))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    PasskeyAssertionOptionsDTO options = mapper.readValue(body, PasskeyAssertionOptionsDTO.class);

    assertThat(options.getRpId(), equalTo(TEST_RP_ID));
    assertThat(options.getUserVerification(), equalTo("preferred"));
    assertThat(options.getAllowCredentials(), hasSize(1));
    assertThat(options.getAllowCredentials().get(0).getId(),
        equalTo(authenticator.getCredentialIdBase64Url()));
    assertThat(options.getAllowCredentials().get(0).getTransports(), equalTo(List.of("usb")));
    PasskeyChallenge challenge =
        (PasskeyChallenge) session.getAttribute(PasskeyChallenge.SESSION_ATTRIBUTE);
    assertThat(challenge.matches(PasskeyChallenge.Purpose.AUTHENTICATION, TEST_USER), is(true));
    assertThat(PasskeyTestAuthenticator.base64Url(challenge.getValue()),
        equalTo(options.getChallenge()));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void adminCanReadSettingsAndResetPasskeysOfAnAccount() throws Exception {
    MockHttpSession session = new MockHttpSession();
    PasskeyRegistrationOptionsDTO options = registrationOptions(session, "admin");
    // admin registers on its own account, then resets the test user's (empty) passkeys
    PasskeyRegistrationDTO registration = registrationFor(
        new PasskeyTestAuthenticator(Algorithm.ES256), options.getChallenge(), TEST_ORIGIN, false,
        List.of(), "admin key");
    mvc.perform(post(REGISTRATION_URL).session(session).contentType(MediaType.APPLICATION_JSON)
      .content(mapper.writeValueAsString(registration))).andExpect(status().isCreated());

    mvc.perform(get(MULTI_FACTOR_SETTINGS_FOR_ACCOUNT_URL, TEST_USER_UUID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.passkeyActive", is(false)));

    mvc.perform(delete(BASE_URL + "/reset/" + TEST_USER_UUID)).andExpect(status().isNoContent());
    mvc.perform(delete(BASE_URL + "/reset/" + UNKNOWN_UUID)).andExpect(status().isNotFound());

    assertThat(passkeyRepository.findByAccountUsername("admin"), hasSize(1));
    mvc.perform(delete(BASE_URL + "/reset/" + adminUuid())).andExpect(status().isNoContent());
    assertThat(passkeyRepository.findByAccountUsername("admin"), empty());
  }

  private String adminUuid() {
    return passkeyRepository.findByAccountUsername("admin").get(0).getAccount().getUuid();
  }
}
