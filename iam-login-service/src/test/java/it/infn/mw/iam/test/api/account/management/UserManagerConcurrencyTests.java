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
package it.infn.mw.iam.test.api.account.management;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;

/**
 * Concurrent requests on committed data: nothing here runs in the transaction of the test, so
 * what the tests create is removed by hand.
 */
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class UserManagerConcurrencyTests {

  static final String MANAGER = "test_100";
  static final String CLIENT = "password-grant";
  static final Set<String> EXTRA_SCOPES =
      Set.of("iam:user.read", "iam:user.write", "iam:admin.read", "iam:admin.write");

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  PersistentUUIDTokenGenerator generator;

  @Autowired
  IamAccountService accountService;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamAuthoritiesRepository authoritiesRepo;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  IamEmailNotificationRepository notificationRepo;

  @Autowired
  PlatformTransactionManager transactionManager;

  TransactionTemplate tx;
  Set<String> clientScopes;
  List<String> createdUsernames = new ArrayList<>();

  String manager;
  String admin;

  @BeforeEach
  void setup() throws Exception {
    tx = new TransactionTemplate(transactionManager);

    tx.executeWithoutResult(s -> {
      IamAccount account = accountRepo.findByUsername(MANAGER).orElseThrow();
      account.getAuthorities().add(userManagerRole());
      accountRepo.save(account);

      ClientDetailsEntity client = clientRepo.findByClientId(CLIENT).orElseThrow();
      clientScopes = new HashSet<>(client.getScope());
      Set<String> scopes = new HashSet<>(clientScopes);
      scopes.addAll(EXTRA_SCOPES);
      client.setScope(scopes);
      clientRepo.save(client);
    });

    manager = bearerToken(MANAGER, "openid iam:user.read iam:user.write");
    admin = bearerToken("admin", "openid iam:admin.read iam:admin.write");
  }

  @AfterEach
  void teardown() {
    tx.executeWithoutResult(s -> {
      createdUsernames
        .forEach(u -> accountRepo.findByUsername(u).ifPresent(accountService::deleteAccount));

      IamAccount account = accountRepo.findByUsername(MANAGER).orElseThrow();
      account.getAuthorities().remove(userManagerRole());
      accountRepo.save(account);

      ClientDetailsEntity client = clientRepo.findByClientId(CLIENT).orElseThrow();
      client.setScope(clientScopes);
      clientRepo.save(client);

      accessTokenRepo.deleteAll();
      refreshTokenRepo.deleteAll();
      notificationRepo.deleteAll();
    });
  }

  private IamAuthority userManagerRole() {
    return authoritiesRepo.findByAuthority("ROLE_USER_MANAGER").orElseThrow();
  }

  private String bearerToken(String username, String scope) throws Exception {
    String response = mvc
      .perform(post("/token").with(httpBasic(CLIENT, "secret"))
        .param("grant_type", "password")
        .param("username", username)
        .param("password", "password")
        .param("scope", scope))
      .andReturn()
      .getResponse()
      .getContentAsString();
    return "Bearer " + mapper.readTree(response).path("access_token").asText();
  }

  private String newUsername() {
    String username = "concurrency_" + UUID.randomUUID().toString().substring(0, 8);
    createdUsernames.add(username);
    return username;
  }

  private String createAccount() {
    String username = newUsername();
    return tx.execute(s -> {
      IamAccount account = IamAccount.newAccount();
      account.setUsername(username);
      account.setActive(true);
      account.getUserInfo().setGivenName("Concurrency");
      account.getUserInfo().setFamilyName("Test");
      account.getUserInfo().setEmail(username + "@example.org");
      return accountService.createAccount(account).getUuid();
    });
  }

  private String createConfirmedRegistrationRequest() throws Exception {

    String username = newUsername();
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Concurrency");
    request.setFamilyname("Test");
    request.setEmail(username + "@example.org");
    request.setUsername(username);
    request.setNotes("Some short notes...");

    String response = mvc
      .perform(post("/registration/create").with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andReturn()
      .getResponse()
      .getContentAsString();

    mvc.perform(post("/registration/verify").with(csrf().asHeader())
      .contentType(APPLICATION_FORM_URLENCODED)
      .param("token", generator.getLastToken()));

    return mapper.readValue(response, RegistrationRequestDto.class).getUuid();
  }

  private Callable<Integer> as(String token, MockHttpServletRequestBuilder request) {
    return () -> mvc.perform(request.header(AUTHORIZATION, token))
      .andReturn()
      .getResponse()
      .getStatus();
  }

  private List<Integer> runTogether(List<Callable<Integer>> requests) throws Exception {

    ExecutorService executor = Executors.newFixedThreadPool(requests.size());
    CountDownLatch start = new CountDownLatch(1);

    try {
      List<Future<Integer>> futures = new ArrayList<>();
      for (Callable<Integer> request : requests) {
        futures.add(executor.submit(() -> {
          start.await();
          return request.call();
        }));
      }
      start.countDown();

      List<Integer> statuses = new ArrayList<>();
      for (Future<Integer> future : futures) {
        statuses.add(future.get(60, TimeUnit.SECONDS));
      }
      return statuses;
    } finally {
      executor.shutdownNow();
    }
  }

  private boolean accountExists(String uuid) {
    return tx.execute(s -> accountRepo.findByUuid(uuid).isPresent());
  }

  @RepeatedTest(10)
  void concurrentDisablesAndRemovalsOfAnAccountAreAppliedOnce() throws Exception {

    String uuid = createAccount();

    List<Callable<Integer>> requests = new ArrayList<>();
    for (int i = 0; i < 6; i++) {
      requests.add(as(manager, patch("/iam/account/{id}/disable", uuid)));
    }

    List<Integer> disables = runTogether(requests);

    assertThat(disables, everyItem(is(200)));
    assertThat(tx.execute(s -> accountRepo.findByUuid(uuid).orElseThrow().isActive()), is(false));
    assertThat(tx.execute(s -> notificationRepo.count()), is(1L));

    requests.clear();
    for (int i = 0; i < 6; i++) {
      requests.add(as(manager, delete("/scim/Users/{id}", uuid)));
    }

    List<Integer> removals = runTogether(requests);

    assertThat(removals, everyItem(anyOf(is(204), is(404))));
    assertThat(Collections.frequency(removals, 204), is(1));
    assertThat(accountExists(uuid), is(false));
  }

  @RepeatedTest(20)
  void userManagerNeverRemovesAnAccountThatAnAdministratorHasJustPromoted() throws Exception {

    String uuid = createAccount();

    List<Integer> statuses = runTogether(List.of(
        as(admin, post("/iam/account/{id}/authorities", uuid).param("authority", "ROLE_ADMIN")),
        as(manager, delete("/scim/Users/{id}", uuid))));

    int promotion = statuses.get(0);
    int removal = statuses.get(1);

    if (promotion == 200) {
      assertThat(removal, is(403));
      assertThat(accountExists(uuid), is(true));
    } else {
      assertThat(promotion, is(404));
      assertThat(removal, is(204));
      assertThat(accountExists(uuid), is(false));
    }
  }

  @RepeatedTest(20)
  void concurrentDecisionsOnARegistrationRequestAreAppliedOnce() throws Exception {

    String uuid = createConfirmedRegistrationRequest();
    String username = createdUsernames.get(createdUsernames.size() - 1);

    List<Callable<Integer>> decisions = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      decisions.add(as(manager, post("/registration/approve/{uuid}", uuid)));
      decisions.add(as(manager, post("/registration/reject/{uuid}", uuid)));
    }

    List<Integer> statuses = runTogether(decisions);

    assertThat(statuses, everyItem(anyOf(is(200), is(400), is(404))));
    assertThat(Collections.frequency(statuses, 200), is(1));

    boolean approved = statuses.indexOf(200) % 2 == 0;
    assertThat(tx.execute(s -> accountRepo.findByUsername(username)
      .map(IamAccount::isActive)
      .orElse(false)), is(approved));
  }
}
