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
package it.infn.mw.iam.test.api.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.springframework.data.domain.Pageable;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ClientOwnerConcurrencyTests {

  static final String OWNERS_RESOURCE = "/iam/api/clients/{clientId}/owners";
  static final String OWNER_RESOURCE = "/iam/api/clients/{clientId}/owners/{accountId}";

  static final String CLIENT_ID = "client";

  static final List<String> USERS = List.of("test_100", "test_101", "test_102", "test_103");

  @Autowired
  MockMvc mvc;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  IamAccountClientRepository accountClientRepo;

  @Autowired
  ClientService clientService;

  @Autowired
  PlatformTransactionManager transactionManager;

  TransactionTemplate tx;
  List<Long> originalOwners;
  Map<String, String> uuids = new HashMap<>();

  @BeforeEach
  void setup() {
    tx = new TransactionTemplate(transactionManager);

    tx.executeWithoutResult(s -> {
      originalOwners = owners().stream().map(o -> o.getAccount().getId()).toList();
      USERS.forEach(u -> uuids.put(u, accountRepo.findByUsername(u).orElseThrow().getUuid()));
    });
  }

  @AfterEach
  void teardown() {
    tx.executeWithoutResult(s -> {
      accountClientRepo.deleteByClientId(client().getId());
      originalOwners.forEach(id -> clientService.linkClientToAccount(client(),
          accountRepo.findById(id).orElseThrow()));
    });
  }

  private ClientDetailsEntity client() {
    return clientRepo.findByClientId(CLIENT_ID).orElseThrow();
  }

  private List<IamAccountClient> owners() {
    return accountClientRepo.findByClientClientId(CLIENT_ID, Pageable.unpaged()).getContent();
  }

  private List<String> ownerUsernames() {
    return tx.execute(
        s -> owners().stream().map(o -> o.getAccount().getUsername()).toList());
  }

  private void setOwners(String... usernames) {
    tx.executeWithoutResult(s -> {
      accountClientRepo.deleteByClientId(client().getId());
      Arrays.stream(usernames)
        .forEach(u -> clientService.linkClientToAccount(client(),
            accountRepo.findByUsername(u).orElseThrow()));
    });
  }

  private MockHttpSession login(String username) throws Exception {
    MockHttpSession session =
        (MockHttpSession) mvc.perform(get("/login")).andReturn().getRequest().getSession();

    return (MockHttpSession) mvc
      .perform(post("/login").with(csrf().asHeader())
        .param("username", username)
        .param("password", "password")
        .param("submit", "Login")
        .session(session))
      .andReturn()
      .getRequest()
      .getSession();
  }

  private Callable<Integer> request(String caller, MockHttpServletRequestBuilder request)
      throws Exception {
    MockHttpSession session = login(caller);
    return () -> mvc.perform(request.session(session).with(csrf().asHeader()))
      .andReturn()
      .getResponse()
      .getStatus();
  }

  private Callable<Integer> remove(String caller, String owner) throws Exception {
    return request(caller, delete(OWNER_RESOURCE, CLIENT_ID, uuids.get(owner)));
  }

  private Callable<Integer> add(String caller, String owner) throws Exception {
    return request(caller, post(OWNER_RESOURCE, CLIENT_ID, uuids.get(owner)));
  }

  private Callable<Integer> addByUsername(String caller, String owner) throws Exception {
    return request(caller, post(OWNERS_RESOURCE, CLIENT_ID).param("username", owner));
  }

  private List<Integer> runConcurrently(List<Callable<Integer>> tasks) throws Exception {

    ExecutorService executor = Executors.newFixedThreadPool(tasks.size());
    CountDownLatch start = new CountDownLatch(1);

    try {
      List<Future<Integer>> futures = new ArrayList<>();
      for (Callable<Integer> task : tasks) {
        futures.add(executor.submit(() -> {
          start.await();
          return task.call();
        }));
      }
      start.countDown();

      List<Integer> results = new ArrayList<>();
      for (Future<Integer> future : futures) {
        results.add(future.get(60, TimeUnit.SECONDS));
      }
      return results;
    } finally {
      executor.shutdownNow();
    }
  }

  @RepeatedTest(3)
  void ownersLeavingAtTheSameTimeLeaveOneOwner() throws Exception {

    setOwners("test_100", "test_101");

    List<Integer> results = runConcurrently(
        List.of(remove("test_100", "test_100"), remove("test_101", "test_101")));

    assertThat(results, containsInAnyOrder(204, 400));
    assertThat(ownerUsernames(), hasSize(1));
  }

  @RepeatedTest(3)
  void removedOwnersCannotAddOwners() throws Exception {

    setOwners("test_100", "test_101");

    List<Integer> results = runConcurrently(
        List.of(remove("test_100", "test_101"), add("test_101", "test_102")));

    List<String> owners = ownerUsernames();

    assertThat(results.get(0), is(204));
    assertThat(results.get(1), anyOf(is(201), is(403)));
    assertThat(owners.contains("test_102"), is(results.get(1) == 201));
    assertThat(owners.contains("test_101"), is(false));
  }

  @RepeatedTest(3)
  void concurrentAdditionsOfTheSameOwnerLinkItOnce() throws Exception {

    setOwners("test_100", "test_101");

    List<Integer> results = runConcurrently(
        List.of(add("test_100", "test_102"), add("test_101", "test_102"),
            addByUsername("test_100", "test_102"), addByUsername("test_101", "test_102")));

    assertThat(results, everyItem(is(201)));
    assertThat(ownerUsernames(), containsInAnyOrder("test_100", "test_101", "test_102"));
  }

}
