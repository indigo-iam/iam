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
package it.infn.mw.iam.test.repository.client;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.hasClientIdLike;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.hasClientNameLike;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.hasContactLike;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.hasScopeLike;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.orm.jpa.JpaSystemException;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.client.service.ClientDefaultsService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.ClientSpecs;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@IamNoMvcTest
public class ClientRepositoryTests extends ClientRepositoryTestsSupport {


  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private IamAccountClientRepository accountClientRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private OAuth2ClientRepository mitreClientRepo;

  @Autowired
  private Clock clock;

  @Autowired
  private ClientDefaultsService defaultsService;

  @Autowired
  private EntityManager em;

  private IamAccountClient linkClientToAccount(ClientDetailsEntity client, IamAccount account) {
    IamAccountClient ac = new IamAccountClient();
    ac.setCreationTime(Date.from(clock.instant()));
    ac.setAccount(account);
    ac.setClient(client);
    return accountClientRepo.save(ac);
  }

  @Test
  public void testBasicClientOps() {

    ClientDetailsEntity testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER).orElseThrow();

    Page<ClientDetailsEntity> page =
        accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.isEmpty(), is(true));

    linkClientToAccount(testClient, testAccount);

    page = accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.getSize(), is(1));
    assertThat(page.getContent().get(0).getClientId(), is(TEST_CLIENT_CLIENT_ID));

    accountClientRepo.deleteByAccountAndClientId(testAccount, testClient.getId());

    page = accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.isEmpty(), is(true));

    testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();

  }


  @Test
  public void testMultipleLinkRaiseReferentialIntegrityError() {

    JpaSystemException exception = assertThrows(JpaSystemException.class, () -> {
      ClientDetailsEntity testClient =
          clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();

      IamAccount testAccount = accountRepo.findByUsername(TEST_USER).orElseThrow();

      Page<ClientDetailsEntity> page =
          accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

      assertThat(page.isEmpty(), is(true));

      linkClientToAccount(testClient, testAccount);
      linkClientToAccount(testClient, testAccount);
      linkClientToAccount(testClient, testAccount);

      page = accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    });

    assertThat(exception.getMessage(),
        anyOf(containsString("Unique index or primary key violation"),
            containsString("Duplicate entry")));

  }

  @Test
  public void accountCanOwnMultipleClients() {

    ClientDetailsEntity testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();
    ClientDetailsEntity passwordGrantClient =
        clientRepo.findByClientId(PASSWORD_GRANT_CLIENT_ID).orElseThrow();

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER).orElseThrow();

    Page<ClientDetailsEntity> page =
        accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.isEmpty(), is(true));
    linkClientToAccount(testClient, testAccount);
    linkClientToAccount(passwordGrantClient, testAccount);

    page = accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.getSize(), is(2));
    assertThat(page.getContent(), hasItems(testClient, passwordGrantClient));

    accountClientRepo.deleteByAccountAndClientId(testAccount, testClient.getId());

    page = accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(page.getSize(), is(1));
    assertThat(page.getContent(), hasItem(passwordGrantClient));

  }

  @Test
  public void clientCanBeOwnedByMultipleAccounts() {

    ClientDetailsEntity testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();
    ClientDetailsEntity passwordGrantClient =
        clientRepo.findByClientId(PASSWORD_GRANT_CLIENT_ID).orElseThrow();

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER).orElseThrow();
    IamAccount test100Account = accountRepo.findByUsername(TEST_100_USER).orElseThrow();

    assertThat(accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged()).isEmpty(),
        is(true));
    assertThat(accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged()).isEmpty(),
        is(true));

    linkClientToAccount(passwordGrantClient, testAccount);
    linkClientToAccount(testClient, testAccount);
    linkClientToAccount(testClient, test100Account);

    Page<ClientDetailsEntity> testAccountClients =
        accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(testAccountClients.getSize(), is(2));
    assertThat(testAccountClients.getContent(), hasItem(testClient));

    Page<ClientDetailsEntity> test001Clients =
        accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged());

    assertThat(test001Clients.getSize(), is(1));
    assertThat(test001Clients.getContent(), hasItem(testClient));


  }

  @Test
  public void accountDeletionHandledGracefully() {
    ClientDetailsEntity testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();
    IamAccount test100Account = accountRepo.findByUsername(TEST_100_USER).orElseThrow();

    linkClientToAccount(testClient, test100Account);

    Page<ClientDetailsEntity> test100Clients =
        accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged());

    assertThat(test100Clients.getSize(), is(1));
    assertThat(test100Clients.getContent(), hasItem(testClient));

    accountService.deleteAccount(test100Account);

    assertThat(accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged()).isEmpty(),
        is(true));

    assertTrue(clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).isPresent());
  }

  @Test
  public void clientDeletionHandledGracefully() {

    ClientDetailsEntity testClient = clientRepo.findByClientId(TEST_CLIENT_CLIENT_ID).orElseThrow();

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER).orElseThrow();
    IamAccount test100Account = accountRepo.findByUsername(TEST_100_USER).orElseThrow();

    assertThat(accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged()).isEmpty(),
        is(true));
    assertThat(accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged()).isEmpty(),
        is(true));

    linkClientToAccount(testClient, testAccount);
    linkClientToAccount(testClient, test100Account);

    Page<ClientDetailsEntity> testAccountClients =
        accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged());

    assertThat(testAccountClients.getSize(), is(1));
    assertThat(testAccountClients.getContent(), hasItem(testClient));

    Page<ClientDetailsEntity> test001Clients =
        accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged());

    assertThat(test001Clients.getSize(), is(1));
    assertThat(test001Clients.getContent(), hasItem(testClient));

    mitreClientRepo.deleteClient(testClient);

    assertThat(accountClientRepo.findClientByAccount(testAccount, Pageable.unpaged()).isEmpty(),
        is(true));
    assertThat(accountClientRepo.findClientByAccount(test100Account, Pageable.unpaged()).isEmpty(),
        is(true));
  }


  @Test
  public void testClientSearchWorkAsExpected() {
    ClientDetailsEntity client0 = new ClientDetailsEntity();
    client0.setContacts(Sets.newHashSet("first@example.net"));
    client0.setGrantTypes(Sets.newHashSet("client_credentials"));
    client0.setClientName("first");

    defaultsService.setupClientDefaults(client0);

    ClientDetailsEntity client1 = new ClientDetailsEntity();
    client1.setContacts(Sets.newHashSet("second@example.net"));
    client1.setGrantTypes(Sets.newHashSet("client_credentials"));
    client1.setClientName("second");
    client1.setClientId("second");

    defaultsService.setupClientDefaults(client1);

    ClientDetailsEntity client2 = new ClientDetailsEntity();
    client2.setContacts(Sets.newHashSet("test@infn.it"));
    client2.setGrantTypes(Sets.newHashSet("client_credentials", "authorization_code"));
    client2.setRedirectUris(newHashSet("https://example.org/cb"));
    client2.setClientName("third");
    client2.setClientId("third");
    client2.setScope(newHashSet("third_scope"));

    defaultsService.setupClientDefaults(client2);

    client0 = clientRepo.save(client0);
    client1 = clientRepo.save(client1);
    client2 = clientRepo.save(client2);

    em.flush();

    List<ClientDetailsEntity> result = clientRepo.findAll(hasClientNameLike("fir"));
    assertThat(result, hasSize(1));
    assertThat(result.get(0).getClientId(), is(client0.getClientId()));
    
    result = clientRepo.findAll(hasClientNameLike("fir").or(hasClientIdLike("seco")));
    assertThat(result, hasSize(2));
    assertThat(result, hasItems(client0, client1));

    result = clientRepo.findAll(hasContactLike("example.net"));
    assertThat(result, hasSize(2));
    assertThat(result, hasItems(client0, client1));

    result = clientRepo.findAll(hasContactLike("infn.it"));
    assertThat(result, hasSize(1));
    assertThat(result, hasItem(client2));

    result = clientRepo.findAll(hasScopeLike("third_scope"));
    assertThat(result, hasSize(1));
    assertThat(result, hasItem(client2));

    result = clientRepo.findAll(ClientSpecs.hasRedirectUriLike("example.org"));
    assertThat(result, hasSize(1));
    assertThat(result, hasItem(client2));

  }

}
