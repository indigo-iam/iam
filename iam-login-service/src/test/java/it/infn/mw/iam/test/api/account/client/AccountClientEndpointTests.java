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
package it.infn.mw.iam.test.api.account.client;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
public class AccountClientEndpointTests {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountClientRepository accountClientRepo;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private ClientDetailsEntity buildNewClient(String clientId) {
    ClientDetailsEntity entity = new ClientDetailsEntity();
    entity.setClientId(clientId);
    entity.setActive(true);
    entity.setClientName(clientId);
    return clientRepo.save(entity);
  }

  private IamAccountClient addNewClientFor(IamAccount a, ClientDetailsEntity c) {
    IamAccountClient accountClient = new IamAccountClient();
    accountClient.setAccount(a);
    accountClient.setClient(c);
    accountClient.setCreationTime(new Date());
    return accountClientRepo.save(accountClient);
  }

  private void getMyClientsWorksForAdmins() throws Exception {
    mvc.perform(get("/iam/account/me/clients"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.Resources", is(empty())));

    IamAccount admin = accountRepo.findByUsername("admin").orElseThrow();
    ClientDetailsEntity clientAdmin = buildNewClient("client-admin");
    IamAccountClient accountClientAdmin = addNewClientFor(admin, clientAdmin);

    mvc.perform(get("/iam/account/me/clients"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources", not(empty())))
      .andExpect(jsonPath("$.Resources[0].client_id", is("client-admin")));

    IamAccount test = accountRepo.findByUsername("test").orElseThrow();
    ClientDetailsEntity clientTest = buildNewClient("client-test");
    IamAccountClient accountClientTest = addNewClientFor(test, clientTest);

    mvc.perform(get("/iam/account/me/clients"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources", not(empty())))
      .andExpect(jsonPath("$.Resources[0].client_id", is("client-admin")));

    accountClientRepo.delete(accountClientAdmin);
    accountClientRepo.delete(accountClientTest);
    clientRepo.delete(clientAdmin);
    clientRepo.delete(clientTest);
  }
  

  @Test
  public void anonymousAccessToMyClientsEndpointFailsTest() throws Exception {
    mvc.perform(get("/iam/account/me/clients"))
      .andDo(print())
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void myClientsWorksForAdminsTest() throws Exception {
    getMyClientsWorksForAdmins();
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN", "ROLE_USER"})
  public void myClientsWorksForAdminsWithTokenTest() throws Exception {
    getMyClientsWorksForAdmins();
  }

  private void getClientsForAccountWorksForAdmins() throws Exception {
    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    ClientDetailsEntity testClient = buildNewClient("client-test");
    IamAccountClient accountClient = addNewClientFor(testAccount, testClient);

    try {
      mvc.perform(get("/iam/account/{id}/clients", testAccount.getUuid()))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.totalResults", is(1)))
          .andExpect(jsonPath("$.Resources", not(empty())))
          .andExpect(jsonPath("$.Resources[0].client_id", is("client-test")));
    } finally {
      accountClientRepo.delete(accountClient);
      clientRepo.delete(testClient);
    }
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void getClientsForAccountWorksForAdminsTest() throws Exception {
    getClientsForAccountWorksForAdmins();
  }

  @Test
  public void anonymousAccessToClientsOwnedByAccountEndpointFailsTest() throws Exception {
    mvc.perform(get("/iam/account/{id}/clients", "VALID_ID"))
      .andDo(print())
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"})
  public void nonAdminAccessToClientsOwnedByAccountEndpointFailsTest() throws Exception {
    mvc.perform(get("/iam/account/{id}/clients", "VALID_ID"))
      .andDo(print())
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "test", authorities = {"ROLE_USER"})
  public void userAccessToClientsOwnedByUserEndpointSuccessTest() throws Exception {
    IamAccount testAccount = accountRepo.findByUsername("test").orElseThrow();
    mvc.perform(get("/iam/account/{id}/clients", testAccount.getUuid()))
      .andDo(print())
      .andExpect(status().isOk());
  }
}
