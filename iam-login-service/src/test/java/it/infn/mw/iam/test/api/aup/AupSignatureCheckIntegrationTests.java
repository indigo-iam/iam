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
package it.infn.mw.iam.test.api.aup;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.aup.DefaultAupSignatureCheckService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.test.util.MockTimeProvider;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class AupSignatureCheckIntegrationTests extends AupTestSupport {

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAupSignatureRepository signatureRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private AupConverter converter;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private MockTimeProvider mockTimeProvider;

  @Autowired
  private DefaultAupSignatureCheckService service;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void noAupDefinedMeansSignatureNotRequired() {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    assertThat(service.needsAupSignature(testAccount), is(false));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupDefinedSignatureChecksTest() throws JsonProcessingException, Exception {
    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());


    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));


    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(5));

    assertThat(service.needsAupSignature(testAccount), is(true));

    signatureRepo.createSignatureForAccount(testAccount,
        new Date(mockTimeProvider.currentTimeMillis()));

    assertThat(service.needsAupSignature(testAccount), is(false));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(10));

    aup.setUrl("http://updated-aup-text.org/");
    aup.setDescription("Updated AUP desc");

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk());

    assertThat(service.needsAupSignature(testAccount), is(false));

    mvc.perform(post("/iam/aup/touch")).andExpect(status().isOk());

    assertThat(service.needsAupSignature(testAccount), is(true));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.MINUTES.toMillis(20));

    signatureRepo.createSignatureForAccount(testAccount,
        new Date(mockTimeProvider.currentTimeMillis()));

    assertThat(service.needsAupSignature(testAccount), is(false));

    mockTimeProvider.setTime(now.getTime() + TimeUnit.DAYS.toMillis(366));

    assertThat(service.needsAupSignature(testAccount), is(true));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void aupCanAlwaysBeFetchedTest() throws JsonProcessingException, Exception {

    mvc.perform(get("/iam/aup")).andExpect(status().isNotFound());

    AupDTO aup = converter.dtoFromEntity(buildDefaultAup());

    Date now = new Date();
    mockTimeProvider.setTime(now.getTime());

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    mvc.perform(get("/iam/aup")).andExpect(status().isOk());
  }
}
