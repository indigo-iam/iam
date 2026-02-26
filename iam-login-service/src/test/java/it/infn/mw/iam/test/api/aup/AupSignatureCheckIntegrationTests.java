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

import static it.infn.mw.iam.core.web.aup.EnforceAupFilter.REQUESTING_SIGNATURE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.service.aup.DefaultAupSignatureCheckService;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.ClockedHttpSession;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@WithAnonymousUser
@TestPropertySource(properties = {"logging.level.root=DEBUG",
        "logging.level.it.infn.mw.iam.core.web.aup.EnforceAupFilter=DEBUG"
})
class AupSignatureCheckIntegrationTests extends AupTestSupport {

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAupSignatureRepository signatureRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  AupConverter converter;

  @Autowired
  DefaultAupSignatureCheckService service;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MockMvc mvc;

  @Autowired
  MutableClock clock;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  @Test
  void noAupDefinedMeansSignatureNotRequired() {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    assertThat(service.needsAupSignature(testAccount), is(false));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupDefinedSignatureChecksTest() throws JsonProcessingException, Exception {

    IamAup defaultAup = buildDefaultAup(clock.now());
    aupRepo.save(defaultAup);
    AupDTO aup = converter.dtoFromEntity(defaultAup);

    IamAccount testAccount = accountRepo.findByUsername(TEST_USERNAME)
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    clock.advance(Duration.ofMillis(5L));

    assertThat(service.needsAupSignature(testAccount), is(true));

    signatureRepo.createSignatureForAccount(defaultAup, testAccount, clock.now());

    assertThat(service.needsAupSignature(testAccount), is(false));

    clock.advance(Duration.ofMillis(10L));

    aup.setUrl("http://updated-aup-text.org/");
    aup.setDescription("Updated AUP desc");

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk());

    assertThat(service.needsAupSignature(testAccount), is(false));

    mvc.perform(post("/iam/aup/touch")).andExpect(status().isOk());

    assertThat(service.needsAupSignature(testAccount), is(true));

    clock.advance(Duration.ofMillis(20L));

    signatureRepo.createSignatureForAccount(defaultAup, testAccount, clock.now());

    assertThat(service.needsAupSignature(testAccount), is(false));

    clock.advance(Duration.ofDays(366L));

    assertThat(service.needsAupSignature(testAccount), is(true));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupCanAlwaysBeFetchedTest() throws JsonProcessingException, Exception {

    mvc.perform(get("/iam/aup")).andExpect(status().isNotFound());

    AupDTO aup = converter.dtoFromEntity(buildDefaultAup(clock.now()));

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    mvc.perform(get("/iam/aup")).andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void testWhenNoDefaultAupNoRedirection() throws Exception {

    mvc.perform(get("/dashboard"))
        .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void testWhenSessionNeedsAupThenRedirection() throws Exception {

    IamAup defaultAup = buildDefaultAup(clock.now());
    aupRepo.save(defaultAup);

    MockHttpSession session = new MockHttpSession();
    session.setAttribute(REQUESTING_SIGNATURE, Boolean.TRUE);

    mvc.perform(get("/dashboard")
        .session(session))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/iam/aup/sign"))
        .andExpect(header().doesNotExist("Set-Cookie"));
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void testNeedsSignatureAndSessionOlderThanAupCreationThenRedirection() throws Exception {

    IamAup defaultAup = buildDefaultAup(clock.now());
    aupRepo.save(defaultAup);

    ClockedHttpSession session =
        new ClockedHttpSession(clock.instant().plusMillis(100).toEpochMilli());

    mvc.perform(get("/dashboard")
        .session(session))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/iam/aup/sign"))
        .andExpect(header().doesNotExist("Set-Cookie"));
  }
}
