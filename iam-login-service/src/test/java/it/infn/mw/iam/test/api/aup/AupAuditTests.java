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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.audit.events.aup.AupCreatedEvent;
import it.infn.mw.iam.audit.events.aup.AupDeletedEvent;
import it.infn.mw.iam.audit.events.aup.AupSignedEvent;
import it.infn.mw.iam.audit.events.aup.AupUpdatedEvent;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {
    "spring.main.allow-bean-definition-overriding=true",
})
@Transactional
class AupAuditTests extends AupTestSupport {

  static final String UPDATED_AUP_URL = "http://updated-aup.org/";

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  AupConverter converter;

  @Autowired
  ApplicationEventPublisher eventPublisher;

  @Autowired
  MockMvc mvc;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
    eventCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
    reset(eventPublisher);
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupCreationRaisesAupCreatedEvent() throws JsonProcessingException, Exception {

    AupDTO aup = converter.dtoFromEntity(buildDefaultAup(clock.now()));

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    verify(eventPublisher).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AupCreatedEvent.class));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupDeletionRaisesAupDeletedEvent() throws JsonProcessingException, Exception {

    IamAup aup = buildDefaultAup(clock.now());
    aupRepo.saveDefaultAup(aup);

    mvc.perform(delete("/iam/aup")).andExpect(status().isNoContent());

    verify(eventPublisher).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AupDeletedEvent.class));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupUpdateRaisesAupUpdatedEvent() throws JsonProcessingException, Exception {

    IamAup aup = buildDefaultAup(clock.now());
    aupRepo.saveDefaultAup(aup);

    aup.setUrl(UPDATED_AUP_URL);

    // Time travel 1 minute in the future
    clock.advance(Duration.ofMinutes(1L));

    mvc
      .perform(
          patch("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isOk());
    
    verify(eventPublisher).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AupUpdatedEvent.class));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void aupSignatureRaisesAupSignedEvent() throws JsonProcessingException, Exception {

    IamAup aup = buildDefaultAup(clock.now());
    aupRepo.saveDefaultAup(aup);
    
    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());
    verify(eventPublisher).publishEvent(eventCaptor.capture());
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(AupSignedEvent.class));
  }


}
