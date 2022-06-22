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
package it.infn.mw.iam.test.registration.cern;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.InstituteDTO;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class,
        CernRegistrationValidationServiceTests.TestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@ActiveProfiles({"h2-test", "cern"})
@TestPropertySource(properties = {"cern.task.enabled=false"})
public class CernRegistrationValidationServiceTests {

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    CernHrDBApiService hrDbApi() {
      return mock(CernHrDBApiService.class);
    }
  }

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private CernHrDBApiService hrDbApi;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    reset(hrDbApi);
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  private RegistrationRequestDto createDto(String username) {
    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");
    request.setPassword("password");
    return request;
  }

  private VOPersonDTO mockVoPerson() {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName("TEST");
    dto.setName("USER");
    dto.setEmail("test@hr.cern");
    dto.setId(988211L);
    dto.setParticipations(Sets.newHashSet());

    ParticipationDTO p = new ParticipationDTO();

    p.setExperiment("test");
    p.setStartDate(Date.from(Instant.parse("2020-01-01T00:00:00.00Z")));

    InstituteDTO i = new InstituteDTO();
    i.setId("000001");
    i.setName("INFN");
    i.setCountry("IT");
    i.setTown("Bologna");
    p.setInstitute(i);

    dto.getParticipations().add(p);

    return dto;
  }

  @Test
  @WithAnonymousUser
  public void testAuthenticationIsRequired() throws Exception {

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("error").value("User is not authenticated"));

  }

  @Test
  @WithMockOIDCUser
  public void testCernSSOAuthIsRequired() throws Exception {

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("error", containsString("not authenticated by CERN SSO issuer")));

  }

  @Test
  @WithMockOIDCUser(issuer = "https://auth.cern.ch/auth/realms/cern")
  public void testPersonIdIsRequired() throws Exception {

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("error", containsString("person id claim")));

  }

  @Test
  @WithMockOIDCUser(issuer = "https://auth.cern.ch/auth/realms/cern",
      claims = {"cern_person_id", "988211"})
  public void testHrDbApiErrorIsHandled() throws Exception {
    when(hrDbApi.hasValidExperimentParticipation(anyString()))
      .thenThrow(new CernHrDbApiError("error"));

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("error", containsString("HR Db API error")));

  }

  @Test
  @WithMockOIDCUser(issuer = "https://auth.cern.ch/auth/realms/cern", givenName = "Test",
      familyName = "User", claims = {"cern_person_id", "988211"})
  public void testInvalidRequestIsReported() throws Exception {
    when(hrDbApi.hasValidExperimentParticipation(anyString())).thenReturn(false);

    mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("error", containsString("No valid experiment participation found")));
  }

  @Test
  @WithMockOIDCUser(issuer = "https://auth.cern.ch/auth/realms/cern",
      claims = {"cern_person_id", "988211"})
  public void testLabelIsAddedToRegistrationRequest() throws Exception {
    when(hrDbApi.hasValidExperimentParticipation(anyString())).thenReturn(true);
    when(hrDbApi.getHrDbPersonRecord(anyString())).thenReturn(mockVoPerson());

    String response = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(createDto("test_reg"))))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegistrationRequestDto request = mapper.readValue(response, RegistrationRequestDto.class);

    assertThat(request.getLabels(), notNullValue());
    assertThat(request.getLabels(), hasSize(1));
    assertThat(request.getLabels().get(0).getPrefix(), is("hr.cern"));
    assertThat(request.getLabels().get(0).getName(), is("cern_person_id"));
    assertThat(request.getLabels().get(0).getValue(), is("988211"));
    assertThat(request.getGivenname(), is(mockVoPerson().getFirstName()));
    assertThat(request.getFamilyname(), is(mockVoPerson().getName()));
    assertThat(request.getEmail(), is(mockVoPerson().getEmail()));

    mvc.perform(post("/registration/approve/{uuid}", request.getUuid())
      .with(user("admin").roles("ADMIN", "USER"))).andExpect(status().isOk());

    IamAccount account =
        repo.findByUsername("test_reg").orElseThrow(assertionError("Expected user not found"));

    assertThat(account.getLabels(), hasSize(1));

    Optional<IamLabel> personId =
        account.getLabelByPrefixAndName("hr.cern", "cern_person_id");
    assertThat(personId.isPresent(), is(true));
    assertThat(personId.get().getValue(), is("988211"));
  }

}
