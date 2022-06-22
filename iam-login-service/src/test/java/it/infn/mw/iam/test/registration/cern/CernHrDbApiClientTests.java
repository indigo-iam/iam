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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withUnauthorizedRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.ErrorDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CernHrDbApiClientTests.TestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"cern.hr-api.username=" + CernTestSupport.HR_API_USERNAME,
    "cern.hr-api.password=" + CernTestSupport.HR_API_PASSWORD,
    "cern.hr-api.url=" + CernTestSupport.HR_API_URL,
    "cern.experiment-name=" + CernTestSupport.EXPERIMENT_NAME, "cern.task.enabled=false"})
@ActiveProfiles({"h2-test", "cern"})
public class CernHrDbApiClientTests extends CernTestSupport {

  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    public RestTemplateFactory mockRestTemplateFactory() {
      return new MockRestTemplateFactory();
    }
  }

  @Autowired
  private RestTemplateFactory rtf;

  @Autowired
  private ObjectMapper mapper;

  private MockRestTemplateFactory mockRtf;

  @Autowired
  private CernHrDBApiService hrDbService;

  @Before
  public void setup() {
    mockRtf = (MockRestTemplateFactory) rtf;
    mockRtf.resetTemplate();
  }

  @Test
  public void checkMembershipSuccess() {
    String personId = "12356789";
    String apiValidationUrl = apiValidationUrl(personId);
    mockRtf.getMockServer()
      .expect(requestTo(apiValidationUrl))
      .andExpect(method(GET))
      .andExpect(header("Authorization", BASIC_AUTH_HEADER_VALUE))
      .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body("true"));

    assertThat(hrDbService.hasValidExperimentParticipation(personId), is(true));
  }

  @Test
  public void checkMembershipFailure() {
    String personId = "12356789";
    String apiValidationUrl = apiValidationUrl(personId);
    mockRtf.getMockServer()
      .expect(requestTo(apiValidationUrl))
      .andExpect(method(GET))
      .andExpect(header("Authorization", BASIC_AUTH_HEADER_VALUE))
      .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body("false"));

    assertThat(hrDbService.hasValidExperimentParticipation(personId), is(false));
  }

  @Test(expected = CernHrDbApiError.class)
  public void checkAuthorizationError() {
    String personId = "12356789";
    String apiValidationUrl = apiValidationUrl(personId);
    mockRtf.getMockServer()
      .expect(requestTo(apiValidationUrl))
      .andExpect(method(GET))
      .andExpect(header("Authorization", BASIC_AUTH_HEADER_VALUE))
      .andRespond(withUnauthorizedRequest());
    try {
      hrDbService.hasValidExperimentParticipation(personId);
    } catch (CernHrDbApiError e) {
      assertThat(e.getMessage(), containsString("401"));
      throw e;
    }
  }

  @Test
  public void checkPersonRecord() throws JsonProcessingException {
    String personId = "12356789";
    String voPersonUrl = voPersonUrl(personId);
    mockRtf.getMockServer()
      .expect(requestTo(voPersonUrl))
      .andExpect(method(GET))
      .andExpect(header("Authorization", BASIC_AUTH_HEADER_VALUE))
      .andRespond(withStatus(OK).contentType(APPLICATION_JSON)
        .body(mapper.writeValueAsString(mockHrUser(personId))));

    VOPersonDTO user = hrDbService.getHrDbPersonRecord(personId);
    assertThat(user.getFirstName(), is(MOCK_HR_USER_FIRST_NAME));
    assertThat(user.getName(), is(MOCK_HR_USER_FAMILY_NAME));
  }

  @Test(expected = CernHrDbApiError.class)
  public void checkErrorPersonRecord() throws JsonProcessingException {
    String personId = "12356789";
    String voPersonUrl = voPersonUrl(personId);
    mockRtf.getMockServer()
      .expect(requestTo(voPersonUrl))
      .andExpect(method(GET))
      .andExpect(header("Authorization", BASIC_AUTH_HEADER_VALUE))
      .andRespond(withStatus(NOT_FOUND).contentType(APPLICATION_JSON)
        .body(mapper.writeValueAsString(ErrorDTO.newError("NOT_FOUND", "User not found"))));

    try {
      hrDbService.getHrDbPersonRecord(personId);
    } catch (CernHrDbApiError e) {
      assertThat(e.getMessage(), startsWith("HR db api error: 404 Not Found"));
      throw e;
    }
  }
}
