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
package it.infn.mw.iam.test.rcauth;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.client.response.MockRestResponseCreators;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.rcauth.RCAuthCertificateRequestor;
import it.infn.mw.iam.rcauth.RCAuthError;
import it.infn.mw.iam.rcauth.x509.CertificateRequestHolder;
import it.infn.mw.iam.rcauth.x509.CertificateRequestUtil;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, RCAuthTestConfig.class,
        RCAuthCertificateRequestorTests.TestConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(
    properties = {"rcauth.enabled=true", "rcauth.client-id=" + RCAuthTestSupport.CLIENT_ID,
        "rcauth.client-secret=" + RCAuthTestSupport.CLIENT_SECRET,
        "rcauth.issuer=" + RCAuthTestSupport.ISSUER})
public class RCAuthCertificateRequestorTests extends RCAuthTestSupport {


  @TestConfiguration
  public static class TestConfig {
    @Bean
    @Primary
    public RestTemplateFactory mockRestTemplateFactory() {
      return new MockRestTemplateFactory();
    }
  }

  @Autowired
  private RCAuthCertificateRequestor requestor;

  @Autowired
  private RestTemplateFactory rtf;

  private MockRestTemplateFactory mockRtf;

  @Before
  public void setup() {
    mockRtf = (MockRestTemplateFactory) rtf;
    mockRtf.resetTemplate();
  }

  @Test
  public void testGetCertificateSuccess() throws OperatorCreationException, IOException {


    prepareCertificateResponse();
    CertificateRequestHolder rh = CertificateRequestUtil.buildCertificateRequest(DN, 512);
    try {
      requestor.getCertificate(RANDOM_ACCESS_TOKEN, rh);
    } finally {
      verifyMockServerCalls();
    }
  }

  @Test(expected=RCAuthError.class)
  public void testGetCertificateError() throws OperatorCreationException, IOException {
    
    prepareErrorResponse();
    CertificateRequestHolder rh = CertificateRequestUtil.buildCertificateRequest(DN, 512);
    
    try {
      requestor.getCertificate(RANDOM_ACCESS_TOKEN, rh);
    } catch (RCAuthError e) {
      assertThat(e.getMessage(), containsString("500"));
      throw e;
    } finally {
      verifyMockServerCalls();
    }
  }

  public void prepareCertificateResponse() {
    mockRtf.getMockServer()
      .expect(requestTo(GET_CERT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(APPLICATION_FORM_URLENCODED_UTF8_VALUE))
      .andRespond(MockRestResponseCreators.withSuccess(TEST_0_CERT_STRING, MediaType.TEXT_PLAIN));
  }

  public void prepareErrorResponse() {
    mockRtf.getMockServer()
      .expect(requestTo(GET_CERT_URI))
      .andExpect(method(HttpMethod.POST))
      .andExpect(content().contentType(APPLICATION_FORM_URLENCODED_UTF8_VALUE))
      .andRespond(withServerError());
  }


  void verifyMockServerCalls() {
    mockRtf.getMockServer().verify();
    mockRtf.resetTemplate();
  }
}
