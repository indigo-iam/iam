/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.test.oauth.jwk;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.text.ParseException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.test.util.oidc.MockRestTemplateFactory;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, JWKCacheSetServiceTests.class})
@WebAppConfiguration
@Transactional
public class JWKCacheSetServiceTests {

  public static final String JWK_URL = "https://iam.example/jwk";
  public static final String JKS_PATH = "oidc/mock_jwk.jks";

  @Bean
  @Primary
  public RestTemplateFactory mockRestTemplateFactory() {
    return new MockRestTemplateFactory();
  }

  @Autowired
  JWKSetCacheService service;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  RestTemplateFactory rtf;

  MockRestTemplateFactory mockRtf;

  @Before
  public void setup() {
    mockRtf = (MockRestTemplateFactory) rtf;
    mockRtf.resetTemplate();
  }

  @Test
  public void testGetJwk() throws JsonProcessingException, JOSEException, ParseException {

    try {
      mockRtf.getMockServer()
        .expect(requestTo(JWK_URL))
        .andRespond(MockRestResponseCreators.withStatus(HttpStatus.NOT_FOUND));

      assertThat(service.getValidator(JWK_URL), nullValue());

      verifyMockServerCalls();

      mockRtf.getMockServer()
        .expect(requestTo(JWK_URL))
        .andRespond(MockRestResponseCreators.withStatus(HttpStatus.NOT_FOUND));

      assertThat(service.getEncrypter(JWK_URL), nullValue());

      verifyMockServerCalls();

      mockRtf.getMockServer()
        .expect(requestTo(JWK_URL))
        .andRespond(withSuccess(new ClassPathResource(JKS_PATH),
            MediaType.APPLICATION_JSON));

      assertThat(service.getValidator(JWK_URL), notNullValue());

      verifyMockServerCalls();

      mockRtf.getMockServer()
        .expect(requestTo(JWK_URL))
        .andRespond(withSuccess(new ClassPathResource(JKS_PATH),
            MediaType.APPLICATION_JSON));

      assertThat(service.getEncrypter(JWK_URL), notNullValue());


    } finally {
      verifyMockServerCalls();
    }
  }

  void verifyMockServerCalls() {
    mockRtf.getMockServer().verify();
    mockRtf.resetTemplate();
  }
}
