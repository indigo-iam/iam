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
package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.WithMockSAMLUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class ExternalAuthenticationRegistrationTests {

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private MockMvc mvc;

  @Test
  @WithMockOIDCUser
  public void testExtAuthOIDC() throws JsonProcessingException, Exception {

    String username = "test-oidc-subject";

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    byte[] requestBytes = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    mvc
      .perform(post("/registration/approve/{uuid}", request.getUuid())
        .with(SecurityMockMvcRequestPostProcessors.user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk());

    IamAccount account = accountRepository.findByUsername("test-oidc-subject").get();

    assertNotNull(account);

    assertThat(account.getOidcIds().size(), equalTo(1));

    IamOidcId id = new IamOidcId("test-oidc-issuer", "test-oidc-user");
    assertThat(account.getOidcIds(), hasItem(id));
    assertThat(account.getOidcIds(), hasItem(id));

    accountRepository.delete(account);
  }

  @Test
  @WithMockSAMLUser
  public void testExtAuthSAML() throws JsonProcessingException, Exception {

    String username = "test-saml-user";

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("Saml User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    byte[] requestBytes = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    mvc
      .perform(post("/registration/approve/{uuid}", request.getUuid())
        .with(SecurityMockMvcRequestPostProcessors.user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk());

    IamAccount account = accountRepository.findByUsername("test-saml-user").get();

    assertNotNull(account);

    assertThat(account.getSamlIds().size(), equalTo(1));

    IamSamlId firstSamlId = account.getSamlIds().iterator().next();
    assertThat(firstSamlId.getIdpId(), equalTo(DEFAULT_IDP_ID));
    assertThat(firstSamlId.getUserId(), equalTo("test-saml-user"));

    accountRepository.delete(account);
  }


}
