package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport.DEFAULT_IDP_ID;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.WithMockSAMLUser;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebAppConfiguration
public class ExternalAuthenticationRegistrationTests {

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private ObjectMapper objectMapper;

  private MockMvc mvc;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

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
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON_UTF8)
	.content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    mvc
      .perform(post("/registration/{uuid}/{decision}", request.getUuid(),
	  IamRegistrationRequestStatus.APPROVED)
	    .with(SecurityMockMvcRequestPostProcessors.user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk());

    IamAccount account = accountRepository.findByUsername("test-oidc-subject").get();

    assertNotNull(account);

    assertThat(account.getOidcIds().size(), equalTo(1));
    assertThat(account.getOidcIds().get(0).getSubject(), equalTo("test-oidc-user"));
    assertThat(account.getOidcIds().get(0).getIssuer(), equalTo("test-oidc-issuer"));

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
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON_UTF8)
	.content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    mvc
      .perform(post("/registration/{uuid}/{decision}", request.getUuid(),
	  IamRegistrationRequestStatus.APPROVED)
	    .with(SecurityMockMvcRequestPostProcessors.user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk());

    IamAccount account = accountRepository.findByUsername("test-saml-user").get();

    assertNotNull(account);

    assertThat(account.getSamlIds().size(), equalTo(1));

    assertThat(account.getSamlIds().get(0).getIdpId(), equalTo(DEFAULT_IDP_ID));
    assertThat(account.getSamlIds().get(0).getUserId(), equalTo("test-saml-user"));

    accountRepository.delete(account);
  }


}
