package it.infn.mw.iam.test.multi_factor_authentication;

import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;

import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class MfaVerifyControllerTests extends MultiFactorTestSupport {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext context;

  @MockBean
  private IamAccountRepository accountRepo;

  @InjectMocks
  MfaVerifyController controller;

  @Before
  public void setup() {
    when(accountRepo.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(TEST_ACCOUNT));

    mvc =
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
  }

  @After
  public void tearDown() {
    reset(accountRepo);
  }

  @Test
  @WithMockPreAuthenticatedUser(username = TEST_USERNAME)
  public void testGetMfaVerifyView() throws Exception {
    mvc.perform(get(MfaVerifyController.MFA_VERIFY_URL))
      .andExpect(status().isOk())
      .andExpect(model().attributeExists("factors"));
  }

  @Test
  @WithAnonymousUser
  public void testGetMfaVerifyViewNoAuthenticationIsUnauthorized() throws Exception {
    mvc.perform(get(MfaVerifyController.MFA_VERIFY_URL)).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", authorities = {"USER"})
  public void testGetMfaVerifyViewWithFullAuthenticationIsForbidden() throws Exception {
    mvc.perform(get(MfaVerifyController.MFA_VERIFY_URL)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockPreAuthenticatedUser(username = "bad_user")
  public void testGetMfaVerifyViewWhenUserNotFoundIsBadRequest() throws Exception {
    mvc.perform(get(MfaVerifyController.MFA_VERIFY_URL)).andExpect(status().isBadRequest());
  }
}
