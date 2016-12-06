package it.infn.mw.iam.test.ext_authn.account_linking;

import static it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport.DEFAULT_IDP_ID;
import static it.infn.mw.iam.test.ext_authn.saml.SamlExternalAuthenticationTestSupport.T2_EPUID;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isIn;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.UUID;

import javax.transaction.Transactional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
@WebAppConfiguration
@Transactional
public class AccountUnlinkTests {

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  private MockMvc mvc;

  public static final String UNLINKED_ISSUER = UUID.randomUUID().toString();
  public static final String UNLINKED_SUBJECT = UUID.randomUUID().toString();

  public static final String OIDC_LINKED_ISSUER = "urn:test-oidc-issuer";
  public static final String OIDC_LINKED_SUBJECT = "test-user";

  public static final String SAML_LINKED_ISSUER = DEFAULT_IDP_ID;
  public static final String SAML_LINKED_SUBJECT = T2_EPUID;

  public static final IamSamlId UNLINKED_SAML_ID = new IamSamlId(UNLINKED_ISSUER, UNLINKED_SUBJECT);
  public static final IamOidcId UNLINKED_OIDC_ID = new IamOidcId(UNLINKED_ISSUER, UNLINKED_SUBJECT);

  public static final IamSamlId LINKED_SAML_ID =
      new IamSamlId(SAML_LINKED_ISSUER, SAML_LINKED_SUBJECT);

  public static final IamOidcId LINKED_OIDC_ID =
      new IamOidcId(OIDC_LINKED_ISSUER, OIDC_LINKED_SUBJECT);

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  private String accountLinkingResource(ExternalAuthenticationType type) {
    return String.format("/iam/account-linking/%s", type.name());
  }

  private String accountLinkingResourceOidc() {
    return accountLinkingResource(ExternalAuthenticationType.OIDC);
  }

  private String accountLinkingResourceSaml() {
    return accountLinkingResource(ExternalAuthenticationType.SAML);
  }


  @Test
  public void accountUnlinkEndpointFailsForUnauthenticatedUsers() throws Exception {
    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", LINKED_OIDC_ID.getIssuer())
        .param("sub", LINKED_OIDC_ID.getSubject()))
      .andDo(print())
      .andExpect(status().is4xxClientError());

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", LINKED_SAML_ID.getIdpId())
        .param("sub", LINKED_SAML_ID.getUserId()))
      .andDo(print())
      .andExpect(status().is4xxClientError());
  }

  @Test
  @WithMockUser(username = "test")
  public void oidcAccountUnlinkSucceedsSilentlyForUnlinkedAccount() throws Throwable {

    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", UNLINKED_OIDC_ID.getIssuer())
        .param("sub", UNLINKED_OIDC_ID.getSubject())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(user.getOidcIds(), not(containsInAnyOrder(UNLINKED_OIDC_ID)));
    assertThat(lastUpdateTime, equalTo(user.getLastUpdateTime()));
  }

  @Test
  @WithMockUser(username = "test")
  public void oidcAccountUnlinkWorks() throws Throwable {


    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    assertThat(LINKED_OIDC_ID, isIn(user.getOidcIds()));

    mvc
      .perform(delete(accountLinkingResourceOidc()).param("iss", LINKED_OIDC_ID.getIssuer())
        .param("sub", LINKED_OIDC_ID.getSubject())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(LINKED_OIDC_ID, not(isIn(user.getOidcIds())));
    assertThat(user.getLastUpdateTime(), not(equalTo(lastUpdateTime)));

    // add it back, or other tests may break
    LINKED_OIDC_ID.setAccount(user);
    user.getOidcIds().add(LINKED_OIDC_ID);
    iamAccountRepo.save(user);
  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountUnlinkSucceedsSilentlyForUnlinkedAccount() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", UNLINKED_SAML_ID.getIdpId())
        .param("sub", UNLINKED_SAML_ID.getUserId())
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    assertThat(UNLINKED_SAML_ID, not(isIn(user.getSamlIds())));
    assertThat(lastUpdateTime, equalTo(user.getLastUpdateTime()));

  }

  @Test
  @WithMockUser(username = "test")
  public void samlAccountUnlinkWorks() throws Exception {
    IamAccount user = iamAccountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected user not found"));

    assertThat(LINKED_SAML_ID, isIn(user.getSamlIds()));

    Date lastUpdateTime = user.getLastUpdateTime();

    mvc
      .perform(delete(accountLinkingResourceSaml()).param("iss", SAML_LINKED_ISSUER)
        .param("sub", SAML_LINKED_SUBJECT)
        .with(csrf().asHeader()))
      .andDo(print()).andExpect(status().isNoContent());

    assertThat(LINKED_SAML_ID, not(isIn(user.getSamlIds())));
    assertThat(lastUpdateTime, not(equalTo(user.getLastUpdateTime())));

    // add it back, or other tests may break
    LINKED_SAML_ID.setAccount(user);
    user.getSamlIds().add(LINKED_SAML_ID);
    iamAccountRepo.save(user);

  }

}
