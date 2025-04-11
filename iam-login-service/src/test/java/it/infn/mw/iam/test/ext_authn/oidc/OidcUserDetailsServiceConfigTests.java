package it.infn.mw.iam.test.ext_authn.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.authn.oidc.service.JustInTimeProvisioningOIDCUserDetailsService;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.config.oidc.OidcConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {IamLoginService.class, OidcConfiguration.class})
@TestPropertySource(properties = {"oidc.jit-account-provisioning.enabled=true",
    "oidc.jit-account-provisioning.trusted-idps=example.org"})
public class OidcUserDetailsServiceConfigTests {

  @Autowired
  private OidcUserDetailsService userDetailsService;

  @Test
  public void testBeanIsJustInTimeProvisioningService() {
    assertThat(userDetailsService).isNotNull();
    assertThat(userDetailsService).isInstanceOf(JustInTimeProvisioningOIDCUserDetailsService.class);
  }
}
