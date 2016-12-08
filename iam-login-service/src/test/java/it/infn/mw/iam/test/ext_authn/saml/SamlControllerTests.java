package it.infn.mw.iam.test.ext_authn.saml;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, SamlTestConfig.class})
@WebAppConfiguration
public class SamlControllerTests extends SamlExternalAuthenticationTestSupport {

  @Test
  public void testListIdpsMatch() throws Exception {
    mvc.perform(get("/saml/idps").param("q", "test"))
      .andExpect(status().isOk())
      .andExpect(MockMvcResultMatchers.jsonPath("$[0].entityId",
          Matchers.equalTo("https://idptestbed/idp/shibboleth")));

  }


  @Test
  public void testListIdpsNoMatch() throws Exception {
    mvc.perform(get("/saml/idps").param("q", "not-found"))
      .andExpect(status().isOk())
      .andExpect(content().string("[]"));

  }

}
