package it.infn.mw.iam.test.actuator;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
public class ActuatorEndpointsWithTokenAuthTests {

  private static final String ADMIN_USERNAME = "admin";
  private static final String ADMIN_AUTORITY = "ROLE_ADMIN";

  private static final String STATUS_UP = "UP";

  private static final Set<String> SENSITIVE_ENDPOINTS = Sets.newHashSet("/metrics", "/configprops",
      "/env", "/mappings", "/flyway", "/autoconfig", "/beans", "/dump", "/trace");

  @Value("${spring.mail.host}")
  private String mailHost;

  @Value("${spring.mail.port}")
  private Integer mailPort;

  @Autowired
  private WebApplicationContext context;

  private MockMvc mvc;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred", scopes = {"read-tasks", "write-tasks"})
  public void testHealthEndpointWithToken() throws Exception {
    // @formatter:off
    mvc.perform(get("/health"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.db").doesNotExist())
      .andExpect(jsonPath("$.diskSpace").doesNotExist())
      ;
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred",
      scopes = {"openid", "profile", "read-tasks", "write-tasks"}, user = ADMIN_USERNAME,
      authorities = {ADMIN_AUTORITY})
  public void testHealthEndpointWithTokenAsAdmin() throws Exception {
    // @formatter:off
    mvc.perform(get("/health"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.diskSpace.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.db.status", equalTo(STATUS_UP)))
      .andExpect(jsonPath("$.mail").doesNotExist())
      ;
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred",
      scopes = {"openid", "profile", "read-tasks", "write-tasks"})
  public void testSensitiveEndpointWithTokenAsUser() throws Exception {
    for (String endpoint : SENSITIVE_ENDPOINTS) {
      // @formatter:off
      mvc.perform(get(endpoint))
        .andExpect(status().isForbidden())
        ;
      // @formatter:on
    }
  }

  @Test
  @WithMockOAuthUser(clientId = "client-cred",
      scopes = {"openid", "profile", "read-tasks", "write-tasks"}, user = ADMIN_USERNAME,
      authorities = {ADMIN_AUTORITY})
  public void testSensitiveEndpointWithTokenAsAdmin() throws Exception {
    for (String endpoint : SENSITIVE_ENDPOINTS) {
      // @formatter:off
      mvc.perform(get(endpoint))
        .andExpect(status().isOk())
        ;
      // @formatter:on
    }
  }
}
