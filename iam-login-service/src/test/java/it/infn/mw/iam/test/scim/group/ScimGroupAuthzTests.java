package it.infn.mw.iam.test.scim.group;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.scim.ScimUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
public class ScimGroupAuthzTests {

  @Autowired
  private MockMvc mvc;

  private final static String GROUP_URI = ScimUtils.getGroupsLocation();
  private final static String USER_URI = ScimUtils.getUsersLocation();

  @Test
  public void testGroupsListRequest() throws Exception {

    mvc.perform(get(GROUP_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("insufficient_scope")))
      .andExpect(jsonPath("$.error_description", equalTo("Insufficient scope for this resource")))
      .andExpect(jsonPath("$.scope", equalTo("scim:read")));
  }

  @Test
  public void testUsersListRequest() throws Exception {

    mvc.perform(get(USER_URI).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isForbidden())
      .andExpect(jsonPath("$.error", equalTo("insufficient_scope")))
      .andExpect(jsonPath("$.error_description", equalTo("Insufficient scope for this resource")))
      .andExpect(jsonPath("$.scope", equalTo("scim:read")));
  }

}
