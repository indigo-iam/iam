package it.infn.mw.iam.test.scim.group;

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static java.lang.String.format;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.transaction.Transactional;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoGroup;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.JacksonUtils;
import it.infn.mw.iam.test.util.WithMockOAuthUser;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@Transactional
public class ScimGroupTests {

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  private MockMvc mvc;
  private ObjectMapper objectMapper;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();
    objectMapper = JacksonUtils.createJacksonObjectMapper();
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateNewChildGroup() throws Exception {

    ScimGroup animals = createGroup("animals");
    assertNotNull(animals);

    ScimGroup mammals = createGroup("mammals", animals);
    assertNotNull(mammals);

    Assert.assertEquals(animals.getId(), mammals.getIndigoGroup().getParentGroup().getValue());
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testCreateGroupWithNotExistingParent() throws Exception {
    String uuid = "fake-group-very-long-uuid";
    ScimGroupRef fakeGroupRef = ScimGroupRef.builder()
      .display("fake group")
      .value(uuid)
      .ref(scimResourceLocationProvider.groupLocation(uuid))
      .build();

    ScimIndigoGroup scimFakeParentGroup =
        new ScimIndigoGroup.Builder().parentGroup(fakeGroupRef).build();

    // @formatter:off
    mvc.perform(post("/scim/Groups")
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(ScimGroup.builder("mammals").indigoGroup(scimFakeParentGroup).build())))
      .andExpect(status().isNotFound())
      .andExpect(jsonPath("$.status", equalTo(NOT_FOUND.toString())))
      .andExpect(jsonPath("$.detail", equalTo(format("Parent group '%s' not found", uuid))));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testDeleteParentGroupWithChildren() throws Exception {
    ScimGroup animals = createGroup("animals");
    createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(delete(animals.getMeta().getLocation()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.status", equalTo(BAD_REQUEST.toString())))
      .andExpect(jsonPath("$.detail", equalTo("Group is not empty")));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testDeleteChildGroup() throws Exception {
    ScimGroup animals = createGroup("animals");
    ScimGroup mammals = createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(delete(mammals.getMeta().getLocation()))
      .andExpect(status().isNoContent());
    // @formatter:on

    // @formatter:off
    mvc.perform(get("/scim/Groups/{id}", animals.getId()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(animals.getId())))
      .andExpect(jsonPath("$.members").doesNotExist());
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testGetParentGroupWithChild() throws Exception {
    ScimGroup animals = createGroup("animals");
    ScimGroup mammals = createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(get("/scim/Groups/{id}", animals.getId()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(animals.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(animals.getDisplayName())))
      .andExpect(jsonPath("$.members[0].display", equalTo(mammals.getDisplayName())))
      .andExpect(jsonPath("$.members[0].value", equalTo(mammals.getId())))
      .andExpect(jsonPath("$.members[0].$ref", equalTo(mammals.getMeta().getLocation())));
    // @formatter:on
  }

  @Test
  @WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
  public void testGetChildGroup() throws Exception {
    ScimGroup animals = createGroup("animals");
    ScimGroup mammals = createGroup("mammals", animals);

    // @formatter:off
    mvc.perform(get("/scim/Groups/{id}", mammals.getId()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(mammals.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(mammals.getDisplayName())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.display", equalTo(animals.getDisplayName())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.value", equalTo(animals.getId())))
      .andExpect(jsonPath("$."+INDIGO_GROUP_SCHEMA+".parentGroup.$ref", equalTo(animals.getMeta().getLocation())));
    // @formatter:on
  }

  private ScimGroup createGroup(String name) throws Exception {
    return createGroup(name, null);
  }

  private ScimGroup createGroup(String name, ScimGroup parent) throws Exception {
    ScimGroup group = ScimGroup.builder(name).build();
    if (parent != null) {
      ScimGroupRef parentGroupRef = ScimGroupRef.builder()
        .display(parent.getDisplayName())
        .value(parent.getId())
        .ref(scimResourceLocationProvider.groupLocation(parent.getId()))
        .build();

      ScimIndigoGroup parentIndigoGroup =
          new ScimIndigoGroup.Builder().parentGroup(parentGroupRef).build();

      group = ScimGroup.builder(name).indigoGroup(parentIndigoGroup).build();
    }

    String response = mvc
      .perform(post("/scim/Groups").contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(group)))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString();

    return objectMapper.readValue(response, ScimGroup.class);
  }

}
