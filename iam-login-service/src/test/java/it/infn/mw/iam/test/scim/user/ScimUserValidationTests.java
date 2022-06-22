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
package it.infn.mw.iam.test.scim.user;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CLIENT_ID;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_READ_SCOPE;
import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_WRITE_SCOPE;
import static org.apache.commons.lang.RandomStringUtils.random;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, CoreControllerTestSupport.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@WithMockOAuthUser(clientId = SCIM_CLIENT_ID, scopes = {SCIM_READ_SCOPE, SCIM_WRITE_SCOPE})
public class ScimUserValidationTests extends ScimUserTestSupport {

  @Autowired
  private ScimRestUtilsMvc scimUtils;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private final String PICTURE_INVALID_URL =
      "https://iam.local.io/\"</script><script>alert(8);</script>";

  private final String VALID_STRING = "This is a' vàlid strìng";
  private final String INVALID_STRING = "</script><script>alert(8);</script>";

  private final String STRING_65 = random(65, true, false);
  private final String STRING_64 = random(64, true, false);
  private final String STRING_2 = random(2, true, false);
  private final String STRING_1 = "A";

  private final String[] VALID_EMAILS = {"abc@def.gh", "abc@def"};
  private final String[] INVALID_EMAILS = {"abc.de", "abc@de<com"};
  private final String VALID_LONG_EMAIL = STRING_64 + "@" + STRING_64 + ".com";

  private ScimUser lennon;
  private ScimUser lincoln;

  @Before
  public void setup() throws Exception {
    lennon = createScimUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = createScimUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void teardown() throws Exception {

    deleteScimUser(lennon);
    deleteScimUser(lincoln);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testReplaceWithTooShortGivenName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(STRING_2, STRING_1).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("length must be between 2 and 64")));
  }

  @Test
  public void testReplaceWithTooLongGivenName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(STRING_65, STRING_64).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("length must be between 2 and 64")));
  }

  @Test
  public void testReplaceWithInvalidGivenName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(INVALID_STRING, VALID_STRING).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("String contains invalid characters")));
  }

  @Test
  public void testReplaceWithTooShortFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(STRING_64, STRING_1).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("length must be between 2 and 64")));
  }

  @Test
  public void testReplaceWithTooLongFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(STRING_64, STRING_65).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("length must be between 2 and 64")));
  }

  @Test
  public void testReplaceWithInvalidFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(VALID_STRING, INVALID_STRING).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("String contains invalid characters")));
  }

  @Test
  public void testReplaceWithTooLongEmail() throws Exception {

    ScimUser updates = ScimUser.builder().buildEmail(VALID_LONG_EMAIL).build();

    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("length must be less than 128")));
  }

  @Test
  public void testReplaceWithInvalidEmail() throws Exception {

    for (int i = 0; i < INVALID_EMAILS.length; i++) {

      ScimEmail email = ScimEmail.builder().email(INVALID_EMAILS[i]).build();
      ScimUser updates = ScimUser.builder().addEmail(email).build();
      scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
        .andExpect(jsonPath("$.detail", containsString("Please provide a valid email address")));
    }
  }

  @Test
  public void testReplaceWithEmailNoType() throws Exception {

    ScimEmail email = ScimEmail.builder().value(VALID_EMAILS[0]).primary(true).build();
    ScimUser updates = ScimUser.builder().addEmail(email).build();
    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("Please provide a value for email type")));
  }

  @Test
  public void testReplaceWithEmailNoPrimary() throws Exception {

    ScimEmail email = ScimEmail.builder().value(VALID_EMAILS[0]).build();
    ScimUser updates = ScimUser.builder().addEmail(email).build();
    scimUtils.patchUser(lennon.getId(), replace, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("Please provide a value for email primary")));
  }

  @Test
  public void testReplaceWithValidEmail() throws Exception {

    for (int i = 0; i < VALID_EMAILS.length; i++) {

      ScimEmail email = ScimEmail.builder().email(VALID_EMAILS[i]).build();
      ScimUser updates = ScimUser.builder().addEmail(email).build();
      scimUtils.patchUser(lennon.getId(), replace, updates);
    }
  }

  @Test
  public void testAddInvalidPicture() throws Exception {

    ScimUser updates = ScimUser.builder().buildPhoto(PICTURE_INVALID_URL).build();

    scimUtils.patchUser(lennon.getId(), add, updates, HttpStatus.BAD_REQUEST)
      .andExpect(jsonPath("$.detail", containsString("String contains HTML tags")));
  }

  @Test
  public void testReplaceWithGivenAndFamilyNameWithMaxLength() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(STRING_64, STRING_64).build();

    scimUtils.patchUser(lennon.getId(), replace, updates);
  }

  @Test
  public void testReplaceWithValidGivenAndFamilyName() throws Exception {

    ScimUser updates = ScimUser.builder().buildName(VALID_STRING, VALID_STRING).build();

    scimUtils.patchUser(lennon.getId(), replace, updates);
  }
}
