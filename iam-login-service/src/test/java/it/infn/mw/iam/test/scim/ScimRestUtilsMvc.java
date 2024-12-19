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
package it.infn.mw.iam.test.scim;

import static it.infn.mw.iam.test.scim.ScimUtils.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.scim.ScimUtils.getMeLocation;
import static it.infn.mw.iam.test.scim.ScimUtils.getUserLocation;
import static it.infn.mw.iam.test.scim.ScimUtils.getUsersLocation;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;

@Component
public class ScimRestUtilsMvc extends RestUtils {

  @Autowired
  public ScimRestUtilsMvc(MockMvc mvc, ObjectMapper mapper) {
    super(mvc, mapper);
  }

  public ScimUser postUser(ScimUser user) throws Exception {

    return mapper.readValue(postUser(user, CREATED).andReturn().getResponse().getContentAsString(),
        ScimUser.class);
  }

  public ResultActions postUser(ScimUser user, HttpStatus expectedStatus) throws Exception {

    return doPost(getUsersLocation(), user, SCIM_CONTENT_TYPE, expectedStatus);
  }



  public ScimUser getUser(String uuid) throws Exception {

    return mapper.readValue(getUser(uuid, OK).andReturn().getResponse().getContentAsString(),
        ScimUser.class);
  }

  public ResultActions getUser(String uuid, HttpStatus expectedStatus) throws Exception {

    return doGet(getUserLocation(uuid), SCIM_CONTENT_TYPE, expectedStatus);
  }

  public ResultActions getUsers(MultiValueMap<String, String> params, HttpStatus expectedStatus)
      throws Exception {

    return doGet(getUsersLocation(), params, SCIM_CONTENT_TYPE, expectedStatus);
  }

  public ResultActions getUsers(MultiValueMap<String, String> params) throws Exception {

    return doGet(getUsersLocation(), params, SCIM_CONTENT_TYPE, OK);
  }

  public ResultActions getUsers(HttpStatus expectedStatus) throws Exception {

    return doGet(getUsersLocation(), SCIM_CONTENT_TYPE, expectedStatus);
  }

  public ResultActions getUsers() throws Exception {

    return doGet(getUsersLocation(), SCIM_CONTENT_TYPE, OK);
  }

  public ScimUser getMe() throws Exception {

    return mapper.readValue(getMe(OK).andExpect(content().contentType(SCIM_CONTENT_TYPE))
      .andReturn()
      .getResponse()
      .getContentAsString(), ScimUser.class);
  }

  public ResultActions getMe(HttpStatus expectedStatus) throws Exception {

    return doGet(getMeLocation(), SCIM_CONTENT_TYPE, expectedStatus);
  }

  public ResultActions putUser(String uuid, ScimUser user, HttpStatus expectedStatus)
      throws Exception {

    return doPut(getUserLocation(uuid), user, SCIM_CONTENT_TYPE, expectedStatus);
  }

  public ScimUser putUser(String uuid, ScimUser user) throws Exception {

    return mapper.readValue(putUser(uuid, user, OK).andReturn().getResponse().getContentAsString(),
        ScimUser.class);
  }

  public ResultActions deleteUser(String uuid, HttpStatus expectedStatus) throws Exception {

    return doDelete(getUserLocation(uuid), expectedStatus);
  }

  public void deleteUser(String uuid) throws Exception {

    deleteUser(uuid, NO_CONTENT);
  }

  public void deleteUser(ScimUser user, HttpStatus expectedStatus) throws Exception {

    deleteUser(user.getId(), expectedStatus);
  }

  public void deleteUser(ScimUser user) throws Exception {

    deleteUser(user.getId());
  }

  public void deleteUsers(ScimUser... users) throws Exception {

    for (ScimUser u : users) {
      deleteUser(u);
    }
  }

  private ScimUserPatchRequest getUserPatchRequest(ScimPatchOperationType type, ScimUser updates)
      throws Exception {

    ScimUserPatchRequest patchRequest;
    switch (type) {
      case add:
        patchRequest = ScimUserPatchRequest.builder().add(updates).build();
        break;
      case remove:
        patchRequest = ScimUserPatchRequest.builder().remove(updates).build();
        break;
      case replace:
        patchRequest = ScimUserPatchRequest.builder().replace(updates).build();
        break;
      default:
        throw new Exception("unsupported patch type");
    }
    return patchRequest;
  }

  public ResultActions patchUser(String uuid, ScimPatchOperationType type, ScimUser updates,
      HttpStatus expectedStatus) throws Exception {

    return doPatch(getUserLocation(uuid), getUserPatchRequest(type, updates), SCIM_CONTENT_TYPE,
        expectedStatus);
  }

  public ResultActions patchUser(String uuid, ScimPatchOperationType type, ScimUser updates)
      throws Exception {

    return patchUser(uuid, type, updates, NO_CONTENT);
  }

  public ResultActions patchMe(ScimPatchOperationType type, ScimUser updates,
      HttpStatus expectedStatus) throws Exception {

    return doPatch(getMeLocation(), getUserPatchRequest(type, updates), SCIM_CONTENT_TYPE,
        expectedStatus);
  }

  public ResultActions patchMe(ScimPatchOperationType type, ScimUser updates) throws Exception {

    return patchMe(type, updates, NO_CONTENT);
  }
}
