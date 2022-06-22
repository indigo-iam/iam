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
package it.infn.mw.iam.api.scim.controller;

import static it.infn.mw.iam.api.scim.controller.utils.ValidationHelper.handleValidationError;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;

@RestController
@RequestMapping("/scim/Users")
@Transactional
public class ScimUserController extends ScimControllerSupport{

  @Autowired
  ScimUserProvisioning userProvisioningService;

  FilterProvider excludePasswordFilter = new SimpleFilterProvider().addFilter("passwordFilter",
      SimpleBeanPropertyFilter.serializeAllExcept("password"));

  private Set<String> parseAttributes(final String attributesParameter) {

    Set<String> result = new HashSet<>();
    if (!Strings.isNullOrEmpty(attributesParameter)) {
      result = Sets.newHashSet(Splitter.on(CharMatcher.anyOf(".,"))
        .trimResults()
        .omitEmptyStrings()
        .split(attributesParameter));
    }
    result.add("schemas");
    result.add("id");
    return result;
  }

  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN')")
  @RequestMapping(method = RequestMethod.GET, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue listUsers(@RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex,
      @RequestParam(required = false) final String attributes) {

    ScimPageRequest pr = buildUserPageRequest(count, startIndex);
    ScimListResponse<ScimUser> result = userProvisioningService.list(pr);

    MappingJacksonValue wrapper = new MappingJacksonValue(result);

    if (attributes != null) {
      Set<String> includeAttributes = parseAttributes(attributes);

      FilterProvider filterProvider = new SimpleFilterProvider().addFilter("attributeFilter",
          SimpleBeanPropertyFilter.filterOutAllExcept(includeAttributes));

      wrapper.setFilters(filterProvider);
    }

    return wrapper;
  }

  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN')")
  @RequestMapping(value = "/{id}", method = RequestMethod.GET,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimUser getUser(@PathVariable final String id) {

    return userProvisioningService.getById(id);
  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(method = RequestMethod.POST, consumes = ScimConstants.SCIM_CONTENT_TYPE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.CREATED)
  public MappingJacksonValue create(
      @RequestBody @Validated(ScimUser.NewUserValidation.class) final ScimUser user,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim User", validationResult);
    ScimUser result = userProvisioningService.create(user);

    return new MappingJacksonValue(result);
  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/{id}", method = RequestMethod.PUT,
      consumes = ScimConstants.SCIM_CONTENT_TYPE, produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.OK)
  public ScimUser replaceUser(@PathVariable final String id,
      @RequestBody @Validated(ScimUser.NewUserValidation.class) final ScimUser user,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim User", validationResult);

    return userProvisioningService.replace(id, user);

  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/{id}", method = RequestMethod.PATCH,
      consumes = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void updateUser(@PathVariable final String id,
      @RequestBody @Validated(ScimUser.UpdateUserValidation.class) final ScimUserPatchRequest patchRequest,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim Patch Request", validationResult);

    userProvisioningService.update(id, patchRequest.getOperations());

  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteUser(@PathVariable final String id) {

    userProvisioningService.delete(id);
  }

}
