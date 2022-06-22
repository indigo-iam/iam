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
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.provisioning.ScimGroupProvisioning;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;

@RestController
@RequestMapping("/scim/Groups")
public class ScimGroupController extends ScimControllerSupport {

  public static final String INVALID_GROUP_MSG = "Invalid Scim Group";

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

  @Autowired
  ScimGroupProvisioning groupProvisioningService;

  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN') or #iam.isGroupManager(#id)")
  @RequestMapping(value = "/{id}", method = RequestMethod.GET,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimGroup getGroup(@PathVariable final String id) {

    return groupProvisioningService.getById(id);
  }

  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN')")
  @RequestMapping(method = RequestMethod.GET, produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue listGroups(@RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex,
      @RequestParam(required = false) final String attributes) {

    ScimPageRequest pr = buildGroupPageRequest(count, startIndex);
    ScimListResponse<ScimGroup> result = groupProvisioningService.list(pr);

    MappingJacksonValue wrapper = new MappingJacksonValue(result);

    if (attributes != null) {
      Set<String> includeAttributes = parseAttributes(attributes);

      FilterProvider filterProvider = new SimpleFilterProvider().addFilter("attributeFilter",
          SimpleBeanPropertyFilter.filterOutAllExcept(includeAttributes));

      wrapper.setFilters(filterProvider);
    }

    return wrapper;
  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(method = RequestMethod.POST, consumes = ScimConstants.SCIM_CONTENT_TYPE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.CREATED)
  public ScimGroup create(@RequestBody @Validated final ScimGroup group,
      final BindingResult validationResult) {

    handleValidationError(INVALID_GROUP_MSG, validationResult);
    return groupProvisioningService.create(group);
  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/{id}", method = RequestMethod.PUT,
      consumes = ScimConstants.SCIM_CONTENT_TYPE, produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.OK)
  public ScimGroup replaceGroup(@PathVariable final String id,
      @RequestBody @Validated final ScimGroup group, final BindingResult validationResult) {

    handleValidationError(INVALID_GROUP_MSG, validationResult);

    return groupProvisioningService.replace(id, group);

  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN') or #iam.isGroupManager(#id)")
  @RequestMapping(value = "/{id}", method = RequestMethod.PATCH,
      consumes = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void updateGroup(@PathVariable final String id,
      @RequestBody @Validated final ScimGroupPatchRequest groupPatchRequest,
      final BindingResult validationResult) {

    handleValidationError(INVALID_GROUP_MSG, validationResult);

    groupProvisioningService.update(id, groupPatchRequest.getOperations());
  }

  @PreAuthorize("#oauth2.hasScope('scim:write') or hasRole('ADMIN') or #iam.isGroupManager(#id)")
  @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteGroup(@PathVariable final String id) {

    groupProvisioningService.delete(id);
  }


  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN') or #iam.isGroupManager(#id)")
  @RequestMapping(value = "/{id}/members", method = RequestMethod.GET,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimMemberRef> listMembers(@PathVariable final String id,
      @RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex) {

    return groupProvisioningService.listAccountMembers(id,
        buildPageRequest(count, startIndex, SCIM_MEMBERS_MAX_PAGE_SIZE));
  }

  @PreAuthorize("#oauth2.hasScope('scim:read') or hasRole('ADMIN') or #iam.isGroupManager(#id)")
  @RequestMapping(value = "/{id}/subgroups", method = RequestMethod.GET,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimListResponse<ScimMemberRef> listSubgroups(@PathVariable final String id,
      @RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex) {

    return groupProvisioningService.listGroupMembers(id,
        buildPageRequest(count, startIndex, SCIM_MEMBERS_MAX_PAGE_SIZE));
  }
}
