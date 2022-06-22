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
package it.infn.mw.iam.api.group.find;

import static it.infn.mw.iam.api.common.PagingUtils.buildPageRequest;
import static it.infn.mw.iam.api.utils.ValidationErrorUtils.handleValidationError;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.form.PaginatedRequestWithFilterForm;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimGroup;

@RestController
@PreAuthorize("hasRole('ADMIN')")
public class FindGroupController {

  public static final int PAGE_SIZE = 200;

  public static final String FIND_BY_LABEL_RESOURCE = "/iam/group/find/bylabel";
  public static final String FIND_BY_NAME_RESOURCE = "/iam/group/find/byname";
  public static final String FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT =
      "/iam/group/find/unsubscribed/{accountUuid}";

  public static final String INVALID_FIND_GROUP_REQUEST = "Invalid find group request";

  final FindGroupService service;

  @Autowired
  public FindGroupController(FindGroupService service) {
    this.service = service;
  }

  protected MappingJacksonValue filterOutMembers(ListResponseDTO<ScimGroup> listResult) {
    MappingJacksonValue result = new MappingJacksonValue(listResult);

    FilterProvider filterProvider = new SimpleFilterProvider().addFilter("attributeFilter",
        SimpleBeanPropertyFilter.serializeAllExcept("members"));

    result.setFilters(filterProvider);
    return result;
  }


  @RequestMapping(method = GET, value = FIND_BY_LABEL_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue findByLabel(@RequestParam(required = true) String name,
      @RequestParam(required = false) String value,
      @RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex) {

    return filterOutMembers(
        service.findGroupByLabel(name, value, buildPageRequest(count, startIndex, PAGE_SIZE)));

  }

  @RequestMapping(method = GET, value = FIND_BY_NAME_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue findByName(@RequestParam(required = true) String name) {

    return filterOutMembers(service.findGroupByName(name));
  }

  @RequestMapping(method = GET, value = FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue findUnsubscribedGroupsForAccount(@PathVariable String accountUuid,
      @Validated PaginatedRequestWithFilterForm form, BindingResult formValidationResult) {

    handleValidationError(INVALID_FIND_GROUP_REQUEST, formValidationResult);

    return filterOutMembers(service.findUnsubscribedGroupsForAccount(accountUuid, form.getFilter(),
        buildPageRequest(form.getCount(), form.getStartIndex(), PAGE_SIZE)));
  }

}
