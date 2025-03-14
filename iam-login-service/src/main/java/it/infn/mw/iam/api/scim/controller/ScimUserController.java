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
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
public class ScimUserController extends ScimControllerSupport {

  // All the supported attribute Operators
  private enum attributeOperators{
    eq
  }

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

  private ArrayList<String> parseFilters(final String filtersParameter) {

    ArrayList<String> result = new ArrayList<String>();

    if (!Strings.isNullOrEmpty(filtersParameter)) {
      String copyParam = filtersParameter.toLowerCase();

      // Iterating over all defined enums 
      for(attributeOperators operator : attributeOperators.values()){

        // Looking for the first instance of the given operator in the request
        int index = copyParam.indexOf(operator.toString());

        // If there is an occurence and it's surrounded by spaces
        if(index > 0 && copyParam.charAt(index-1) == ' ' && copyParam.charAt(index + operator.name().length()) == ' '){
          
          // Then the value before is the parameter

          // The parameter before is then from the start until the first space
          String parameter = copyParam.substring(0, index -1);

          // The value is from the operator until the end
          String value = copyParam.substring(index + operator.name().length() + 1, copyParam.length());
          
          
          result.add(parameter);
          result.add(operator.name());
          result.add(value);
      
        }

      }

      // Fuck, ok, I can't find a solution at the moment with regex
      //result = Sets.newHashSet(copyParam.split("(?= and )(?= or )"));

      // okay, a dumb solution is better then no solution
      // I can look for sub strings for the logical operators, i.e. look for "and", "or" and "not"
      // in the string and check that the index before and after the ones found are space characters
    
      // if I know the location (using indexOf) then I can find the text and split accordingly 
      // Though this is a dumb implemenentation....

      // I can also drop the logical operators for know and only focus on the attribute operators
      // this removes the issue, though then you can only query one parameter at a time and only 
      // for one thing


    // Okay We're going with the simple implementation of the attribute operators for now. 
    }
    return result;
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @GetMapping(produces = ScimConstants.SCIM_CONTENT_TYPE)
  public MappingJacksonValue listUsers(@RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex,
      @RequestParam(required = false) final String attributes,
      @RequestParam(required = false) final String filters){
      

    ScimPageRequest pr = buildUserPageRequest(count, startIndex);
    ScimListResponse<ScimUser> result = userProvisioningService.list(pr);

    

    


    // The wrapper seems to have all the users within it
    // Also the attributes is sorting the values in here, so that must mean that I can do the same
    // i.e. I don't have to filter it before it arrives to this point. 
    MappingJacksonValue wrapper = new MappingJacksonValue(result);

    if (filters != null) {
      // Then similar to the parseAttributes, it needs to parse the filters

      ArrayList<String> filter = parseFilters(filters);
      ArrayList<ScimUser> filteredUsers = new ArrayList<ScimUser>();

      // I need to run through all users and check that the name corresponds
      for(ScimUser user : result.getResources()){
        if(!user.getName().getGivenName().equalsIgnoreCase(filter.get(2))){
          filteredUsers.add(user);
        }
      }

      result.getResources().removeAll(filteredUsers);
      wrapper = new MappingJacksonValue(result);

    }


    // This is the part where it cuts down the amount of attributes
    // i.e. I need to query the list similarly to how they remove from it
    if (attributes != null) {
      Set<String> includeAttributes = parseAttributes(attributes);

      FilterProvider filterProvider = new SimpleFilterProvider().addFilter("attributeFilter",
          SimpleBeanPropertyFilter.filterOutAllExcept(includeAttributes));

      wrapper.setFilters(filterProvider);
    }

    return wrapper;
  }

  @PreAuthorize("#iam.hasScope('scim:read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_GM')")
  @GetMapping(value = "/{id}", produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ScimUser getUser(@PathVariable final String id) {

    return userProvisioningService.getById(id);
  }

  @PreAuthorize("#iam.hasScope('scim:write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PostMapping(consumes = ScimConstants.SCIM_CONTENT_TYPE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.CREATED)
  public MappingJacksonValue create(
      @RequestBody @Validated(ScimUser.NewUserValidation.class) final ScimUser user,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim User", validationResult);
    ScimUser result = userProvisioningService.create(user);

    return new MappingJacksonValue(result);
  }

  @PreAuthorize("#iam.hasScope('scim:write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PutMapping(value = "/{id}", consumes = ScimConstants.SCIM_CONTENT_TYPE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.OK)
  public ScimUser replaceUser(@PathVariable final String id,
      @RequestBody @Validated(ScimUser.NewUserValidation.class) final ScimUser user,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim User", validationResult);

    return userProvisioningService.replace(id, user);

  }

  @PreAuthorize("#iam.hasScope('scim:write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PatchMapping(value = "/{id}", consumes = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void updateUser(@PathVariable final String id,
      @RequestBody @Validated(ScimUser.UpdateUserValidation.class) final ScimUserPatchRequest patchRequest,
      final BindingResult validationResult) {

    handleValidationError("Invalid Scim Patch Request", validationResult);

    userProvisioningService.update(id, patchRequest.getOperations());

  }

  @PreAuthorize("#iam.hasScope('scim:write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @DeleteMapping(value = "/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteUser(@PathVariable final String id) {

    userProvisioningService.delete(id);
  }

}
