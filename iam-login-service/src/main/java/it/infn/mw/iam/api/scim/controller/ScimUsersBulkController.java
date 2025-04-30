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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimBulkOperationSingle;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimErrorResponse;
import it.infn.mw.iam.api.scim.model.ScimResource;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.model.ScimUserPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUsersBulkRequest;
import it.infn.mw.iam.api.scim.model.ScimUsersBulkResponse;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;

@RestController
@RequestMapping("/scim/Users/Bulk")
public class ScimUsersBulkController extends ScimControllerSupport {

  public static final String INVALID_BULK_MSG = "Invalid Bulk Request";

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  ScimUserProvisioning userProvisioningService;

  @Autowired 
  ScimExceptionHandler errorHandler;

  @PreAuthorize("#iam.hasScope('scim:write')")
  @PostMapping(consumes = ScimConstants.SCIM_CONTENT_TYPE, produces = ScimConstants.SCIM_CONTENT_TYPE)
  @ResponseStatus(HttpStatus.OK)
  public MappingJacksonValue bulkPost(@RequestBody @Validated final ScimUsersBulkRequest bulkRequest,
      final BindingResult validationResult) {

    handleValidationError(INVALID_BULK_MSG, validationResult);
    ScimUsersBulkResponse.Builder bulkResponse = ScimUsersBulkResponse.reponseBuilder();

    for(ScimBulkOperationSingle singleOperation: bulkRequest.getOperations()){
      try {
        if (singleOperation.getMethod().equals("POST")){
          ScimUser user = singleOperation.getDataAs(ScimUser.class, objectMapper);
          try {
            ScimResource resp = userProvisioningService.create(user);
            bulkResponse.addSuccessResponse("POST", resp.getMeta().getLocation(), singleOperation.getbulkId(), "201");
          } catch (ScimResourceExistsException e){
            ScimErrorResponse error = errorHandler.handleResourceExists(e);
            bulkResponse.addErrorResponse("POST",singleOperation.getbulkId(), error.getStatus(), error);
          }
      } else if (singleOperation.getMethod().equals("PATCH")){
        ScimUserPatchRequest patch = singleOperation.getDataAs(ScimUserPatchRequest.class, objectMapper);
        String path = singleOperation.getPath();
        String[] segments = path.split("/");
        String id = segments[segments.length - 1];
        try {
          userProvisioningService.update(id, patch.getOperations());
          bulkResponse.addSuccessResponse("PATCH", path, "200");
        } catch (ScimResourceNotFoundException e){
          ScimErrorResponse error = errorHandler.handleResourceNotFoundException(e);
          bulkResponse.addErrorResponse("PATCH", error.getStatus(), error);
        } catch (ScimPatchOperationNotSupported e){
          ScimErrorResponse error = errorHandler.handleInvalidArgumentException(e);
          bulkResponse.addErrorResponse("PATCH", error.getStatus(), error);
        }
      }
    } catch (Exception e) {
      System.err.println("Failed to process operation: " + e.getMessage());
    }}
    
    return new MappingJacksonValue(bulkResponse.build()); 
  }

}