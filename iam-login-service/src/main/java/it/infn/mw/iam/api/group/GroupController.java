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
package it.infn.mw.iam.api.group;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.AttributeDTO;
import it.infn.mw.iam.api.common.AttributeDTOConverter;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.GroupDTO;
import it.infn.mw.iam.api.common.GroupDTO.CreateGroup;
import it.infn.mw.iam.api.common.GroupDTO.UpdateGroup;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.group.error.NoSuchGroupError;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamGroup;

@RestController
public class GroupController {

  public static final String INVALID_GROUP = "Invalid group: ";
  public static final String INVALID_ATTRIBUTE = "Invalid attribute: ";

  final IamGroupService groupService;
  final GroupDTOConverter converter;
  final AttributeDTOConverter attributeConverter;

  public GroupController(IamGroupService groupService, GroupDTOConverter converter, AttributeDTOConverter attrConverter) {
    this.groupService = groupService;
    this.converter = converter;
    this.attributeConverter = attrConverter;
  }

  private String buildValidationErrorMessage(String prefix, BindingResult result) {
    StringBuilder sb = new StringBuilder(prefix);
    if (result.hasGlobalErrors()) {
      sb.append(result.getGlobalErrors().get(0).getDefaultMessage());
    } else {
      sb.append(result.getFieldErrors().stream().map(FieldError::getDefaultMessage).collect(Collectors.joining(",")));
    }
    return sb.toString();
  }

  private void handleValidationError(String prefix, BindingResult result) {
    if (result.hasErrors()) {
      throw new InvalidGroupError(buildValidationErrorMessage(prefix, result));
    }
  }

  @PostMapping(value = "/iam/group")
  @ResponseStatus(value = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public GroupDTO createGroup(@RequestBody @Validated(CreateGroup.class) GroupDTO group, final BindingResult validationResult) {

    handleValidationError(INVALID_GROUP,validationResult);

    IamGroup entity = converter.entityFromDto(group);
    entity = groupService.createGroup(entity);
    return converter.dtoFromEntity(entity);
  }
  
  @PutMapping(value = "/iam/group/{id}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.isGroupManager(#id)")
  public GroupDTO updateGroup(@PathVariable String id, @RequestBody @Validated(UpdateGroup.class) GroupDTO group, final BindingResult validationResult) {
    handleValidationError(INVALID_GROUP, validationResult);

    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    entity = groupService.setDescription(entity, group.getDescription());
    return converter.dtoFromEntity(entity);  
  }

  @GetMapping(value = "/iam/group/{id}/attributes")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.isGroupManager(#id)")
  public List<AttributeDTO> getAttributes(@PathVariable String id){
    
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    
    List<AttributeDTO> results = Lists.newArrayList();
    entity.getAttributes().forEach(a -> results.add(attributeConverter.dtoFromEntity(a)));
    
    return results;
  }
  
  @PutMapping(value = "/iam/group/{id}/attributes")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void setAttribute(@PathVariable String id, @RequestBody @Validated AttributeDTO attribute, final BindingResult validationResult) {
    handleValidationError(INVALID_ATTRIBUTE,validationResult);
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    
    IamAttribute attr = attributeConverter.entityFromDto(attribute);
    entity.getAttributes().remove(attr);
    entity.getAttributes().add(attr);
  }
  
  @DeleteMapping(value = "/iam/group/{id}/attributes")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public void deleteAttribute(@PathVariable String id, @Validated AttributeDTO attribute, final BindingResult validationResult) {
    handleValidationError(INVALID_ATTRIBUTE, validationResult);
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    
    entity.getAttributes().remove(attributeConverter.entityFromDto(attribute));
  }
  
  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidGroupError.class)
  @ResponseBody
  public ErrorDTO handleValidationError(InvalidGroupError e) {    
    return ErrorDTO.fromString(e.getMessage());
  }
  
  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchGroupError.class)
  @ResponseBody
  public ErrorDTO handleNotFoundError(NoSuchGroupError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
