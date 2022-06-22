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

import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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
  
  @Autowired
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
  
  @RequestMapping(value = "/iam/group", method = POST)
  @ResponseStatus(value = HttpStatus.CREATED)
  @PreAuthorize("hasRole('ADMIN')")
  public GroupDTO createGroup(@RequestBody @Validated(CreateGroup.class) GroupDTO group, final BindingResult validationResult) {
    
    handleValidationError(INVALID_GROUP,validationResult);
    
    IamGroup entity = converter.entityFromDto(group);
    entity = groupService.createGroup(entity);
    return converter.dtoFromEntity(entity);
  }
  
  @RequestMapping(value = "/iam/group/{id}", method = PUT)
  @PreAuthorize("hasRole('ADMIN') or #iam.isGroupManager(#id)")
  public GroupDTO updateGroup(@PathVariable String id, @RequestBody @Validated(UpdateGroup.class) GroupDTO group, final BindingResult validationResult) {
    handleValidationError(INVALID_GROUP, validationResult);
    
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    entity = groupService.setDescription(entity, group.getDescription());
    return converter.dtoFromEntity(entity);  
  }
  
  @RequestMapping(value = "/iam/group/{id}/attributes", method=RequestMethod.GET)
  @PreAuthorize("hasRole('ADMIN') or #iam.isGroupManager(#id)")
  public List<AttributeDTO> getAttributes(@PathVariable String id){
    
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    
    List<AttributeDTO> results = Lists.newArrayList();
    entity.getAttributes().forEach(a -> results.add(attributeConverter.dtoFromEntity(a)));
    
    return results;
  }
  
  @RequestMapping(value = "/iam/group/{id}/attributes", method= PUT)
  @PreAuthorize("hasRole('ADMIN')")
  public void setAttribute(@PathVariable String id, @RequestBody @Validated AttributeDTO attribute, final BindingResult validationResult) {
    handleValidationError(INVALID_ATTRIBUTE,validationResult);
    IamGroup entity = groupService.findByUuid(id).orElseThrow(()->NoSuchGroupError.forUuid(id));
    
    IamAttribute attr = attributeConverter.entityFromDto(attribute);
    entity.getAttributes().remove(attr);
    entity.getAttributes().add(attr);
  }
  
  @RequestMapping(value = "/iam/group/{id}/attributes", method=DELETE)
  @PreAuthorize("hasRole('ADMIN')")
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
