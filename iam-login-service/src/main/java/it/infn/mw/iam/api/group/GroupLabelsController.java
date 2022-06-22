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

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static java.lang.String.format;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.LabelDTO;
import it.infn.mw.iam.api.common.LabelDTOConverter;
import it.infn.mw.iam.api.common.error.InvalidLabelError;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.group.error.NoSuchGroupError;
import it.infn.mw.iam.persistence.model.IamGroup;

@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping(GroupLabelsController.RESOURCE)
public class GroupLabelsController {

  public static final String RESOURCE = "/iam/group/{id}/labels";
  public static final String INVALID_LABEL_TEMPLATE = "Invalid label: %s";

  final IamGroupService service;
  final LabelDTOConverter converter;

  @Autowired
  public GroupLabelsController(IamGroupService service, LabelDTOConverter converter) {
    this.service = service;
    this.converter = converter;
  }

  private void handleValidationError(BindingResult result) {
    if (result.hasErrors()) {
      throw new InvalidLabelError(format(INVALID_LABEL_TEMPLATE, stringifyValidationError(result)));
    }
  }

  @RequestMapping(method = GET)
  @PreAuthorize("hasRole('ADMIN') or #iam.isGroupManager(#id)")
  public List<LabelDTO> getLabels(@PathVariable String id) {

    IamGroup group = service.findByUuid(id).orElseThrow(() -> NoSuchGroupError.forUuid(id));

    List<LabelDTO> results = Lists.newArrayList();

    group.getLabels().forEach(l -> results.add(converter.dtoFromEntity(l)));

    return results;
  }

  @RequestMapping(method = PUT)
  public void setLabel(@PathVariable String id, @RequestBody @Validated LabelDTO label,
      BindingResult validationResult) {
    handleValidationError(validationResult);
    IamGroup group = service.findByUuid(id).orElseThrow(() -> NoSuchGroupError.forUuid(id));

    service.addLabel(group, converter.entityFromDto(label));
  }

  @RequestMapping(method = DELETE)
  @ResponseStatus(NO_CONTENT)
  public void deleteLabel(@PathVariable String id, @Validated LabelDTO label,
      BindingResult validationResult) {
    handleValidationError(validationResult);
    IamGroup group = service.findByUuid(id).orElseThrow(() -> NoSuchGroupError.forUuid(id));
    service.deleteLabel(group, converter.entityFromDto(label));
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidLabelError.class)
  @ResponseBody
  public ErrorDTO handleValidationError(InvalidLabelError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchGroupError.class)
  @ResponseBody
  public ErrorDTO handleNotFoundError(NoSuchGroupError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

}
