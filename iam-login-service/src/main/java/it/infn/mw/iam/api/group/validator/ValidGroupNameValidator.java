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
package it.infn.mw.iam.api.group.validator;

import static java.util.Objects.isNull;

import java.util.Optional;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.common.GroupDTO;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Component
@Scope("prototype")
public class ValidGroupNameValidator implements ConstraintValidator<ValidGroupName, GroupDTO>{

  public static final int MAX_NAME_LENGTH = 512;
  
  final IamGroupRepository repo;
  
  @Autowired
  public ValidGroupNameValidator(IamGroupRepository repo) {
    this.repo = repo;
  }

  @Override
  public void initialize(ValidGroupName constraintAnnotation) {
    // intentionally empty
  }

  @Override
  public boolean isValid(GroupDTO value, ConstraintValidatorContext context) {
    Optional<IamGroup> parent;
    
    if (!isNull(value.getParent()) ) {
      parent = repo.findByUuid(value.getParent().getUuid());
      if (!parent.isPresent()) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate("parent group not found").addConstraintViolation();
        return false;
      }
      
      final String compositeName = String.format("%s/%s", parent.get().getName(), value.getName());
      
      if (compositeName.length() >= MAX_NAME_LENGTH) {
        return false;
      }
    }
    
    return true;
  }

}
