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
package it.infn.mw.iam.api.client.management.validation;

import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.context.annotation.Scope;

import it.infn.mw.iam.api.scim.exception.ScimBulkPayloadSizeExceeded;
import it.infn.mw.iam.api.scim.model.ScimBulkOperationSingle;

@Scope("prototype")
public class ValidBulkSizeValidator implements ConstraintValidator<ValidBulkSize, List<ScimBulkOperationSingle>> {

  private long max;

  @Override
  public void initialize(ValidBulkSize constraintAnnotation) {
    this.max = constraintAnnotation.max();
  }

  @Override
  public boolean isValid(List<ScimBulkOperationSingle> operations, ConstraintValidatorContext context) {
    if (operations.size() > max){
        throw new ScimBulkPayloadSizeExceeded("Maximum number of operations exceeded ("+max+")");
    }
    return true;
  }

}