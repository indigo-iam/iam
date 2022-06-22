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

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Component
@Scope("prototype")
public class ClientIdAvailableValidator implements ConstraintValidator<ClientIdAvailable, String> {
  private final IamClientRepository clientRepo;

  @Autowired
  public ClientIdAvailableValidator(IamClientRepository clientRepo) {
    this.clientRepo = clientRepo;
  }

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    if ((value == null) || (value.trim().isBlank())) {
      return true;
    }
    return clientRepo.findByClientId(value).isEmpty();
  }

}
