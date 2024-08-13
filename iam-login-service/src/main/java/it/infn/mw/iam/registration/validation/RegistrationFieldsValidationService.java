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

package it.infn.mw.iam.registration.validation;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.ok;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.error;


@Service
@Profile("!cern")
public class RegistrationFieldsValidationService implements RegistrationRequestValidationService {

  public static final Logger LOG = LoggerFactory.getLogger(RegistrationFieldsValidationService.class);

  @Autowired
  private IamProperties iamProperties;

  @Override
  public RegistrationRequestValidationResult validateRegistrationRequest(RegistrationRequestDto dto,
      Optional<ExternalAuthenticationRegistrationInfo> authentication) {

    /**
     * Determine if the `notes` is mandatory or optional field.
     *
     * When the `notes` field is mandatory during registration, it will perform
     * `notesSanityChecks`.
     */
    if (iamProperties.getRegistration().getFields().containsKey("notes")) {
      RegistrationFieldProperties notesFieldAttribute = iamProperties.getRegistration().getFields().get("notes");

      if ("mandatory".equalsIgnoreCase(notesFieldAttribute.getFieldBehaviour().name())) {
        if (dto.getNotes() == null) {
          return error("Notes field cannot be null");
        }

        if (dto.getNotes().trim().isEmpty()) {
          return error("Notes field cannot be the empty string");
        }
      }
    }

    return ok();
  }
}
