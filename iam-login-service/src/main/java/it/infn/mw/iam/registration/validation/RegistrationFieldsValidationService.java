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

import static it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour.MANDATORY;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.error;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.ok;
import static java.lang.String.format;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.registration.RegistrationAlteredEvent;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationField;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;


@Service
@Profile("!cern")
public class RegistrationFieldsValidationService implements RegistrationRequestValidationService {

  public static final String ERROR_01 = "External Authentication is required by configuration";
  public static final String ERROR_02 = "Mandatory %s field cannot be null or an empty string";
  public static final String ERROR_03 = "External authentication is required with read only fields";
  public static final String ERROR_04 =
      "Invalid value for the read only field %s: not coherent with the external authn";

  public static final Logger LOG =
      LoggerFactory.getLogger(RegistrationFieldsValidationService.class);

  private final IamProperties properties;
  private final ApplicationEventPublisher eventPublisher;

  public RegistrationFieldsValidationService(IamProperties properties,
      ApplicationEventPublisher eventPublisher) {
    this.properties = properties;
    this.eventPublisher = eventPublisher;
  }

  @Override
  public RegistrationRequestValidationResult validateRegistrationRequest(RegistrationRequestDto dto,
      Optional<ExternalAuthenticationRegistrationInfo> authentication) {

    RegistrationProperties rp = properties.getRegistration();

    if (rp.isRequireExternalAuthentication() && authentication.isEmpty()) {
      return error(ERROR_01);
    }

    for (Map.Entry<RegistrationField, RegistrationFieldProperties> pair : rp.getFields()
      .entrySet()) {

      /* Check mandatory fields are not null or blank */
      if (!validateMandatoryField(pair, dto)) {
        return error(format(ERROR_02, pair.getKey().name().toLowerCase()));
      }

      /* Check read only fields are coherent with external authentication */
      if (pair.getValue().isReadOnly()) {
        if (authentication.isEmpty()) {
          return error(ERROR_03);
        }
        if (!validateReadOnlyField(pair.getKey(), pair.getValue().getExternalAuthAttribute(), dto,
            authentication.get())) {
          handleDtoManipulation(pair, dto, authentication.get());
          return error(format(ERROR_04, pair.getKey().name()));
        }
      }
    }

    return ok();
  }

  private void handleDtoManipulation(Entry<RegistrationField, RegistrationFieldProperties> pair,
      RegistrationRequestDto dto, ExternalAuthenticationRegistrationInfo info) {

    eventPublisher.publishEvent(
        new RegistrationAlteredEvent(this, dto, info, format(ERROR_04, pair.getKey().name())));
  }

  private boolean validateReadOnlyField(RegistrationField field, String extAuthAttribute,
      RegistrationRequestDto dto, ExternalAuthenticationRegistrationInfo extAuthnInfo) {

    switch (field) {
      case EMAIL:
        return dto.getEmail().equals(extAuthnInfo.getEmail())
            || dto.getEmail().equals(extAuthnInfo.getAdditionalAttributes().get(extAuthAttribute));
      case NAME:
        return dto.getGivenname().equals(extAuthnInfo.getGivenName()) || dto.getGivenname()
          .equals(extAuthnInfo.getAdditionalAttributes().get(extAuthAttribute));
      case SURNAME:
        return dto.getFamilyname().equals(extAuthnInfo.getFamilyName()) || dto.getFamilyname()
          .equals(extAuthnInfo.getAdditionalAttributes().get(extAuthAttribute));
      case USERNAME:
        return dto.getUsername().equals(extAuthnInfo.getSuggestedUsername()) || dto.getUsername()
          .equals(extAuthnInfo.getAdditionalAttributes().get(extAuthAttribute));
      case AFFILIATION:
        return dto.getAffiliation()
          .equals(extAuthnInfo.getAdditionalAttributes().get(extAuthAttribute));
      case NOTES:
        return true;
      default:
        return false;
    }
  }

  private boolean validateMandatoryField(
      Map.Entry<RegistrationField, RegistrationFieldProperties> entry, RegistrationRequestDto dto) {

    if (!MANDATORY.equals(entry.getValue().getFieldBehaviour())) {
      return true;
    }
    switch (entry.getKey()) {
      case NAME:
        return dto.getGivenname() != null && !dto.getGivenname().isBlank();
      case SURNAME:
        return dto.getFamilyname() != null && !dto.getFamilyname().isBlank();
      case USERNAME:
        return dto.getUsername() != null && !dto.getUsername().isBlank();
      case EMAIL:
        return dto.getEmail() != null && !dto.getEmail().isBlank();
      case NOTES:
        return dto.getNotes() != null && !dto.getNotes().isBlank();
      default:
        return false;
    }
  }

}
