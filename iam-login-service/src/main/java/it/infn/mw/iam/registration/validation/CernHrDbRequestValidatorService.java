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

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.core.lifecycle.cern.CernHrLifecycleHandler.LABEL_CERN_PREFIX;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.error;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.invalid;
import static it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult.ok;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.LabelDTO;
import it.infn.mw.iam.api.registration.cern.CernHrDBApiService;
import it.infn.mw.iam.api.registration.cern.CernHrDbApiError;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.config.cern.CernProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;

@Service
@Profile("cern")
public class CernHrDbRequestValidatorService implements RegistrationRequestValidationService {



  public static final Logger LOG = LoggerFactory.getLogger(CernHrDbRequestValidatorService.class);

  final CernHrDBApiService hrDbApi;
  final CernProperties cernProperties;

  @Autowired
  public CernHrDbRequestValidatorService(CernHrDBApiService hrDbApi, CernProperties properties) {
    this.hrDbApi = hrDbApi;
    this.cernProperties = properties;
  }

  public void addPersonIdLabel(RegistrationRequestDto request, String personId) {
    LabelDTO label = LabelDTO.builder()
      .prefix(LABEL_CERN_PREFIX)
      .name(cernProperties.getPersonIdClaim())
      .value(personId)
      .build();

    if (isNull(request.getLabels())) {
      request.setLabels(Lists.newArrayList());
    }

    request.getLabels().add(label);
  }

  public void synchronizeInfo(RegistrationRequestDto request, String personId) {

    VOPersonDTO voPersonDTO = hrDbApi.getHrDbPersonRecord(personId);

    request.setGivenname(voPersonDTO.getFirstName());
    request.setFamilyname(voPersonDTO.getName());
    request.setEmail(voPersonDTO.getEmail());
  }

  @Override
  public RegistrationRequestValidationResult validateRegistrationRequest(
      RegistrationRequestDto registrationRequest,
      Optional<ExternalAuthenticationRegistrationInfo> authentication) {

    if (!authentication.isPresent()) {
      return invalid("User is not authenticated");
    }

    ExternalAuthenticationRegistrationInfo auth = authentication.get();

    if (!cernProperties.getSsoIssuer().equals(auth.getIssuer())) {
      return invalid(
          format("User is not authenticated by CERN SSO issuer %s", cernProperties.getSsoIssuer()));
    }

    final String cernPersonId =
        auth.getAdditionalAttributes().get(cernProperties.getPersonIdClaim());

    if (isNullOrEmpty(cernPersonId)) {
      return invalid(format("CERN person id claim '%s' not found in authentication attributes",
          cernProperties.getPersonIdClaim()));
    }

    try {
      if (hrDbApi.hasValidExperimentParticipation(cernPersonId)) {
        addPersonIdLabel(registrationRequest, cernPersonId);
        synchronizeInfo(registrationRequest, cernPersonId);
        return ok();
      }
    } catch (CernHrDbApiError e) {
      return error("HR Db API error: " + e.getMessage());
    }

    return invalid(format("No valid experiment participation found for user %s %s (PersonId: %s)",
        auth.getGivenName(), auth.getFamilyName(), cernPersonId));
  }

}
