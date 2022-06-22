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
package it.infn.mw.iam.api.registration.cern;

import static it.infn.mw.iam.util.BasicAuthenticationUtils.basicAuthHeaderValue;
import static java.lang.String.format;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.cern.CernProperties;

@Service
@Profile("cern")
public class DefaultCernHrDBApiService implements CernHrDBApiService {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultCernHrDBApiService.class);

  public static final String PARTICIPATION_API_PATH_TEMPLATE =
      "/api/VOPersons/participation/%s/valid/%s";

  public static final String VO_PERSON_API_PATH_TEMPLATE = "/api/VOPersons/%s";

  final RestTemplateFactory rtFactory;
  final CernProperties properties;

  @Autowired
  public DefaultCernHrDBApiService(RestTemplateFactory rtFactory, CernProperties properties) {
    this.rtFactory = rtFactory;
    this.properties = properties;
  }

  private HttpHeaders buildAuthHeaders() {

    HttpHeaders headers = new HttpHeaders();

    headers.set("Authorization", basicAuthHeaderValue(properties.getHrApi().getUsername(),
        properties.getHrApi().getPassword()));

    return headers;
  }

  @Override
  public boolean hasValidExperimentParticipation(String personId) {
    RestTemplate rt = rtFactory.newRestTemplate();

    String personValidUrl = String.format("%s%s", properties.getHrApi().getUrl(),
        format(PARTICIPATION_API_PATH_TEMPLATE, properties.getExperimentName(), personId));

    LOG.debug("Querying HR db participation API for person {} at URL {}", personId, personValidUrl);

    try {

      ResponseEntity<Boolean> response = rt.exchange(personValidUrl, HttpMethod.GET,
          new HttpEntity<>(buildAuthHeaders()), Boolean.class);
      return response.getBody();
    } catch (RestClientException e) {
      final String errorMsg = "HR db api error: " + e.getMessage();
      throw new CernHrDbApiError(errorMsg, e);
    } 
  }

  @Override
  public VOPersonDTO getHrDbPersonRecord(String personId) {

    RestTemplate rt = rtFactory.newRestTemplate();

    String personValidUrl = String.format("%s%s", properties.getHrApi().getUrl(),
        format(VO_PERSON_API_PATH_TEMPLATE, personId));

    LOG.debug("Querying HR db VO person API for person {} at URL {}", personId, personValidUrl);

    try {
      ResponseEntity<VOPersonDTO> response = rt.exchange(personValidUrl, HttpMethod.GET,
          new HttpEntity<>(buildAuthHeaders()), VOPersonDTO.class);
      return response.getBody();
    } catch (RestClientException e) {
      final String errorMsg = "HR db api error: " + e.getMessage();
      throw new CernHrDbApiError(errorMsg, e);
    }
  }
}
