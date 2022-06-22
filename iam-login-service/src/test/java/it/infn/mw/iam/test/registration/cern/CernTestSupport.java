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
package it.infn.mw.iam.test.registration.cern;

import static it.infn.mw.iam.util.BasicAuthenticationUtils.basicAuthHeaderValue;

import java.time.Instant;
import java.util.Date;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.registration.cern.dto.InstituteDTO;
import it.infn.mw.iam.api.registration.cern.dto.ParticipationDTO;
import it.infn.mw.iam.api.registration.cern.dto.VOPersonDTO;

public class CernTestSupport {
  
  

  public static final String HR_API_USERNAME = "user";
  public static final String HR_API_PASSWORD = "password";
  public static final String HR_API_URL = "https://hr.cern.ch";

  public static final String SSO_ENTITY_ID = "https://cern.ch/login";
  public static final String EXPERIMENT_NAME = "wlcg";

  public static final String MOCK_HR_USER_FIRST_NAME = "John";
  public static final String MOCK_HR_USER_FAMILY_NAME = "Lennon";
  public static final String MOCK_HR_USER_EMAIL = "lennon@heaven.org";
  public static final Date MOCK_HR_USER_PARTICIPATION_START = Date.from(Instant.parse("2020-01-01T00:00:00.00Z"));
  public static final String MOCK_HR_USER_INSTITUTION_ID = "000001";
  public static final String MOCK_HR_USER_INSTITUTION_NAME = "Apple records";
  public static final String MOCK_HR_USER_INSTITUTION_COUNTRY = "GB";
  public static final String MOCK_HR_USER_INSTITUTION_TOWN = "London";
  
  public static final String BASIC_AUTH_HEADER_VALUE =
      basicAuthHeaderValue(HR_API_USERNAME, HR_API_PASSWORD);

  public static final String API_VALIDATION_URL =
      String.format("%s/api/VOPersons/participation/wlcg/valid", HR_API_URL);

  public static final String VO_PERSON_API_URL = 
      String.format("%s/api/VOPersons", HR_API_URL);
  
  public static String apiValidationUrl(String personId) {
    return String.format("%s/%s", API_VALIDATION_URL, personId);
  }
  
  public static String voPersonUrl(String personId) {
    return String.format("%s/%s", VO_PERSON_API_URL, personId);
  }
  
  public static VOPersonDTO mockHrUser(String personId) {
    VOPersonDTO dto = new VOPersonDTO();
    dto.setFirstName(MOCK_HR_USER_FIRST_NAME);
    dto.setName(MOCK_HR_USER_FAMILY_NAME);
    dto.setEmail(MOCK_HR_USER_EMAIL);
    dto.setParticipations(Sets.newHashSet());
    
    dto.setId(Long.parseLong(personId));
    
    ParticipationDTO p = new ParticipationDTO();
    
    p.setExperiment("wlcg");
    p.setStartDate(MOCK_HR_USER_PARTICIPATION_START);
    
    InstituteDTO i = new InstituteDTO();
    i.setId(MOCK_HR_USER_INSTITUTION_ID);
    i.setName(MOCK_HR_USER_INSTITUTION_NAME);
    i.setCountry(MOCK_HR_USER_INSTITUTION_COUNTRY);
    i.setTown(MOCK_HR_USER_INSTITUTION_TOWN);
    p.setInstitute(i);
    
    dto.getParticipations().add(p);
    
    return dto;
  }
  
  
}
