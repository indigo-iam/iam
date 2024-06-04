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
package it.infn.mw.iam.test.registration;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.core.user.IamAccountService;

import it.infn.mw.iam.registration.DefaultRegistrationRequestService;
import it.infn.mw.iam.registration.RegistrationRequestDto;

import it.infn.mw.iam.registration.validation.RegistrationRequestValidatorError;

public class DefaultRegistrationRequestServiceTests {

    @InjectMocks
    private DefaultRegistrationRequestService service;

    @Mock
    private IamAccountService accountService;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testCreateRequestWithNotesBeingMandatoryField() {
      String username = "user_with_empty_notes";
      String email = username + "@example.org";

      RegistrationRequestDto request = new RegistrationRequestDto();
      request.setGivenname("Test");
      request.setFamilyname("User");
      request.setEmail(email);
      request.setUsername(username);
      request.setPassword("password");

      Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
      RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
      notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
      fieldAttribute.put("notes", notesProperties);

      Exception exception = assertThrows(RegistrationRequestValidatorError.class, () -> {
        service.createRequest(request, Optional.empty(), fieldAttribute);
      });

      assertTrue(exception.getMessage().contains("Notes field cannot be null"));
    }

    @Test
    void testCreateRequestWithNotesBeingMandatoryFieldCase2() {
      String username = "user_with_empty_notes";
      String email = username + "@example.org";

      RegistrationRequestDto request = new RegistrationRequestDto();
      request.setGivenname("Test");
      request.setFamilyname("User");
      request.setEmail(email);
      request.setUsername(username);
      request.setNotes("   ");
      request.setPassword("password");

      Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
      RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
      notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
      fieldAttribute.put("notes", notesProperties);

      Exception exception = assertThrows(RegistrationRequestValidatorError.class, () -> {
        service.createRequest(request, Optional.empty(), fieldAttribute);
      });

      assertTrue(exception.getMessage().contains("Notes field cannot be the empty string"));
    }
  }
