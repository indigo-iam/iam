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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.validation.RegistrationFieldsValidationService;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult;
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;

@RunWith(SpringRunner.class)
@SpringBootTest()
public class RegistrationFieldsValidationServiceTests {

  @Mock
  private IamProperties iamProperties;

  @Mock
  private IamProperties.RegistrationProperties registrationProperties;

  @Mock
  private RegistrationFieldProperties notesFieldProperties;

  @InjectMocks
  private RegistrationFieldsValidationService service;

  @Before
  public void setup() {
    MockitoAnnotations.openMocks(this);

    // Mock the registration properties and fields map
    when(iamProperties.getRegistration()).thenReturn(registrationProperties);
  }

  @Test
  public void testValidateRegistrationRequest_MandatoryCase_notesNotNull() {
    String username = "user_with_notes";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("This is a note");
    request.setPassword("password");

    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
    fieldAttribute.put("notes", notesProperties);

    when(iamProperties.getRegistration().getFields()).thenReturn(fieldAttribute);

    RegistrationRequestValidationResult result =
        service.validateRegistrationRequest(request, Optional.empty());

    assertTrue(result.isOk());
  }

  @Test
  public void testValidateRegistrationRequest_MandatoryCase_notesNull() {

    String username = "user_withy_notes_not_defined";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");

    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
    fieldAttribute.put("notes", notesProperties);

    when(iamProperties.getRegistration().getFields()).thenReturn(fieldAttribute);

    RegistrationRequestValidationResult result =
        service.validateRegistrationRequest(request, Optional.empty());

    assertEquals("Notes field cannot be null", result.getErrorMessage());
  }

  @Test
  public void testValidateRegistrationRequest_MandatoryCase_notesEmpty() {

    String username = "user_with_empty_notes";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");
    request.setNotes("    ");

    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.MANDATORY);
    fieldAttribute.put("notes", notesProperties);

    when(iamProperties.getRegistration().getFields()).thenReturn(fieldAttribute);

    RegistrationRequestValidationResult result =
        service.validateRegistrationRequest(request, Optional.empty());

    assertEquals("Notes field cannot be the empty string", result.getErrorMessage());
  }

  @Test
  public void testValidateRegistrationRequest_OptionalCase() {

    String username = "user_with_notes_field_optional";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");

    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.OPTIONAL);
    fieldAttribute.put("notes", notesProperties);

    when(iamProperties.getRegistration().getFields()).thenReturn(fieldAttribute);

    RegistrationRequestValidationResult result =
        service.validateRegistrationRequest(request, Optional.empty());

    assertTrue(result.isOk());
  }

  @Test
  public void testValidateRegistrationRequest_HiddenCase() {

    String username = "user_with_notes_field_hidden";
    String email = username + "@example.org";

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setPassword("password");

    Map<String, RegistrationFieldProperties> fieldAttribute = new HashMap<>();
    RegistrationFieldProperties notesProperties = new RegistrationFieldProperties();
    notesProperties.setReadOnly(true);
    notesProperties.setExternalAuthAttribute("notes");
    notesProperties.setFieldBehaviour(ExternalAuthAttributeSectionBehaviour.HIDDEN);
    fieldAttribute.put("notes", notesProperties);

    when(iamProperties.getRegistration().getFields()).thenReturn(fieldAttribute);

    RegistrationRequestValidationResult result =
        service.validateRegistrationRequest(request, Optional.empty());

    assertTrue(result.isOk());
  }
}
