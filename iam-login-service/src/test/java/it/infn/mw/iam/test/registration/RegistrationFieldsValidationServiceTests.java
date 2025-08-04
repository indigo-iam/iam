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

import static it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour.HIDDEN;
import static it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour.MANDATORY;
import static it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour.OPTIONAL;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.email;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.name;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.notes;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.surname;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.username;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationField;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.validation.RegistrationFieldsValidationService;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult;

@RunWith(SpringRunner.class)
@SpringBootTest()
public class RegistrationFieldsValidationServiceTests {

  private final String TEST_USERNAME = "unregistereduser";
  private final String TEST_EMAIL = TEST_USERNAME + "@example.com";
  private final String TEST_GIVEN_NAME = "unregistered";
  private final String TEST_FAMILY_NAME = "unregistered";
  private final String TEST_NOTES = "This is a note";

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

  private RegistrationFieldProperties buildFieldProperties(boolean isReadOnly,
      ExternalAuthAttributeSectionBehaviour behaviour, String externalAuthAttribute) {
    RegistrationFieldProperties fieldProperties = new RegistrationFieldProperties();
    fieldProperties.setReadOnly(isReadOnly);
    fieldProperties.setFieldBehaviour(behaviour);
    fieldProperties.setExternalAuthAttribute(externalAuthAttribute);
    return fieldProperties;
  }

  private RegistrationRequestDto getDefaultFullRegistrationRequest() {
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname(TEST_GIVEN_NAME);
    request.setFamilyname(TEST_FAMILY_NAME);
    request.setEmail(TEST_EMAIL);
    request.setUsername(TEST_USERNAME);
    request.setNotes(TEST_NOTES);
    return request;
  }

  @Test
  public void testAllMandatoryFieldsAreProvided() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, MANDATORY, null));
    fields.put(surname, buildFieldProperties(false, MANDATORY, null));
    fields.put(email, buildFieldProperties(false, MANDATORY, null));
    fields.put(username, buildFieldProperties(false, MANDATORY, null));
    fields.put(notes, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());
  }

  @Test
  public void testGivenNameWithDifferentBehaviours() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();
    request.setGivenname(null);

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, HIDDEN, null));
    fields.put(surname, buildFieldProperties(false, MANDATORY, null));
    fields.put(email, buildFieldProperties(false, MANDATORY, null));
    fields.put(username, buildFieldProperties(false, MANDATORY, null));
    fields.put(notes, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(name).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(name).setFieldBehaviour(MANDATORY);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory name field cannot be null or an empty string",
        result.getErrorMessage());

    request.setGivenname("");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory name field cannot be null or an empty string",
        result.getErrorMessage());

    request.setGivenname("   ");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory name field cannot be null or an empty string",
        result.getErrorMessage());
  }

  @Test
  public void testFamilyNameWithDifferentBehaviours() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();
    request.setFamilyname(null);

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, MANDATORY, null));
    fields.put(surname, buildFieldProperties(false, HIDDEN, null));
    fields.put(email, buildFieldProperties(false, MANDATORY, null));
    fields.put(username, buildFieldProperties(false, MANDATORY, null));
    fields.put(notes, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(surname).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(surname).setFieldBehaviour(MANDATORY);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory surname field cannot be null or an empty string",
        result.getErrorMessage());

    request.setFamilyname("");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory surname field cannot be null or an empty string",
        result.getErrorMessage());

    request.setFamilyname("   ");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory surname field cannot be null or an empty string",
        result.getErrorMessage());
  }

  @Test
  public void testEmailWithDifferentBehaviours() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();
    request.setEmail(null);

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, MANDATORY, null));
    fields.put(surname, buildFieldProperties(false, MANDATORY, null));
    fields.put(email, buildFieldProperties(false, HIDDEN, null));
    fields.put(username, buildFieldProperties(false, MANDATORY, null));
    fields.put(notes, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(email).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(email).setFieldBehaviour(MANDATORY);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory email field cannot be null or an empty string",
        result.getErrorMessage());

    request.setEmail("");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory email field cannot be null or an empty string",
        result.getErrorMessage());

    request.setEmail("   ");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory email field cannot be null or an empty string",
        result.getErrorMessage());
  }

  @Test
  public void testUsernameWithDifferentBehaviours() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();
    request.setUsername(null);

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, MANDATORY, null));
    fields.put(surname, buildFieldProperties(false, MANDATORY, null));
    fields.put(email, buildFieldProperties(false, MANDATORY, null));
    fields.put(username, buildFieldProperties(false, HIDDEN, null));
    fields.put(notes, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(username).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(username).setFieldBehaviour(MANDATORY);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory username field cannot be null or an empty string",
        result.getErrorMessage());

    request.setUsername("");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory username field cannot be null or an empty string",
        result.getErrorMessage());

    request.setUsername("   ");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory username field cannot be null or an empty string",
        result.getErrorMessage());
  }

  @Test
  public void testNotesWithDifferentBehaviours() {

    RegistrationRequestDto request;
    RegistrationRequestValidationResult result;

    // Hidden or Optional: null is ignored
    request = getDefaultFullRegistrationRequest();
    request.setNotes(null);

    Map<RegistrationField, RegistrationFieldProperties> fields = new HashMap<>();
    fields.put(name, buildFieldProperties(false, MANDATORY, null));
    fields.put(surname, buildFieldProperties(false, MANDATORY, null));
    fields.put(email, buildFieldProperties(false, MANDATORY, null));
    fields.put(username, buildFieldProperties(false, MANDATORY, null));
    fields.put(notes, buildFieldProperties(false, HIDDEN, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(notes).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(notes).setFieldBehaviour(MANDATORY);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory notes field cannot be null or an empty string",
        result.getErrorMessage());

    request.setNotes("");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory notes field cannot be null or an empty string",
        result.getErrorMessage());

    request.setNotes("   ");
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertFalse(result.isOk());
    assertEquals("Mandatory notes field cannot be null or an empty string",
        result.getErrorMessage());
  }

}
