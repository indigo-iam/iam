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
import static it.infn.mw.iam.config.IamProperties.RegistrationField.EMAIL;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.NAME;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.NOTES;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.SURNAME;
import static it.infn.mw.iam.config.IamProperties.RegistrationField.USERNAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.when;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEventPublisher;
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
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private IamProperties.RegistrationProperties registrationProperties;

  @Mock
  private RegistrationFieldProperties notesFieldProperties;

  private RegistrationFieldsValidationService service;

  @Before
  public void setup() {
    MockitoAnnotations.openMocks(this);

    // Mock the registration properties and fields map
    when(iamProperties.getRegistration()).thenReturn(registrationProperties);
    service = new RegistrationFieldsValidationService(iamProperties, eventPublisher);
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
    fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, HIDDEN, null));
    fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
    fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(NAME).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(NAME).setFieldBehaviour(MANDATORY);
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(SURNAME, buildFieldProperties(false, HIDDEN, null));
    fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
    fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(SURNAME).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(SURNAME).setFieldBehaviour(MANDATORY);
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(EMAIL, buildFieldProperties(false, HIDDEN, null));
    fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(EMAIL).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(EMAIL).setFieldBehaviour(MANDATORY);
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
    fields.put(USERNAME, buildFieldProperties(false, HIDDEN, null));
    fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(USERNAME).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(USERNAME).setFieldBehaviour(MANDATORY);
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

    Map<RegistrationField, RegistrationFieldProperties> fields =
        new EnumMap<>(RegistrationField.class);
    fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
    fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
    fields.put(NOTES, buildFieldProperties(false, HIDDEN, null));
    when(iamProperties.getRegistration().getFields()).thenReturn(fields);

    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    fields.get(NOTES).setFieldBehaviour(OPTIONAL);
    result = service.validateRegistrationRequest(request, Optional.empty());
    assertTrue(result.isOk());

    // Mandatory: expected error
    fields.get(NOTES).setFieldBehaviour(MANDATORY);
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
