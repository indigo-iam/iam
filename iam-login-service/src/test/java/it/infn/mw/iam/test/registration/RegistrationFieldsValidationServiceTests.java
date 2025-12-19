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
import static it.infn.mw.iam.config.IamProperties.RegistrationField.CERTIFICATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ExternalAuthAttributeSectionBehaviour;
import it.infn.mw.iam.config.IamProperties.RegistrationField;
import it.infn.mw.iam.config.IamProperties.RegistrationFieldProperties;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.registration.validation.RegistrationFieldsValidationService;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidationResult;

@ExtendWith(SpringExtension.class)
class RegistrationFieldsValidationServiceTests {

    private final String TEST_USERNAME = "unregistereduser";
    private final String TEST_EMAIL = TEST_USERNAME + "@example.com";
    private final String TEST_GIVEN_NAME = "unregistered";
    private final String TEST_FAMILY_NAME = "unregistered";
    private final String TEST_NOTES = "This is a note";
    private final String TEST_CERT = """
                      -----BEGIN CERTIFICATE-----
            MIIDkDCCAnigAwIBAgIUIRiHqEUe9NMkryEsI23CTkMamdgwDQYJKoZIhvcNAQEL
            BQAwLDELMAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAx
            MB4XDTI1MDcwMTEzMjgwMFoXDTM1MDYyOTEzMjgwMFowLDELMAkGA1UEBhMCSVQx
            DDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAxMIIBIjANBgkqhkiG9w0BAQEF
            AAOCAQ8AMIIBCgKCAQEA2RuUgUXeAFM9/wOiAMrhttRp2zImtZVRkYFNwawPVxve
            5SCENZjEivQ3f1PtmFGxG0YboZGu0dR2n9MV3GGNFJkrhAet7fAwoZr8BvoQaEjr
            yC9I5z3fpwwwabfpsFPe04CeWfXHmSMQoHLXYQqxLi8etzcJZ1tsBT1yAUwbkqNx
            95bgl4FBaU7iv+jqdxf4aoa5n8QUeM0+CtM/RSQQLQtlKItQRyib8MxYDeRcc3pB
            VaysLLj1I0bsVZgFM7Qg/2oftsQAMiRqRM0byz2VNBvuaSgZ3gZpOyB/+0P/SGPK
            WHnxLZMV/Wy5RDckoG4zHVIxIiEeYDD0txnhLsNIxwIDAQABo4GpMIGmMAwGA1Ud
            EwQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTMwWkWHGWur+WQk7BR
            VNguNPY5MDBnBgNVHSMEYDBegBTMwWkWHGWur+WQk7BRVNguNPY5MKEwpC4wLDEL
            MAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEPMA0GA1UEAwwGdGVzdDAxghQhGIeo
            RR700ySvISwjbcJOQxqZ2DANBgkqhkiG9w0BAQsFAAOCAQEApWB8P+CQCeJCsOKA
            65DBE6jCoXS1He+iG5eFfw/GuKZhRe7zLZsObAH+DKqbjkCLsHsRoEUo8EPErmvY
            GDE58Zrv8fsqakcNseRBcLHgBmPiZgDEIk3yd9S/3mAFaY4D7KLb/2uOHSBc72Ax
            C3zYT8VA6C7wEiSW+Fg9gbXwMb34Xj6xGIm2+74iogwrQd9l2geyfSLirpUvZe24
            otjNLk3d7XQ1mSjiUx+6+blzwdIkaoVjbS0WsYOdtaPo+wuPGQieyzWvnIdOl8sd
            9ovNoFyB1LkUaWImlLucqRKdhuAy/e+9lurYpQ1uft86ep1p6pimEmb7bOQYcKEo
            jARH0w==
            -----END CERTIFICATE-----
                      """;

    @Mock
    private IamProperties iamProperties;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private IamProperties.RegistrationProperties registrationProperties;

    @Mock
    private RegistrationFieldProperties notesFieldProperties;

    private RegistrationFieldsValidationService service;

    @BeforeEach
    void setup() {
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
        request.setCertificate(TEST_CERT);
        return request;
    }

    @Test
    void testAllMandatoryFieldsAreProvided() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
        when(iamProperties.getRegistration().getFields()).thenReturn(fields);

        result = service.validateRegistrationRequest(request, Optional.empty());
        assertTrue(result.isOk());
    }

    @Test
    void testGivenNameWithDifferentBehaviours() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
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
    void testFamilyNameWithDifferentBehaviours() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
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
    void testEmailWithDifferentBehaviours() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
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
    void testUsernameWithDifferentBehaviours() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
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
    void testNotesWithDifferentBehaviours() {

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
        fields.put(CERTIFICATE, buildFieldProperties(false, MANDATORY, null));
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

    @Test
    void testCertificateWithDifferentBehaviours() {

        RegistrationRequestDto request;
        RegistrationRequestValidationResult result;

        // Hidden or Optional: null is ignored
        request = getDefaultFullRegistrationRequest();
        request.setCertificate(null);

        Map<RegistrationField, RegistrationFieldProperties> fields =
                new EnumMap<>(RegistrationField.class);
        fields.put(NAME, buildFieldProperties(false, MANDATORY, null));
        fields.put(SURNAME, buildFieldProperties(false, MANDATORY, null));
        fields.put(EMAIL, buildFieldProperties(false, MANDATORY, null));
        fields.put(USERNAME, buildFieldProperties(false, MANDATORY, null));
        fields.put(NOTES, buildFieldProperties(false, MANDATORY, null));
        fields.put(CERTIFICATE, buildFieldProperties(false, HIDDEN, null));
        when(iamProperties.getRegistration().getFields()).thenReturn(fields);

        result = service.validateRegistrationRequest(request, Optional.empty());
        assertTrue(result.isOk());

        fields.get(CERTIFICATE).setFieldBehaviour(OPTIONAL);
        result = service.validateRegistrationRequest(request, Optional.empty());
        assertTrue(result.isOk());

        // Mandatory: expected error
        fields.get(CERTIFICATE).setFieldBehaviour(MANDATORY);
        result = service.validateRegistrationRequest(request, Optional.empty());
        assertFalse(result.isOk());
        assertEquals("Mandatory certificate field cannot be null or an empty string",
                result.getErrorMessage());

        request.setCertificate("");
        result = service.validateRegistrationRequest(request, Optional.empty());
        assertFalse(result.isOk());
        assertEquals("Mandatory certificate field cannot be null or an empty string",
                result.getErrorMessage());

        request.setCertificate("   ");
        result = service.validateRegistrationRequest(request, Optional.empty());
        assertFalse(result.isOk());
        assertEquals("Mandatory certificate field cannot be null or an empty string",
                result.getErrorMessage());
    }

}
