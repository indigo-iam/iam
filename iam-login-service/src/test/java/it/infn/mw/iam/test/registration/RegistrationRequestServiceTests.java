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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW;
import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.registration.DefaultRegistrationRequestService;
import it.infn.mw.iam.registration.RegistrationConverter;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;

@ExtendWith(MockitoExtension.class)
class RegistrationRequestServiceTests {

    @InjectMocks
    private DefaultRegistrationRequestService service;

    @Mock
    private IamRegistrationRequest request;

    @Mock
    private RegistrationConverter converter;

    @Mock 
    private NotificationFactory notificationFactory;

    @Mock 
    private IamAccountService accountService; 

    @Mock 
    private ApplicationEventPublisher eventPublisher;

    @Mock 
    private IamAccount account; 

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldReturnDtoWhenStatusTransitionIsValid() {
        
        when(request.getStatus()).thenReturn(NEW);
        when(request.getAccount()).thenReturn(account);
        when(account.getUsername()).thenReturn("test-user");

        RegistrationRequestDto dto = new RegistrationRequestDto();
       
        when(converter.fromEntity(any(IamRegistrationRequest.class)))
                .thenReturn(dto);

        RegistrationRequestDto result = service.timeoutRequest(request);

        assertNotNull(result);
        assertEquals(dto, result);

        verify(converter).fromEntity(any());
        verify(accountService).deleteAccount(account);
        verify(eventPublisher).publishEvent(any());
    }

    @Test
    void shouldThrowExceptionWhenStatusTransitionIsInvalid() {

        when(request.getStatus()).thenReturn(APPROVED);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> service.timeoutRequest(request)
        );

        assertTrue(exception.getMessage().contains("Bad status transition"));
    }
}
