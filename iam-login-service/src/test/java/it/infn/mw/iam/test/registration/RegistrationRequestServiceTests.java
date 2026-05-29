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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.repository.IamRegistrationRequestRepository;
import it.infn.mw.iam.registration.DefaultRegistrationRequestService;

@ExtendWith(MockitoExtension.class)
class RegistrationRequestServiceTests {

    @Mock
    private IamRegistrationRequestRepository requestRepository;

    @Mock
    private IamAccountService accountService;

    @InjectMocks
    private DefaultRegistrationRequestService registrationRequestService;

    private Instant expiryTime;
    private Date expiryDate;

    @BeforeEach
    void setup() {
        expiryTime = Instant.now().minus(7, ChronoUnit.DAYS);
        expiryDate = Date.from(expiryTime);
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void shouldDeleteRegistrationsAndAccounts() {

        List<Long> accountIds = List.of(1L, 2L);

        when(requestRepository.findAccountIdsForExpiredRegistrations(expiryDate))
                .thenReturn(accountIds);

        when(requestRepository.deleteExpiredRegistrations(expiryDate))
                .thenReturn(2);

        when(accountService.deleteAccountsForExpiredRegistrations(accountIds))
                .thenReturn(2);

        registrationRequestService.cleanupExpiredRequests(expiryTime);

        verify(requestRepository).findAccountIdsForExpiredRegistrations(expiryDate);
        verify(requestRepository).deleteExpiredRegistrations(expiryDate);
        verify(accountService).deleteAccountsForExpiredRegistrations(accountIds);
    }

    @Test
    public void shouldHandleNoExpiredRegistrations() {

        when(requestRepository.findAccountIdsForExpiredRegistrations(expiryDate))
                .thenReturn(Collections.emptyList());

        registrationRequestService.cleanupExpiredRequests(expiryTime);

        verify(accountService, never()).deleteAccountsForExpiredRegistrations(Collections.emptyList());
    }

    @Test
    public void shouldDeleteRegistrationsBeforeAccounts() {

        List<Long> accountIds = List.of(1L);

        when(requestRepository.findAccountIdsForExpiredRegistrations(any()))
                .thenReturn(accountIds);

        when(requestRepository.deleteExpiredRegistrations(any()))
                .thenReturn(1);

        when(accountService.deleteAccountsForExpiredRegistrations(accountIds))
                .thenReturn(1);

        registrationRequestService.cleanupExpiredRequests(expiryTime);

        InOrder inOrder = inOrder(requestRepository, accountService);

        inOrder.verify(requestRepository).findAccountIdsForExpiredRegistrations(any());
        inOrder.verify(requestRepository).deleteExpiredRegistrations(any());
        inOrder.verify(accountService).deleteAccountsForExpiredRegistrations(accountIds);
    }

    @Test
    public void shouldPropagateExceptionAndRollback() {

        when(requestRepository.findAccountIdsForExpiredRegistrations(any()))
                .thenThrow(new RuntimeException("DB failure"));

        assertThrows(RuntimeException.class,
                () -> registrationRequestService.cleanupExpiredRequests(expiryTime));

        verify(requestRepository, never()).deleteExpiredRegistrations(any());
        verify(accountService, never()).deleteAccountsForExpiredRegistrations(any());
    }

}
