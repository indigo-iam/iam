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
package it.infn.mw.iam.test.api.common;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.web.server.ResponseStatusException;

import it.infn.mw.iam.api.account.AccountManagementService;
import it.infn.mw.iam.api.common.ConcurrentChangeExceptionHandler;
import it.infn.mw.iam.api.scim.controller.ScimUserController;

class ConcurrentChangeConflictTests {

  final ConcurrentChangeExceptionHandler handler = new ConcurrentChangeExceptionHandler();

  @Test
  void lostRacesAreConflictsAndOtherCommitFailuresAreRethrown() {

    TransactionSystemException lostRace = new TransactionSystemException("commit failed",
        new IllegalStateException(new SQLException("Deadlock found")));
    TransactionSystemException other = new TransactionSystemException("commit failed");

    assertThat(handler.concurrencyFailure(new CannotAcquireLockException("locked")).getError(),
        containsString("changed by another request"));
    assertThat(handler.commitFailure(lostRace).getError(),
        containsString("changed by another request"));
    assertThrows(TransactionSystemException.class, () -> handler.commitFailure(other));
  }

  @Test
  void removalOfAUserThatLosesARaceIsAConflict() {

    AccountManagementService service = mock(AccountManagementService.class);
    ScimUserController controller = new ScimUserController();
    ReflectionTestUtils.setField(controller, "accountManagementService", service);
    doThrow(new CannotAcquireLockException("locked")).when(service).removeAccount("uuid");

    ResponseStatusException e =
        assertThrows(ResponseStatusException.class, () -> controller.deleteUser("uuid"));
    assertThat(e.getStatus(), is(HttpStatus.CONFLICT));
  }
}
