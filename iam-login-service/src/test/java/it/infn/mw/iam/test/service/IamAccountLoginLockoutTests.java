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
package it.infn.mw.iam.test.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;

class IamAccountLoginLockoutTests {

  private static final Instant NOW = Instant.parse("2026-10-13T10:00:00Z");

  @ParameterizedTest
  @NullSource
  @ValueSource(longs = {0, -1})
  void nonPositiveOrNullDurationIsRejectedWithoutChangingState(Long seconds) {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout();
    lockout.setLockoutCount(2);
    Date previousEnd = Date.from(NOW.plusSeconds(60));
    lockout.setSuspendedUntil(previousEnd);
    Duration duration = seconds == null ? null : Duration.ofSeconds(seconds);
    assertThrows(IllegalArgumentException.class, () -> lockout.applySuspension(NOW, duration));
    assertEquals(previousEnd, lockout.getSuspendedUntil());
    assertEquals(2, lockout.getLockoutCount());
  }

  @Test
  void suspensionExpiresExactlyAtItsEnd() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout();
    assertFalse(lockout.isSuspended(NOW));
    lockout.applySuspension(NOW, Duration.ofSeconds(60));
    assertEquals(1, lockout.getLockoutCount());
    assertEquals(Date.from(NOW.plusSeconds(60)), lockout.getSuspendedUntil());
    assertTrue(lockout.isSuspended(NOW.plusSeconds(59)));
    assertFalse(lockout.isSuspended(NOW.plusSeconds(60)));
    assertFalse(lockout.isSuspended(NOW.plusSeconds(61)));
  }

  @Test
  void clearingRoundPreservesHistoricalCount() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout();
    lockout.setFailedAttempts(3);
    lockout.setFirstFailureTime(Date.from(NOW));
    lockout.applySuspension(NOW, Duration.ofMinutes(5));
    lockout.clearCurrentRound();
    assertEquals(0, lockout.getFailedAttempts());
    assertNull(lockout.getFirstFailureTime());
    assertNull(lockout.getSuspendedUntil());
    assertEquals(1, lockout.getLockoutCount());
    assertTrue(lockout.isCurrentRoundEmpty());
    assertFalse(lockout.isSuspended(NOW));
  }

  @Test
  void roundIsEmptyOnlyWhenAllCurrentRoundFieldsAreEmpty() {
    IamAccountLoginLockout lockout = new IamAccountLoginLockout();
    assertTrue(lockout.isCurrentRoundEmpty());
    lockout.setFailedAttempts(1);
    assertFalse(lockout.isCurrentRoundEmpty());
    lockout.clearCurrentRound();
    lockout.setFirstFailureTime(Date.from(NOW));
    assertFalse(lockout.isCurrentRoundEmpty());
    lockout.clearCurrentRound();
    lockout.setSuspendedUntil(Date.from(NOW));
    assertFalse(lockout.isCurrentRoundEmpty());
  }
}
