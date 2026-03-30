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
package it.infn.mw.iam.test.util.clock;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;


public class MutableClock extends Clock {

  private Instant instant;

  public MutableClock(Clock clock) {
    instant = clock.instant();
  }

  public void advance(Duration duration) {
    instant = instant.plus(duration);
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }

  @Override
  public Instant instant() {
    return instant;
  }

  public LocalDate localDate() {
    return LocalDate.now(this);
  }

  public Date now() {
    return Date.from(instant);
  }

  public Instant lastMidnight() {
    return instant.truncatedTo(ChronoUnit.DAYS);
  }

  public Instant daysBefore(int days) {
    return instant.minus(days, ChronoUnit.DAYS);
  }

  public Instant daysAfter(int days) {
    return instant.plus(days, ChronoUnit.DAYS);
  }

}
