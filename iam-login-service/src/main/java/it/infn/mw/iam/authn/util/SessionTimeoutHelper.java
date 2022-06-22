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
package it.infn.mw.iam.authn.util;



import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SessionTimeoutHelper {

  public static final long DEFAULT_SESSION_TIMEOUT_SECS = 60;

  final Clock clock;
  final long timeoutInSecs;

  @Autowired
  public SessionTimeoutHelper(Clock clock, @Value("${spring.session.timeout}") long timeoutInSecs) {
    this.clock = clock;
    this.timeoutInSecs = timeoutInSecs;
  }

  public Instant getDefaultSessionExpirationTime() {

    final Instant now = clock.instant();

    if (timeoutInSecs < DEFAULT_SESSION_TIMEOUT_SECS) {
      return now.plus(Duration.ofSeconds(DEFAULT_SESSION_TIMEOUT_SECS));
    }

    return now.plus(Duration.ofSeconds(timeoutInSecs));
  }

}
