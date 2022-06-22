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
package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.util.SessionTimeoutHelper;

@RunWith(MockitoJUnitRunner.class)
public class SessionTimeoutHelperTests {
  
  public static final Instant NOW = Instant.parse("2019-01-01T00:00:00.00Z");
  public static final Instant NOW_PLUS_60_SECS = NOW.plus(Duration.ofSeconds(60));
  
  Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());
  
  @Test
  public void testTimeout() {
    
    
    SessionTimeoutHelper timeoutHelper = new SessionTimeoutHelper(clock, 0);
    
    Instant sessionTimeout = timeoutHelper.getDefaultSessionExpirationTime();
    
    assertThat(sessionTimeout, is(NOW_PLUS_60_SECS));
    
    timeoutHelper = new SessionTimeoutHelper(clock, 59);
    
    sessionTimeout = timeoutHelper.getDefaultSessionExpirationTime();
    
    assertThat(sessionTimeout, is(NOW_PLUS_60_SECS));
    
    timeoutHelper = new SessionTimeoutHelper(clock, 120);
    
    sessionTimeout = timeoutHelper.getDefaultSessionExpirationTime();
    
    assertThat(sessionTimeout, is(NOW.plus(Duration.ofSeconds(120))));
    
  }
  
  
  

}
