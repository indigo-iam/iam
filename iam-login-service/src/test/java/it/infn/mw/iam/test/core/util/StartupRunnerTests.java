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
package it.infn.mw.iam.test.core.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.text.ParseException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;
import it.infn.mw.iam.core.util.StartupRunner;
import it.infn.mw.iam.dashboard.DashboardConfigService;

@ExtendWith(MockitoExtension.class)
class StartupRunnerTests {

  @Mock
  private DashboardConfigService service;

  private StartupRunner runner;

  @BeforeEach
  void initRunner() {
    runner = new StartupRunner(service);
  }

  @Test
  void testRunnerInitializesDashboard() throws ParseException {
    when(service.isEnabled()).thenReturn(true);
    runner.run(mock(ApplicationArguments.class));
    assertDoesNotThrow(() -> runner.run(mock(ApplicationArguments.class)));
    verify(service, times(2)).init();
  }

  @Test
  void testRunnerDoesNotInitializeDashboard() throws ParseException {
    when(service.isEnabled()).thenReturn(false);
    runner.run(mock(ApplicationArguments.class));
    verify(service, times(0)).init();
  }

  @Test
  void testRunnerThrowsExceptionOnInitializationFailure() throws ParseException {
    when(service.isEnabled()).thenReturn(true);
    doThrow(new ParseException("Test exception", 0)).when(service).init();
    assertThrows(IllegalStateException.class, () -> runner.run(mock(ApplicationArguments.class)));
    verify(service, times(1)).init();
  }
}
