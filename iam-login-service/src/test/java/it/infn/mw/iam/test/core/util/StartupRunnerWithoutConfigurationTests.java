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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.dashboard.DashboardConfigService;

@SpringBootTest(classes = { IamLoginService.class })
@TestPropertySource(properties = "iam.dashboard.enabled=false")
public class StartupRunnerWithoutConfigurationTests {

  @MockBean
  private DashboardConfigService myService;

  @Test
  void testRunnerDoesNotInitializeDashboard() throws IllegalStateException {
    verify(myService, times(0)).initDashboardClient(any(DashboardProperties.class), any(String.class));
  }
}
