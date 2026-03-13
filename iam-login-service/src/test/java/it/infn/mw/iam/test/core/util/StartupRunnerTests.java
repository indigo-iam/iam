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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.text.ParseException;

import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.core.util.StartupRunner;
import it.infn.mw.iam.dashboard.DashboardConfigService;

@SpringBootTest(classes = { IamLoginService.class }
// @formatter:off
  , properties = {
  "iam.dashboard.client-id=dashboard-client-id",
  "iam.dashboard.client-secret=AS69GU9PWvXw3te2RtYqhRYLlNYOhY03IjCnTjeRA69nFXK",
  "iam.dashboard.enabled=true"
// @formatter:on
    })
public class StartupRunnerTests {

  @SpyBean
  private StartupRunner runner;

  @SpyBean
  private DashboardConfigService service;

  @Test
  void shouldStartRunner() throws ParseException {
    verify(runner).run(any(ApplicationArguments.class));

    verify(service, times(1)).initDashboardClient(any(DashboardProperties.class), any(String.class));

  }
}
