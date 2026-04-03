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

package it.infn.mw.iam.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.dashboard.DashboardConfigService;

@Component
public class StartupRunner implements ApplicationRunner {

  private static final Logger LOG = LoggerFactory.getLogger(StartupRunner.class);

  private final DashboardConfigService dashboardConfigService;

  public StartupRunner(DashboardConfigService dashboardConfigService) {
    this.dashboardConfigService = dashboardConfigService;
  }

  @Override
  public void run(ApplicationArguments args) {
    if (!dashboardConfigService.isEnabled()) {
      LOG.info("Skipping dashboard client initialization.");
      return;
    }

    boolean isValid = dashboardConfigService.init();
    if (!isValid) {
      throw new IllegalStateException(
          "Dashboard client record does not exist or is not valid. Please check the dashboard client properties and ensure that a record with the specified client id, client secret and redirect uri exists in the database");
    }
  }
}
