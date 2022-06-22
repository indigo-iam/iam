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

import org.flywaydb.core.internal.exception.FlywaySqlException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

public class WrongFlywayVersionFailureAnalyzer extends AbstractFailureAnalyzer<FlywaySqlException> {

  private static final String ERROR_DESCRIPTION =
      "An error occurred while upgrading the IAM database schema";

  private static final String FLYWAY_NEEDS_UPGRADE_MARKER =
      "'version_rank' doesn't have a default value";

  private static final String UPGRADE_TO_V172_FIRST =
      "You are trying to upgrade to v1.8.0 from an invalid IAM version. Please first upgrade your installation to v1.7.2 and then upgrade to v1.8.0!";

  @Override
  protected FailureAnalysis analyze(Throwable rootFailure, FlywaySqlException cause) {
    if (cause.getMessage().contains(FLYWAY_NEEDS_UPGRADE_MARKER)) {
      return new FailureAnalysis(getDescription(cause), UPGRADE_TO_V172_FIRST, cause);
    }
    return null;
  }

  private String getDescription(FlywaySqlException cause) {
    return String.format("%s: %s", ERROR_DESCRIPTION,
        cause.getMessage());
  }

}
