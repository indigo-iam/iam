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
package it.infn.mw.iam.test.core.mfa;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;

import it.infn.mw.iam.core.mfa.IamTotpMfaKeyRotationRunner;
import it.infn.mw.iam.core.mfa.IamTotpSecretRotationService;

@ExtendWith(MockitoExtension.class)
class IamTotpMfaKeyRotationRunnerTests {

  @Mock
  private IamTotpSecretRotationService service;

  private IamTotpMfaKeyRotationRunner runner;

  @BeforeEach
  void initRunner() {
    runner = new IamTotpMfaKeyRotationRunner(service);
  }

  @Test
  void runnerDoesNothingWhenRotationIsNotNeeded() {

    when(service.shouldRotateSecrets()).thenReturn(false);
    runner.run(mock(ApplicationArguments.class));
    verify(service, never()).rotateSecrets();
  }

  @Test
  void runnerExecutesRotationWhenNeeded() {

    when(service.shouldRotateSecrets()).thenReturn(true);
    runner.run(mock(ApplicationArguments.class));
    verify(service).rotateSecrets();
  }
}
