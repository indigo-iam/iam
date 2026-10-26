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
package it.infn.mw.iam.test.fallbackJwk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.context.ConfigurableApplicationContext;

import it.infn.mw.iam.jwkfallback.DatabaseRecoveryMonitor;
import it.infn.mw.iam.jwkfallback.FallbackShutdownSignal;

public class DatabaseRecoveryMonitorTests {

    @Test
    void exitsWithFailureStatusOnceDatabaseIsReachable() {
        ConfigurableApplicationContext context = mock(ConfigurableApplicationContext.class);
        AtomicInteger exitStatus = new AtomicInteger(Integer.MIN_VALUE);

        new DatabaseRecoveryMonitor(context, new FallbackShutdownSignal(),
                "jdbc:h2:mem:recovery", "sa", "", exitStatus::set).checkDatabaseConnection();

        verify(context).close();
        assertEquals(1, exitStatus.get());
    }

    @Test
    void doesNothingWhileDatabaseIsUnreachable() {
        ConfigurableApplicationContext context = mock(ConfigurableApplicationContext.class);
        AtomicInteger exitStatus = new AtomicInteger(Integer.MIN_VALUE);

        new DatabaseRecoveryMonitor(context, new FallbackShutdownSignal(),
                "jdbc:h2:tcp://localhost:1/mem:none", "sa", "", exitStatus::set).checkDatabaseConnection();

        verify(context, never()).close();
        assertEquals(Integer.MIN_VALUE, exitStatus.get());
    }
}
