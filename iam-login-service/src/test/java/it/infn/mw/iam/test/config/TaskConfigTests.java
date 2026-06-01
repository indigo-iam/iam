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

package it.infn.mw.iam.test.config;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;
import org.springframework.test.util.ReflectionTestUtils;

import it.infn.mw.iam.config.TaskConfig;
import it.infn.mw.iam.registration.RegistrationRequestService;

@ExtendWith(MockitoExtension.class)
class TaskConfigTests {
    @Mock
    private ScheduledTaskRegistrar taskRegistrar;

    @Mock
    private RegistrationRequestService registrationRequestService;

    @InjectMocks
    private TaskConfig taskConfig;

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(taskConfig, "expiryDays", 7L);
        ReflectionTestUtils.setField(taskConfig, "cleanupExpiredRegistrationCronSchedule", "0 0 * * * *");
    }

    @Test
    void shouldNotScheduleTaskWhenDisabled() {

        ReflectionTestUtils.setField(taskConfig,
                "cleanupExpiredRegistrationCronScheduleEnable", false);

        taskConfig.scheduledCleanUpExpireRegistrationTask(taskRegistrar);

        verify(taskRegistrar, never())
                .addCronTask(any(Runnable.class), anyString());
    }

    @Test
    void shouldScheduleTaskWhenEnabled() {

        ReflectionTestUtils.setField(taskConfig,
                "cleanupExpiredRegistrationCronScheduleEnable", true);

        taskConfig.scheduledCleanUpExpireRegistrationTask(taskRegistrar);

        verify(taskRegistrar, times(1))
                .addCronTask(any(Runnable.class), eq("0 0 * * * *"));
    }

    @Test
    void shouldExecuteScheduledTaskAndCallService() {

        ReflectionTestUtils.setField(taskConfig,
                "cleanupExpiredRegistrationCronScheduleEnable", true);

        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

        taskConfig.scheduledCleanUpExpireRegistrationTask(taskRegistrar);

        verify(taskRegistrar).addCronTask(
                runnableCaptor.capture(),
                anyString());

        Runnable task = runnableCaptor.getValue();
        assertNotNull(task);

        task.run();

        verify(registrationRequestService, times(1))
                .cleanupExpiredRegistrationRequests(any(Instant.class));
    }

    @Test
    void shouldCalculateCorrectExpiryTime() {

        ReflectionTestUtils.setField(taskConfig,
                "cleanupExpiredRegistrationCronScheduleEnable", true);

        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

        taskConfig.scheduledCleanUpExpireRegistrationTask(taskRegistrar);

        verify(taskRegistrar).addCronTask(
                runnableCaptor.capture(),
                anyString());

        Runnable task = runnableCaptor.getValue();

        Instant beforeRun = Instant.now().minus(7, ChronoUnit.DAYS);

        task.run();

        ArgumentCaptor<Instant> instantCaptor = ArgumentCaptor.forClass(Instant.class);

        verify(registrationRequestService)
                .cleanupExpiredRegistrationRequests(instantCaptor.capture());

        Instant actual = instantCaptor.getValue();

        // allow slight time drift
        assertTrue(!actual.isBefore(beforeRun.minusSeconds(2)) &&
                !actual.isAfter(beforeRun.plusSeconds(2)));
    }
}