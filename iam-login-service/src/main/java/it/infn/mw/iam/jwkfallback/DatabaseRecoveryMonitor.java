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
package it.infn.mw.iam.jwkfallback;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class DatabaseRecoveryMonitor {

    private final FallbackShutdownSignal shutdownSignal;

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseRecoveryMonitor.class);

    private final ConfigurableApplicationContext applicationContext;
    private final String url;
    private final String username;
    private final String password;

    public DatabaseRecoveryMonitor(
            ConfigurableApplicationContext applicationContext,
            FallbackShutdownSignal shutdownSignal,
            @Value("${spring.datasource.url}") String url,
            @Value("${spring.datasource.username}") String username,
            @Value("${spring.datasource.password}") String password) {

        this.applicationContext = applicationContext;
        this.url = url;
        this.username = username;
        this.password = password;
        this.shutdownSignal = shutdownSignal;
    }

    @Scheduled(fixedDelayString = "${iam.jwk.fallback-database-check-interval}")
    public void checkDatabaseConnection() {

        try (Connection connection = DriverManager.getConnection(url, username, password)) {

            if (connection.isValid(2)) {
                LOG.info("Database connection recovered. Stopping JWK fallback.");
                applicationContext.close();
                // Signal only after close() has returned.
                shutdownSignal.signalStopped();
            }

        } catch (SQLException e) {
            LOG.debug("Database is not yet available; fallback remains active.");
        }
    }
}
