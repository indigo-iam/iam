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

import java.io.IOException;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.h2.tools.Server;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.http.HttpHeaders;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.jwk.JWKTestSupport;

public class FallbackApplicationStartupTests implements JWKTestSupport {

    private final String LICENSE = "Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021";
    private static final String MYSQL_PROFILE = "--spring.profiles.active=mysql-test";

    @Test
    void fallbackServesJwkWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking the jwk endpoint
            HttpResponse<String> jwk = awaitResponse(app, failure, port, "/jwk", Duration.ofSeconds(60));
            assertEquals(200, jwk.statusCode());
            JsonNode keys = new ObjectMapper().readTree(jwk.body()).get("keys");
            assertEquals(1, keys.size());
            assertEquals("iam", keys.get(0).get("kid").asText());

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackServesInfoWithNoUrlWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true",
                "--iam.logo.url=" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking the /fallback-info endpoint works without image
            HttpResponse<String> info = awaitResponse(app, failure, port, "/fallback-info", Duration.ofSeconds(60));
            assertEquals(503, info.statusCode());
            assertTrue(info.body().contains(LICENSE));
            assertFalse(info.body().contains("<img"));

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackServesInfoWithUrlWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true",
                "--iam.logo.url=https://cern-ipmc.web.cern.ch/logo" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking the /fallback-info endpoint works with external web image
            HttpResponse<String> info = awaitResponse(app, failure, port, "/fallback-info", Duration.ofSeconds(60));
            assertEquals(503, info.statusCode());
            assertTrue(info.body().contains(LICENSE));
            assertTrue(info.body().contains("src=\"https://cern-ipmc.web.cern.ch/logo\""));

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackHandlesBrowserAndClientWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking the /fallback-info endpoint for client
            HttpResponse<String> fallbackInfo = awaitResponse(app, failure, port, "/fallback-info",
                    Duration.ofSeconds(60));
            assertEquals(503, fallbackInfo.statusCode());
            assertTrue(fallbackInfo.body().contains(LICENSE));

            // Checking that browser displays the page at /fallback-info endpoint
            HttpResponse<String> fallbackInfoBrowser = getBrowser(port, "/fallback-info");
            assertEquals(503, fallbackInfoBrowser.statusCode());
            assertTrue(fallbackInfoBrowser.body().contains(LICENSE));

            // Checking that one is redirected from a browser
            HttpResponse<String> loginBrowser = getBrowser(port, "/login");
            assertEquals(302, loginBrowser.statusCode());
            assertEquals(String.format("http://localhost:%d/fallback-info", port),
                    loginBrowser.headers().allValues("location").get(0));

            // Checking a client doesn't get redirect, but 503
            HttpResponse<String> login = get(port, "/login");
            assertEquals(503, login.statusCode());
            assertEquals(0, login.headers().allValues("location").size());

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackServesActuatorWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking /actuator endpoint
            HttpResponse<String> actuator = awaitResponse(app, failure, port, "/actuator", Duration.ofSeconds(60));
            assertEquals(200, actuator.statusCode());
            JsonNode actuatorContent = new ObjectMapper().readTree(actuator.body()).get("_links");
            assertEquals(4, actuatorContent.size());
            assertTrue(actuatorContent.has("self"));
            assertTrue(actuatorContent.has("health"));
            assertTrue(actuatorContent.has("health-path"));
            assertTrue(actuatorContent.has("info"));

            // Checking /actuator/info endpoint
            HttpResponse<String> actuatorInfo = get(port, "/actuator/info");
            assertEquals(200, actuatorInfo.statusCode());
            JsonNode actuatorInfoContent = new ObjectMapper().readTree(actuatorInfo.body());
            assertEquals(2, actuatorInfoContent.size());
            assertTrue(actuatorInfoContent.has("git"));
            assertTrue(actuatorInfoContent.has("build"));
            // Checks the time formatting
            assertTrue(actuatorInfoContent.get("git").get("commit").get("time").isNumber());
            assertTrue(actuatorInfoContent.get("build").get("time").isNumber());

            // Checking /actuator/health endpoint
            HttpResponse<String> actuatorHealth = get(port, "/actuator/health");
            assertEquals(200, actuatorHealth.statusCode());
            JsonNode actuatorHealthContent = new ObjectMapper().readTree(actuatorHealth.body());
            assertEquals(2, actuatorHealthContent.size());
            assertEquals("UP", actuatorHealthContent.get("status").asText());
            assertEquals("DOWN", actuatorHealthContent.get("components").get("db").get("status").asText());
            assertEquals("UP", actuatorHealthContent.get("components").get("ping").get("status").asText());
            assertEquals("UP", actuatorHealthContent.get("components").get("diskSpace").get("status").asText());

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackServesHealthPathEndpointWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        try {

            // Checking /actuator/health/db
            HttpResponse<String> actuatorHealthDb = awaitResponse(app, failure, port, "/actuator/health/db",
                    Duration.ofSeconds(60));
            assertEquals(503, actuatorHealthDb.statusCode());
            JsonNode actuatorHealthDbContent = new ObjectMapper().readTree(actuatorHealthDb.body());
            assertEquals(1, actuatorHealthDbContent.size());
            assertEquals("DOWN", actuatorHealthDbContent.get("status").asText());

            // Checking /actuator/health/ping
            HttpResponse<String> actuatorHealthPing = get(port, "/actuator/health/ping");
            assertEquals(200, actuatorHealthPing.statusCode());
            JsonNode actuatorHealthPingContent = new ObjectMapper().readTree(actuatorHealthPing.body());
            assertEquals(1, actuatorHealthPingContent.size());
            assertEquals("UP", actuatorHealthPingContent.get("status").asText());

            // Checking /actuator/health/diskSpace
            HttpResponse<String> actuatorHealthDiskSpace = get(port, "/actuator/health/diskSpace");
            assertEquals(200, actuatorHealthDiskSpace.statusCode());
            JsonNode actuatorHealthDiskSpaceContent = new ObjectMapper().readTree(actuatorHealthDiskSpace.body());
            assertEquals(1, actuatorHealthDiskSpaceContent.size());
            assertEquals("UP", actuatorHealthDiskSpaceContent.get("status").asText());

            // Checking wrong health endpoint still triggers 404 /actuator/health/america
            HttpResponse<String> actuatorHealthWrong = get(port, "/actuator/health/america");
            assertEquals(404, actuatorHealthWrong.statusCode());

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackDisabledWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                MYSQL_PROFILE,
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=false" };
        BeanCreationException error = assertThrows(BeanCreationException.class, () -> IamLoginService.main(args));
        assertTrue(ExceptionUtils.getThrowableList(error).stream()
                .anyMatch(t -> t instanceof ConnectException),
                "should fail because the database is unreachable");
    }

    @Test
    void fallbackStopsWhenDatabaseRecovers() throws Exception {
        int port = freePort();
        int dbPort = freePort();
        String[] args = {
                "--spring.profiles.active=h2-test",
                "--server.port=" + port,
                "--spring.datasource.url=jdbc:h2:tcp://localhost:" + dbPort + "/mem:iam",
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true",
                "--iam.jwk.fallback-database-check-interval=500",
                "--iam.jwk.fallback-exit-on-recovery=false" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        Server database = null;
        try {
            // Fallback starts when database is unavailable
            assertEquals(200, awaitResponse(app, failure, port, "/jwk", Duration.ofSeconds(60)).statusCode());

            // Multiple attempt from the database monitor and the fallback application is
            // still running
            LockSupport.parkNanos(TimeUnit.SECONDS.toNanos(3L));
            assertTrue(app.isAlive());
            assertEquals(200, get(port, "/jwk").statusCode());

            // The database comes online
            database = Server.createTcpServer("-tcpPort", String.valueOf(dbPort), "-ifNotExists").start();

            // The monitor connects and sends the shutdown signal
            app.join(30_000);
            assertFalse(app.isAlive(), "fallback should have stopped after the database recovered");
            assertThrows(IOException.class, () -> get(port, "/jwk"));
        } finally {
            if (database != null) {
                database.stop();
            }
            if (app.isAlive()) {
                app.interrupt();
                app.join(10_000);
            }
        }
    }

    @Test
    void processExitsWithFailureStatusWhenDatabaseRecovers() throws Exception {
        int port = freePort();
        int dbPort = freePort();
        Path log = Files.createTempFile("fallback-exit-test", ".log");

        List<String> command = List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                "it.infn.mw.iam.IamLoginService",
                "--spring.profiles.active=h2-test",
                "--server.port=" + port,
                "--spring.datasource.url=jdbc:h2:tcp://localhost:" + dbPort + "/mem:iam",
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true",
                "--iam.jwk.fallback-database-check-interval=500");

        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();
        Server database = null;
        try {
            // Fallback has started, so the exit code will not be from startup failure
            assertEquals(200, awaitResponse(port, "/jwk", Duration.ofSeconds(30)).statusCode());
            assertTrue(process.isAlive());

            database = Server.createTcpServer("-tcpPort", String.valueOf(dbPort), "-ifNotExists").start();

            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "process should exit once the database recovers");
            String output = Files.readString(log);
            assertTrue(output.contains("Database connection recovered. Stopping JWK fallback"), output);
            assertEquals(1, process.exitValue(), output);
        } finally {
            if (database != null) {
                database.stop();
            }
            process.destroyForcibly();
        }
    }

    @Test
    void fallbackNotStartedOnConfigurationError() throws Exception {
        int port = freePort();
        assertStartupFailsWithoutFallback(new String[] {
                "--spring.profiles.active=h2-test",
                "--server.port=" + port,
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam", // MySQL URL on an H2 datasource
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" }, port);
    }

    @Test
    void fallbackNotStartedOnWrongCredentials() throws Exception {
        int port = freePort();
        int dbPort = freePort();
        String url = "jdbc:h2:tcp://localhost:" + dbPort + "/mem:wrongcreds" + dbPort;
        Server database = Server.createTcpServer("-tcpPort", String.valueOf(dbPort), "-ifNotExists").start();
        // The open connection keeps the in-memory database (user sa / "right") alive
        try (Connection keepAlive = DriverManager.getConnection(url, "sa", "right")) {
            assertStartupFailsWithoutFallback(new String[] {
                    "--spring.profiles.active=h2-test",
                    "--server.port=" + port,
                    "--spring.datasource.url=" + url,
                    "--spring.datasource.username=sa",
                    "--spring.datasource.password=wrong",
                    "--iam.jwk.default-key-id=iam",
                    "--iam.jwk.default-jws-algorithm=ES256",
                    "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                    "--iam.jwk.standalone-fallback-enabled=true" }, port, "28000");
        } finally {
            database.stop();
        }
    }

    private void assertStartupFailsWithoutFallback(String[] args, int port, String expectedSqlState)
            throws Exception {
        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        app.join(60_000);
        if (app.isAlive()) {
            app.interrupt();
            app.join(10_000);
            fail("fallback started, but this error must not start it");
        }
        assertTrue(failure.get() instanceof BeanCreationException);
        List<Throwable> chain = ExceptionUtils.getThrowableList(failure.get());
        assertTrue(chain.stream().anyMatch(
                t -> t instanceof SQLException e && expectedSqlState.equals(e.getSQLState())),
                "expected SQLState " + expectedSqlState + " in " + failure.get());
        assertTrue(chain.stream().noneMatch(t -> t instanceof ConnectException));
        assertThrows(IOException.class, () -> get(port, "/jwk"));
    }

    private void assertStartupFailsWithoutFallback(String[] args, int port) throws Exception {
        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        AtomicReference<Throwable> failure = start(app);
        app.join(60_000);
        if (app.isAlive()) {
            app.interrupt();
            app.join(10_000);
            fail("fallback started, but this error must not start it");
        }
        assertTrue(failure.get() instanceof BeanCreationException);
        assertTrue(ExceptionUtils.getThrowableList(failure.get()).stream()
                .noneMatch(t -> t instanceof ConnectException));
        assertThrows(IOException.class, () -> get(port, "/jwk"));
    }

    private static AtomicReference<Throwable> start(Thread app) {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        app.setUncaughtExceptionHandler((t, e) -> failure.set(e));
        app.start();
        return failure;
    }

    private static HttpResponse<String> awaitResponse(Thread app, AtomicReference<Throwable> failure,
            int port, String path, Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            if (!app.isAlive()) {
                throw new AssertionError("Application stopped during startup", failure.get());
            }
            try {
                return get(port, path);
            } catch (IOException notUpYet) {
                if (System.nanoTime() > deadline) {
                    throw notUpYet;
                }
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(500L));
            }
        }
    }

    private static HttpResponse<String> awaitResponse(int port, String path, Duration timeout)
            throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (true) {
            try {
                return get(port, path);
            } catch (IOException notUpYet) {
                if (System.nanoTime() > deadline) {
                    throw notUpYet;
                }
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(500L));
            }
        }
    }

    private static HttpResponse<String> get(int port, String path) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> getBrowser(int port, String path) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET()
                        .header(HttpHeaders.ACCEPT, "text/html").build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
