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
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.h2.tools.Server;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.http.HttpHeaders;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.jwk.JWKTestSupport;

public class FallbackApplicationStartupTests implements JWKTestSupport {

    @Test
    void fallbackServesJwkAndActuatorWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        app.start();
        try {

            // Checking the jwk endpoint
            HttpResponse<String> jwk = awaitResponse(port, "/jwk", Duration.ofSeconds(60));
            assertEquals(200, jwk.statusCode());
            JsonNode keys = new ObjectMapper().readTree(jwk.body()).get("keys");
            assertEquals(1, keys.size());
            assertEquals("iam", keys.get(0).get("kid").asText());

            // Checking the redirect page is present
            HttpResponse<String> fallbackInfo = get(port, "/fallback-info");
            assertEquals(503, fallbackInfo.statusCode());

            // Checking that one is redirected from a browser
            HttpResponse<String> login = getBrowser(port, "/login");
            assertEquals(302, login.statusCode());
            assertEquals(String.format("http://localhost:%2d/fallback-info", port),
                    login.headers().allValues("location").get(0));

        } finally {
            app.interrupt(); // makes awaitStopped() return and closes the fallback context
            app.join(10_000);
        }
    }

    @Test
    void fallbackServesActuatorWhenDatabaseIsDown() throws Exception {
        int port = freePort();
        String[] args = {
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        app.start();
        try {

            // Checking /actuator endpoint
            HttpResponse<String> actuator = awaitResponse(port, "/actuator", Duration.ofSeconds(60));
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
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        app.start();
        try {

            // Checking /actuator/health/db
            HttpResponse<String> actuatorHealthDb = awaitResponse(port, "/actuator/health/db", Duration.ofSeconds(60));
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
                "--server.port=" + port,
                // force an unreachable database whatever the environment has running
                "--spring.datasource.url=jdbc:mysql://127.0.0.1:1/iam",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=false" };
        assertThrows(BeanCreationException.class, () -> IamLoginService.main(args));
    }

    @Test
    void fallbackStopsWhenDatabaseRecovers() throws Exception {
        int port = freePort();
        int dbPort = freePort();
        String[] args = {
                "--server.port=" + port,
                "--spring.datasource.url=jdbc:h2:tcp://localhost:" + dbPort + "/mem:iam",
                "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.datasource.username=sa",
                "--spring.datasource.password=",
                "--iam.jwk.default-key-id=iam",
                "--iam.jwk.default-jws-algorithm=ES256",
                "--iam.jwk.keystore-location=classpath:/jwk/ec.jwks",
                "--iam.jwk.standalone-fallback-enabled=true",
                "--iam.jwk.fallback-database-check-interval=500" };

        Thread app = new Thread(() -> IamLoginService.main(args), "iam-under-test");
        app.start();
        Server database = null;
        try {
            // Fallback starts when database is unavailable
            assertEquals(200, awaitResponse(port, "/jwk", Duration.ofSeconds(60)).statusCode());

            // Multiple attempt from the database monitor and the fallback application is
            // still running
            Thread.sleep(3_000);
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
                Thread.sleep(500);
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

    private static HttpResponse<String> post(int port, String path) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).POST(null).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
