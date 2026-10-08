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
package it.infn.mw.iam.test.service.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.transaction.annotation.Transactional;
import org.webjars.NotFoundException;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.service.DefaultClientService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

@SpringBootTest(properties = { "cache.enabled=true", "cache.redis.enabled=false",
                "cache.default-cleanup-period-secs=1" })
@AutoConfigureMockMvc
@Transactional
public class ClientServicesCacheTests {

        private final String NEW_CLIENT_ID = "some-client";
        private final String NEW_CLIENT_DESCRIPTION = "some-client-description";
        private final String USER_ID = "some-user-id";

        @Autowired
        private ClientService clientService;

        @Autowired
        private ClientDetailsService clientDetailsService;

        @Autowired
        private CacheManager cacheManager;

        @BeforeEach
        void clearCache() {
                cacheManager.getCache(DefaultClientService.CACHE_NAME).clear();
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));
        }

        private void waitForCacheExpiration() {
                long timeoutNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);

                while (System.nanoTime() < timeoutNanos) {
                        if (cacheManager.getCache(DefaultClientService.CACHE_NAME)
                                        .get(NEW_CLIENT_ID) == null) {
                                return;
                        }
                        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
                }
                assertNull(
                                cacheManager.getCache(DefaultClientService.CACHE_NAME)
                                                .get(NEW_CLIENT_ID));
        }

        @Test
        void testClientServiceCachePopulationAndEviction() {

                // Checking that the client isn't in the cache
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Creating the new client in the repository through the service
                ClientDetailsEntity client = new ClientDetailsEntity();
                client.setClientId(NEW_CLIENT_ID);
                clientService.saveNewClient(client);

                // This shouldn't have put it into the cache
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Doing a client lookup
                client = clientService.findClientByClientId(NEW_CLIENT_ID)
                                .orElseThrow(() -> new NotFoundException("Client should be present"));

                // This should have populated the cache
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Updating the client
                client.setClientDescription(NEW_CLIENT_DESCRIPTION);
                clientService.updateClient(client);

                // This should have evicted the client
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Populating again
                client = (ClientDetailsEntity) clientDetailsService.loadClientByClientId(NEW_CLIENT_ID);
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));
                assertEquals(NEW_CLIENT_DESCRIPTION, client.getClientDescription());

                // Updating the client status
                clientService.updateClientStatus(client, true, USER_ID);

                // This should have evicted the client
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Populating again
                client = clientService.findClientByClientId(NEW_CLIENT_ID)
                                .orElseThrow(() -> new NotFoundException("Client should be present"));
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));
                assertEquals(NEW_CLIENT_DESCRIPTION, client.getClientDescription());
                assertEquals(USER_ID, client.getStatusChangedBy());
                assertEquals(true, client.isActive());

                // Time eviction
                waitForCacheExpiration();

                // Confirming eviction
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));

                // Populating again
                client = clientService.findClientByClientId(NEW_CLIENT_ID)
                                .orElseThrow(() -> new NotFoundException("Client should be present"));
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));
                assertEquals(NEW_CLIENT_DESCRIPTION, client.getClientDescription());
                assertEquals(USER_ID, client.getStatusChangedBy());
                assertEquals(true, client.isActive());

                // Deleting the client
                clientService.deleteClient(client);

                // Confirming eviction
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(NEW_CLIENT_ID));
        }
}
