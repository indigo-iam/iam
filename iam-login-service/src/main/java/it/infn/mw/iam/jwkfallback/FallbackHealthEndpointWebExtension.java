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

import java.time.Duration;
import java.util.Map;

import org.springframework.boot.actuate.endpoint.ApiVersion;
import org.springframework.boot.actuate.endpoint.SecurityContext;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.actuate.endpoint.annotation.Selector;
import org.springframework.boot.actuate.endpoint.annotation.Selector.Match;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.boot.actuate.endpoint.web.WebServerNamespace;
import org.springframework.boot.actuate.health.CompositeHealth;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpointGroups;
import org.springframework.boot.actuate.health.HealthEndpointWebExtension;
import org.springframework.boot.actuate.health.HealthContributorRegistry;

public class FallbackHealthEndpointWebExtension
        extends HealthEndpointWebExtension {

    private static final String[] NO_PATH = {};

    public FallbackHealthEndpointWebExtension(HealthContributorRegistry registry, HealthEndpointGroups groups,
            Duration slowIndicatorLoggingThreshold) {
        super(registry, groups, slowIndicatorLoggingThreshold);
    }

    @Override
    @ReadOperation
    public WebEndpointResponse<HealthComponent> health(ApiVersion apiVersion, WebServerNamespace serverNamespace,
            SecurityContext securityContext) {

        WebEndpointResponse<HealthComponent> value = health(apiVersion, serverNamespace, securityContext, false,
                NO_PATH);

        HealthComponent health = value.getBody();

        if (health instanceof CompositeHealth composite) {

            Map<String, HealthComponent> components = composite.getComponents();

            if (components != null) {
                components.remove("db");
                components.put("db", Health.down().build());
            }
        }

        return value;
    }

    @Override
    @ReadOperation
    public WebEndpointResponse<HealthComponent> health(ApiVersion apiVersion, WebServerNamespace serverNamespace,
            SecurityContext securityContext, @Selector(match = Match.ALL_REMAINING) String... path) {

        if (path.length == 1 && "db".equals(path[0])) {
            return new WebEndpointResponse<>(
                    Health.down().build(),
                    WebEndpointResponse.STATUS_SERVICE_UNAVAILABLE);
        }

        return health(apiVersion, serverNamespace, securityContext, false, path);
    }
}
