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

import org.springframework.scheduling.annotation.EnableScheduling;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;

import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.util.JwkKeyStoreLoader;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.actuator.health.ExternalConnectivityHealthIndicator;

@EnableScheduling
@SpringBootApplication(scanBasePackages = "it.infn.mw.iam.jwkfallback", exclude = {
        // Excluded as it must not try to establish the db connection upon boot
        DataSourceAutoConfiguration.class,
        // Omitting as no endpoints in fallback needs authentication
        UserDetailsServiceAutoConfiguration.class,
})
@EnableConfigurationProperties(IamProperties.class)
@Import({ IamJWKSetPublishingEndpoint.class, ExternalConnectivityHealthIndicator.class,
        FallbackHealthEndpointWebExtension.class })
public class IamJwkFallbackApplication {

    @Bean
    IamJWTSigningService iamJWTSigningService(
            JwkKeyStore keystore,
            JWKProperties properties) {
        return new IamJWTSigningService(keystore, properties);
    }

    @Bean
    JwkKeyStoreLoader jwkKeyStoreLoader(ResourceLoader resourceLoader) {
        return new JwkKeyStoreLoader(resourceLoader);
    }

    @Bean
    JwkKeyStore jwkKeyStore(
            JwkKeyStoreLoader loader,
            @Value("${iam.jwk.keystore-location}") String keystoreLocation) {
        return loader.load(keystoreLocation);
    }

    @Bean
    JWKProperties jwkProperties(IamProperties iamProperties) {
        return iamProperties.getJwk();
    }

    @Bean
    Duration slowIndicatorLoggingThreshold() {
        return Duration.ofSeconds(10);
    }

    @Bean
    FallbackProcessExit fallbackProcessExit(
            @Value("${iam.jwk.fallback-exit-on-recovery:true}") boolean exitOnRecovery) {
        return exitOnRecovery ? System::exit : status -> {
        };
    }
}
