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
package it.infn.mw.iam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.context.annotation.Import;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;

import org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

import java.util.concurrent.TimeUnit;

import org.springframework.context.annotation.Bean;

import org.springframework.core.io.ResourceLoader;

import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.util.JwkKeyStoreLoader;

import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;
import it.infn.mw.iam.core.jwk.JwkKeyStore;
import it.infn.mw.iam.config.IamProperties;

@SpringBootApplication(scanBasePackages = "it.infn.mw.iam.jwkfallback", exclude = {
        DataSourceAutoConfiguration.class,

        // These two might need to be excluded later
        // HibernateJpaAutoConfiguration.class,
        // FlywayAutoConfiguration.class,

        // This is also exluded by the IamLoginService
        SecurityAutoConfiguration.class,
        // UserDetailsServiceAutoConfiguration.class,
        ManagementWebSecurityAutoConfiguration.class
})
@EnableConfigurationProperties(IamProperties.class)
@Import(IamJWKSetPublishingEndpoint.class)
public class IamJwkFallbackApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamJwkFallbackApplication.class, args);
    }

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

}
