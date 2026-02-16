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
package it.infn.mw.iam.test.util;

import java.util.Arrays;
import java.util.stream.Stream;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

public class JvmProfilesSupport {
//
//  public static class OidcProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] existingProfiles = context.getEnvironment().getActiveProfiles();
//        String[] newProfiles = Arrays.copyOf(existingProfiles, existingProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "oidc";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
//
//  public static class MfaProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] existingProfiles = context.getEnvironment().getActiveProfiles();
//        String[] newProfiles = Arrays.copyOf(existingProfiles, existingProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "mfa";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
//
//  public static class WlcgScopesProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] existingProfiles = context.getEnvironment().getActiveProfiles();
//        String[] newProfiles = Arrays.copyOf(existingProfiles, existingProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "wlcg-scopes";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
//
//  public static class SamlProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] existingProfiles = context.getEnvironment().getActiveProfiles();
//        String[] newProfiles = Arrays.copyOf(existingProfiles, existingProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "saml";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
//
//  public static class RegistrationProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] existingProfiles = context.getEnvironment().getActiveProfiles();
//        String[] newProfiles = Arrays.copyOf(existingProfiles, existingProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "registration";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
//
//  public static class OpenIDFederationProfileInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
//    @Override
//    public void initialize(ConfigurableApplicationContext context) {
//        String[] currentProfiles = Stream
//            .concat(Arrays.stream(context.getEnvironment().getDefaultProfiles()), Arrays.stream(context.getEnvironment().getActiveProfiles()))
//            .toArray(String[]::new);
////        String[] existingProfiles = context.getEnvironment().getDefaultProfiles();
//        String[] newProfiles = Arrays.copyOf(currentProfiles, currentProfiles.length + 1);
//        newProfiles[newProfiles.length - 1] = "openid-federation";
//        context.getEnvironment().setActiveProfiles(newProfiles);
//    }
//  }
}
