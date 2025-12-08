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
package it.infn.mw.iam.test.oauth.profile;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.google.common.collect.Maps;

import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes;
import it.infn.mw.iam.core.oauth.profile.iam.IamOidcScopes;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakOidcScopes;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgOidcScopes;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class ScopeAwareProfileResolverTests {

  static final String CLIENT_ID = "client";

  @Mock
  ClientDetailsService clientsService;

  @Mock
  ClientDetails client;

  @Mock
  JWTProfile aarcProfile;

  @Mock
  JWTProfile iamProfile;

  @Mock
  JWTProfile wlcgProfile;

  @Mock
  JWTProfile kcProfile;

  ScopeAwareProfileResolver profileResolver;

  @BeforeEach
  void setup() {
    Map<String, JWTProfile> profileMap = Maps.newHashMap();

    profileMap.put(AarcOidcScopes.AARC, aarcProfile);
    profileMap.put(IamOidcScopes.IAM, iamProfile);
    profileMap.put(WlcgOidcScopes.WLCG, wlcgProfile);
    profileMap.put(KeycloakOidcScopes.KEYCLOAK, kcProfile);

    profileResolver = new ScopeAwareProfileResolver(iamProfile, profileMap);
  }

  @Test
  void nullClientThrowException() {
    assertThrows(IllegalArgumentException.class, () -> profileResolver.resolveProfile(null));
  }

  @Test
  void profileNotFoundLeadsToDefaultProfile() {

    JWTProfile profile = profileResolver.resolveProfile(Set.of("openid"));
    assertThat(profile, is(iamProfile));
  }

  @Test
  void multipleClientProfilesLeadToDefaultProfileWithNoRequested() {

    JWTProfile profile = profileResolver.resolveProfile(Set.of("openid", "iam", "wlcg"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "iam"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "wlcg"));
    assertThat(profile, is(wlcgProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "wlcg", "iam"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "aarc"));
    assertThat(profile, is(aarcProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "wlcg", "aarc"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "kc"));
    assertThat(profile, is(kcProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "kc", "iam"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "kc", "wlcg"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of());
    assertThat(profile, is(iamProfile));
  }

  @Test
  void multipleClientProfilesLeadToRequestedProfileIfAllowed() {

    Set<String> clientScopes = Set.of("openid", "aarc", "wlcg");

    JWTProfile profile = profileResolver.resolveProfile(clientScopes, Set.of("openid", "wlcg"));
    assertThat(profile, is(wlcgProfile));

    profile = profileResolver.resolveProfile(clientScopes, Set.of("openid", "aarc"));
    assertThat(profile, is(aarcProfile));

    profile = profileResolver.resolveProfile(clientScopes, Set.of("openid"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(clientScopes, Set.of("openid", "wlcg", "aarc"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(clientScopes, Set.of("openid", "wlcg", "kc"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(clientScopes, Set.of("openid"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of(), Set.of());
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of(), Set.of("wlcg"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of(), Set.of("aarc"));
    assertThat(profile, is(iamProfile));

    profile = profileResolver.resolveProfile(Set.of(), Set.of("kc"));
    assertThat(profile, is(iamProfile));
  }

  @Test
  void requestedProfileIsNotAllowed() {

    Set<String> clientScopes = Set.of("openid", "aarc", "wlcg");
    Set<String> requestedScopes = Set.of("openid", "kc");

    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        () -> profileResolver.resolveProfile(clientScopes, requestedScopes));
    assertThat(ScopeAwareProfileResolver.MISMATCH_ERROR, is(e.getMessage()));
  }

  @Test
  void oneProfileLeadToCorrectJwtProfile() {

    JWTProfile profile = profileResolver.resolveProfile(Set.of("openid", "wlcg"), Set.of());
    assertThat(profile, is(wlcgProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "aarc"), Set.of());
    assertThat(profile, is(aarcProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "kc"), Set.of());
    assertThat(profile, is(kcProfile));

    profile = profileResolver.resolveProfile(Set.of("openid", "iam"), Set.of());
    assertThat(profile, is(iamProfile));
  }

}
