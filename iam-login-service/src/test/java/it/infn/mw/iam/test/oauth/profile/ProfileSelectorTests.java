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

import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.google.common.collect.Maps;

import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcJWTProfile;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfile;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakJWTProfile;
import it.infn.mw.iam.core.oauth.profile.wlcg.WLCGJWTProfile;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class ProfileSelectorTests {

  public static final String CLIENT_ID = "client";

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

  @Before
  public void setup() {
    Map<String, JWTProfile> profileMap = Maps.newHashMap();

    profileMap.put(AarcJWTProfile.PROFILE_ID, aarcProfile);
    profileMap.put(IamJWTProfile.PROFILE_ID, iamProfile);
    profileMap.put(WLCGJWTProfile.PROFILE_ID, wlcgProfile);
    profileMap.put(KeycloakJWTProfile.PROFILE_ID, kcProfile);

    profileResolver = new ScopeAwareProfileResolver(iamProfile, profileMap);
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullClientThrowException() throws Exception {
    profileResolver.resolveProfile(null);
  }

  @Test
  public void profileNotFoundLeadsToDefaultProfile() throws Exception {

    JWTProfile profile = profileResolver.resolveProfile(Set.of("openid"));
    assertThat(profile, is(iamProfile));
  }

  @Test
  public void multipleProfilesLeadToDefaultProfile() throws Exception {

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

  }
}
