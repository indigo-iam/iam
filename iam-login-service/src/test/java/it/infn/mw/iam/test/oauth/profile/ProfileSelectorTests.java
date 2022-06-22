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

import static com.google.common.collect.Sets.newLinkedHashSet;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.ScopeAwareProfileResolver;

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

  ScopeAwareProfileResolver profileResolver;

  @Before
  public void setup() {
    Map<String, JWTProfile> profileMap = Maps.newHashMap();

    profileMap.put(ScopeAwareProfileResolver.AARC_PROFILE_ID, aarcProfile);
    profileMap.put(ScopeAwareProfileResolver.IAM_PROFILE_ID, iamProfile);
    profileMap.put(ScopeAwareProfileResolver.WLCG_PROFILE_ID, wlcgProfile);

    profileResolver = new ScopeAwareProfileResolver(iamProfile, profileMap, clientsService);
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullClientThrowException() throws Exception {
    profileResolver.resolveProfile(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyClientIdThrowsException() throws Exception {
    profileResolver.resolveProfile("");
  }

  @Test(expected = IllegalArgumentException.class)
  public void clientNotFoundThrowsException() throws Exception {
    profileResolver.resolveProfile(CLIENT_ID);
  }

  @Test
  public void profileNotFoundLeadsToDefaultProfile() throws Exception {
    when(clientsService.loadClientByClientId(CLIENT_ID)).thenReturn(client);
    when(client.getScope()).thenReturn(Sets.newHashSet("openid"));
    JWTProfile profile = profileResolver.resolveProfile(CLIENT_ID);

    assertThat(profile, is(iamProfile));
  }

  @Test
  public void multipleProfilesLeadToDefaultProfile() throws Exception {
    when(clientsService.loadClientByClientId(CLIENT_ID)).thenReturn(client);
    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "iam", "wlcg"}).iterator()));
    JWTProfile profile = profileResolver.resolveProfile(CLIENT_ID);

    assertThat(profile, is(iamProfile));

    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "iam"}).iterator()));

    profile = profileResolver.resolveProfile(CLIENT_ID);
    assertThat(profile, is(iamProfile));
    
    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "wlcg"}).iterator()));

    profile = profileResolver.resolveProfile(CLIENT_ID);
    assertThat(profile, is(wlcgProfile));
    
    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "wlcg", "iam"}).iterator()));

    profile = profileResolver.resolveProfile(CLIENT_ID);
    assertThat(profile, is(iamProfile));

    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "aarc"}).iterator()));

    profile = profileResolver.resolveProfile(CLIENT_ID);
    assertThat(profile, is(aarcProfile));

    when(client.getScope()).thenReturn(
        newLinkedHashSet(() -> Arrays.stream(new String[] {"openid", "wlcg", "aarc"}).iterator()));

    profile = profileResolver.resolveProfile(CLIENT_ID);
    assertThat(profile, is(iamProfile));
  }
}
