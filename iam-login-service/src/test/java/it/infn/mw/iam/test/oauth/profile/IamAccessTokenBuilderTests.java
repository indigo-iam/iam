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

import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.google.common.collect.Maps;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.iam.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileAccessTokenBuilder;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@RunWith(MockitoJUnitRunner.class)
public class IamAccessTokenBuilderTests {

  IamProperties properties = new IamProperties();

  @Mock
  ScopeClaimTranslationService scService;

  @Mock
  ClaimValueHelper claimValueHelper;

  @Mock
  OAuth2AccessTokenEntity tokenEntity;

  @Mock
  ClientDetailsEntity client;
  
  @Mock
  OAuth2Authentication authentication;

  @Spy
  MockOAuth2Request oauth2Request =
      new MockOAuth2Request("clientId", new String[] {"openid", "profile"});

  @Mock
  UserInfo userInfo;

  final Instant now = Clock.systemDefaultZone().instant();

  IamJWTProfileAccessTokenBuilder tokenBuilder;

  @Before
  public void setup() {

    tokenBuilder =
        new IamJWTProfileAccessTokenBuilder(properties, scService, claimValueHelper);
    when(tokenEntity.getExpiration()).thenReturn(null);
    when(tokenEntity.getClient()).thenReturn(client);
    when(client.getClientId()).thenReturn("client");
    // when(authentication.getName()).thenReturn("auth-name");
    when(authentication.getOAuth2Request()).thenReturn(oauth2Request);
    // when(authentication.isClientOnly()).thenReturn(false);
    when(userInfo.getSub()).thenReturn("userinfo-sub");
    when(oauth2Request.getGrantType()).thenReturn(TOKEN_EXCHANGE_GRANT_TYPE);
  }


  @Test(expected = InvalidRequestException.class)
  public void testMissingSubjectTokenTokenExchangeErrors() {
    try {
      tokenBuilder.buildAccessToken(tokenEntity, authentication, userInfo, now);
    } catch (InvalidRequestException e) {
      assertThat(e.getMessage(), containsString("subject_token not found"));
      throw e;
    }
  }

  @Test(expected = InvalidRequestException.class)
  public void testSubjectTokenNotParsable() {
    Map<String, String> paramsMap = Maps.newHashMap();
    paramsMap.put("subject_token", "3427thjdfhgejt73ja");

    oauth2Request.setRequestParameters(paramsMap);
    try {
      tokenBuilder.buildAccessToken(tokenEntity, authentication, userInfo, now);
    } catch (InvalidRequestException e) {
      assertThat(e.getMessage(), containsString("Error parsing subject token"));
      throw e;
    }
  }

}
