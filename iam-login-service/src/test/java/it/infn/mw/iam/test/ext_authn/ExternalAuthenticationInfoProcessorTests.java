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
package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.Test;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoProcessor;

@SuppressWarnings("deprecation")
public class ExternalAuthenticationInfoProcessorTests {

  @Test
  public void processorReturnsEmptyMapForClientAuthentication() {

    OAuth2Authentication oAuth = mock(OAuth2Authentication.class);

    DefaultExternalAuthenticationInfoProcessor processor =
        new DefaultExternalAuthenticationInfoProcessor();

    assertThat(processor.process(oAuth).entrySet(), empty());
  }

  @Test
  public void processorReturnsUserInfoIfPresent() {

    Map<String, String> info = Maps.newHashMap();
    info.put("key", "val");

    OAuth2Authentication oAuth = mock(OAuth2Authentication.class);
    SavedUserAuthentication userAuth = mock(SavedUserAuthentication.class);

    when(oAuth.getUserAuthentication()).thenReturn(userAuth);
    when(userAuth.getAdditionalInfo()).thenReturn(info);

    DefaultExternalAuthenticationInfoProcessor processor =
        new DefaultExternalAuthenticationInfoProcessor();

    assertThat(processor.process(oAuth), hasEntry("key", "val"));
  }

  @Test
  public void processorReturnsEmtpyCollectionForEmptyUserInfo() {

    Map<String, String> info = Maps.newHashMap();

    OAuth2Authentication oAuth = mock(OAuth2Authentication.class);
    SavedUserAuthentication userAuth = mock(SavedUserAuthentication.class);

    when(oAuth.getUserAuthentication()).thenReturn(userAuth);
    when(userAuth.getAdditionalInfo()).thenReturn(info);

    DefaultExternalAuthenticationInfoProcessor processor =
        new DefaultExternalAuthenticationInfoProcessor();

    assertThat(processor.process(oAuth).entrySet(), empty());
  }
}
