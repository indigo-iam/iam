package it.infn.mw.iam.test.ext_authn;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.google.common.collect.Maps;

import it.infn.mw.iam.authn.DefaultExternalAuthenticationInfoProcessor;

public class ExternalAuthenticationInfoProcessorTests {

  @Test
  public void processorReturnsEmptyMapForClientAuthentication() {

    OAuth2Authentication oAuth = mock(OAuth2Authentication.class);

    DefaultExternalAuthenticationInfoProcessor processor =
        new DefaultExternalAuthenticationInfoProcessor();

    Assert.assertThat(processor.process(oAuth).entrySet(), empty());
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

    Assert.assertThat(processor.process(oAuth), hasEntry("key", "val"));
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

    Assert.assertThat(processor.process(oAuth).entrySet(), empty());
  }
}
