package it.infn.mw.iam.test.util.oauth;

import java.util.Collections;
import java.util.Objects;

import org.springframework.security.oauth2.provider.OAuth2Request;

import com.google.common.collect.Sets;

class MockOAuth2Request extends OAuth2Request {

  private static final long serialVersionUID = -8547059375050883345L;

  public MockOAuth2Request(String clientId, String[] scopes) {
    setClientId(clientId);

    if (!Objects.isNull(scopes)) {
      setScope(Sets.newHashSet(scopes));
    } else {
      setScope(Collections.emptySet());
    }
  }

  @Override
  public boolean isApproved() {
    return true;
  }
}
