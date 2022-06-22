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

import static it.infn.mw.iam.authn.RootIsDashboardSuccessHandler.DASHBOARD_URL;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;

public class RootIsDashboardSuccessHandlerTests {

  public static final String BASE_URL = "http://localhost";

  public static final String SOME_OTHER_URL = "https://some.other.url";


  static class MockRequestCache implements RequestCache {

    SavedRequest savedRequest;

    public MockRequestCache(SavedRequest req) {
      this.savedRequest = req;
    }

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
      // do nothing
    }

    @Override
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
      return savedRequest;
    }

    @Override
    public HttpServletRequest getMatchingRequest(HttpServletRequest request,
        HttpServletResponse response) {

      return null;
    }

    @Override
    public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
      this.savedRequest = null;
    }

  }

  @Test
  public void testSavedRequestToBaseUrlRedirectsToDashboard() throws ServletException, IOException {

    SavedRequest savedRequest = Mockito.mock(SavedRequest.class);
    MockRequestCache cache = new MockRequestCache(savedRequest);

    HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse res = Mockito.mock(HttpServletResponse.class);

    Authentication auth = Mockito.mock(Authentication.class);

    when(savedRequest.getRedirectUrl()).thenReturn(BASE_URL);
    when(req.getContextPath()).thenReturn("");
    when(res.encodeRedirectURL(Mockito.anyString())).then(returnsFirstArg());

    RootIsDashboardSuccessHandler handler = new RootIsDashboardSuccessHandler(BASE_URL, cache);

    handler.onAuthenticationSuccess(req, res, auth);

    verify(res).sendRedirect(DASHBOARD_URL);

  }

  @Test
  public void testSavedRequestToBaseUrlPlusSlashRedirectsToDashboard()
      throws ServletException, IOException {

    SavedRequest savedRequest = Mockito.mock(SavedRequest.class);
    MockRequestCache cache = new MockRequestCache(savedRequest);

    HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse res = Mockito.mock(HttpServletResponse.class);

    Authentication auth = Mockito.mock(Authentication.class);

    when(savedRequest.getRedirectUrl()).thenReturn(BASE_URL + "/");
    when(req.getContextPath()).thenReturn("");
    when(res.encodeRedirectURL(Mockito.anyString())).then(returnsFirstArg());

    RootIsDashboardSuccessHandler handler = new RootIsDashboardSuccessHandler(BASE_URL, cache);

    handler.onAuthenticationSuccess(req, res, auth);

    verify(res).sendRedirect(DASHBOARD_URL);

  }

  @Test
  public void testOtherRequestIsIgnored() throws ServletException, IOException {

    SavedRequest savedRequest = Mockito.mock(SavedRequest.class);
    MockRequestCache cache = new MockRequestCache(savedRequest);

    HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse res = Mockito.mock(HttpServletResponse.class);

    Authentication auth = Mockito.mock(Authentication.class);

    when(savedRequest.getRedirectUrl()).thenReturn(SOME_OTHER_URL);
    when(req.getContextPath()).thenReturn("");
    when(res.encodeRedirectURL(Mockito.anyString())).then(returnsFirstArg());

    RootIsDashboardSuccessHandler handler = new RootIsDashboardSuccessHandler(BASE_URL, cache);

    handler.onAuthenticationSuccess(req, res, auth);

    verify(res).sendRedirect(SOME_OTHER_URL);

  }


  @Test
  public void whenNoRequestIsSavedGoToDashboard() throws ServletException, IOException {
    RequestCache cache = Mockito.mock(RequestCache.class);
    HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
    HttpServletResponse res = Mockito.mock(HttpServletResponse.class);

    when(req.getContextPath()).thenReturn("");
    when(res.encodeRedirectURL(Mockito.anyString())).then(returnsFirstArg());

    Authentication auth = Mockito.mock(Authentication.class);

    RootIsDashboardSuccessHandler handler = new RootIsDashboardSuccessHandler(BASE_URL, cache);
    handler.onAuthenticationSuccess(req, res, auth);
    verify(res).sendRedirect(DASHBOARD_URL);
  }

}
