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

import static it.infn.mw.iam.authn.HintAwareAuthenticationEntryPoint.AARC_HINT_PARAM;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import it.infn.mw.iam.authn.DefaultAARCHintService;
import it.infn.mw.iam.authn.HintAwareAuthenticationEntryPoint;

@RunWith(MockitoJUnitRunner.class)
public class AarcHintAwareAuthenticationEntryPointTests {


    private static final String BASE_URL = "";
    private static final String AUTHORIZE_URL = String.format("%s/authorize", BASE_URL);

    private static final String SAML_ENTITYID = "urn:example.us.auth0.com";

    @Mock
    HttpServletRequest authorizeRequest;

    @Mock
    HttpServletResponse response;

    @Mock
    AuthenticationException exception;

    @Mock
    AuthenticationEntryPoint delegateEntryPoint;

    @InjectMocks
    HintAwareAuthenticationEntryPoint entryPoint;

    @Mock
    DefaultAARCHintService aarcHintService;

    @Before
    public void before() {
        when(authorizeRequest.getRequestURI()).thenReturn(AUTHORIZE_URL);
        when(authorizeRequest.getParameter(AARC_HINT_PARAM)).thenReturn(SAML_ENTITYID);
        when(aarcHintService.resolve(anyString())).thenReturn("/saml/login?idp=" + SAML_ENTITYID);
    }

    @Test
    public void authorizeRequestWithHintIsUnderstood() throws IOException, ServletException {

        entryPoint.commence(authorizeRequest, response, exception);
        verify(delegateEntryPoint, times(0)).commence(authorizeRequest, response, exception);
        verify(aarcHintService, times(1)).resolve(SAML_ENTITYID);
        verify(response, times(1)).sendRedirect("/saml/login?idp=" + SAML_ENTITYID);
    }
}
