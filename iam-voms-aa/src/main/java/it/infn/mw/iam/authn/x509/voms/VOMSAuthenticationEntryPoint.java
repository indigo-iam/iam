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
package it.infn.mw.iam.authn.x509.voms;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import it.infn.mw.voms.aa.VOMSErrorMessage;
import it.infn.mw.voms.aa.ac.VOMSResponseBuilder;


public class VOMSAuthenticationEntryPoint implements AuthenticationEntryPoint {


  final VOMSResponseBuilder responseBuilder;

  public VOMSAuthenticationEntryPoint(VOMSResponseBuilder responseBuilder) {
    this.responseBuilder = responseBuilder;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    
    final VOMSErrorMessage error = VOMSErrorMessage.unauthenticatedClient();
    String vomsResponse = responseBuilder.createErrorResponse(error);
    response.setStatus(error.getError().getHttpStatus());
    response.getOutputStream().write(vomsResponse.getBytes());
  }

}
