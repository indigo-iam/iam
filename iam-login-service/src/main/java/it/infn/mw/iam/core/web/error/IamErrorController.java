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
package it.infn.mw.iam.core.web.error;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class IamErrorController implements ErrorController {

  private static final String IAM_ERROR_VIEW = "iam/error";
  private static final String PATH = "/error";

  @RequestMapping(method = RequestMethod.GET, path = PATH)
  public ModelAndView error(HttpServletRequest request) {

    ModelAndView errorPage = new ModelAndView(IAM_ERROR_VIEW);

    HttpStatus status = HttpStatus.valueOf(getErrorCode(request));

    errorPage.addObject("errorMessage",
        String.format("%d. %s", status.value(), status.getReasonPhrase()));

    Exception exception = getRequestException(request);

    if (exception != null) {
      errorPage.addObject("exceptionMessage", exception.getMessage());
      errorPage.addObject("exceptionStackTrace", ExceptionUtils.getStackTrace(exception).trim());
    }
    return errorPage;
  }

  private int getErrorCode(HttpServletRequest httpRequest) {
    return (Integer) httpRequest.getAttribute("javax.servlet.error.status_code");
  }

  private Exception getRequestException(HttpServletRequest httpRequest) {
    return (Exception) httpRequest.getAttribute("javax.servlet.error.exception");
  }

}
