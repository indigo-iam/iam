<%--

    Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

--%>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<c:if test="${loginPageConfiguration.defaultLoginPageLayout}">
  <c:set value="container-spacer" var="containerSpacer"></c:set>
</c:if>

<form id="login-form" class="${containerSpacer}" action="/login" method="post">
  <div class="signin-preamble text-muted">
    <c:choose>
      <c:when test="${loginPageConfiguration.defaultLoginPageLayout}">
        Sign in with your ${iamOrganisationName} credentials
      </c:when>
      <c:otherwise>
        Or sign in with your ${iamOrganisationName} credentials
      </c:otherwise>
    </c:choose>
  </div>

  <div class="form-group">
    <div class="input-group">
      <span class="input-group-addon">
        <i class="glyphicon glyphicon-user"></i>
      </span>
      <input id="username" class="form-control" type="text" placeholder="Username" autocomplete="off" spellcheck="false"
        value="${ login_hint }" name="username">
    </div>
  </div>
  <div class="form-group">
    <div class="input-group">
      <span class="input-group-addon">
        <i class="glyphicon glyphicon-lock"></i>
      </span>
      <input id="password" name="password" class="form-control" type="password" placeholder="Password">
    </div>
  </div>
  <div>
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
    <input id="login-submit" type="submit" class="btn btn-primary btn-block"
      value="${loginPageConfiguration.loginButtonText}" name="submit" class="form-control">
  </div>
  <c:if test="${loginPageConfiguration.registrationEnabled}">
    <div id="forgot-password" ng-controller="ForgotPasswordModalController">
      <a class="btn btn-link btn-block" ng-click="open()">Forgot your password?</a>
    </div>
  </c:if>
</form>