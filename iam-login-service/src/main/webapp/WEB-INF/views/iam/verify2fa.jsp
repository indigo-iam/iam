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
<form id="verify-2fa-form" action="/iam/verify2fa" method="post">
  <div class="signin-preamble text-muted">Enter code from your authenticator app</div>
  <div class="form-group">
    <div class="input-group">
      <span class="input-group-addon">
        <i class="glyphicon glyphicon-user"></i>
      </span>
      <input id="code" class="form-control" type="text" placeholder="Code" autocomplete="off" spellcheck="false"
        value="${ login_hint }" name="code">
    </div>
  </div>
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
    <input id="verify-2fa-submit" type="submit" class="btn btn-primary btn-block"
      value="${loginPageConfiguration.loginButtonText}" name="submit" class="form-control">
  </div>
</form>
<!-- <c:if test="${loginPageConfiguration.registrationEnabled}">
  <div id="forgot-password" ng-controller="ForgotPasswordModalController">
    <a class="btn btn-link btn-block" ng-click="open()">Forgot your password?</a>
  </div>
</c:if> -->