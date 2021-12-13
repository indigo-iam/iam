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
<t:page title="Reset recovery codes?">
  <jsp:attribute name="footer">
    <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
    <script type="text/javascript" src="/webjars/angularjs/angular-animate.js"></script>
    <script type="text/javascript" src="/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js"></script>
  </jsp:attribute>
  <jsp:body>
    <form class="verify-form" action="/iam/authenticator-app/recovery-code/reset" method="post">
      <div class="verify-preamble text-muted">
        To strengthen account security, it is strongly recommended you reset your account recovery codes after one is used. To do this, press Reset. Otherwise, press Skip.
      </div>
      <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
      <input id="reset-submit" type="submit" class="btn btn-primary btn-block"
        value="Reset" name="reset" class="form-control">
    </form>
    <!-- The below action obviously would not work if needing to redirect elsewhere -->
    <form class="verify-form" action="/dashboard" method="get">
      <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
      <input id="skip-submit" type="submit" class="btn btn-danger btn-block"
        value="Skip" name="skip" class="form-control">
    </form>
  </jsp:body>
</t:page>