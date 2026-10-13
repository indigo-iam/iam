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
<t:page title="Verify">
  <jsp:attribute name="footer">
        <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
        <script type="text/javascript" src="/webjars/angularjs/angular-animate.js"></script>
        <script type="text/javascript" src="/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js"></script>
        <c:if test="${isPasskeyActive}">
          <script type="text/javascript" src="${resourcesPrefix}/iam/js/passkey/webauthn.js"></script>
          <script type="text/javascript" src="${resourcesPrefix}/iam/js/passkey/passkey-verify.js"></script>
        </c:if>
    </jsp:attribute>
  <jsp:body>
    <div id="verify-error">
      <c:if test="${ param.error != null }">
        <div class="alert alert-danger">
          <strong>
            <spring:message code="login.error" />
          </strong>
          <div>${SPRING_SECURITY_LAST_EXCEPTION.message}</div>
        </div>
      </c:if>
    </div>

    <!-- Displays the factors of authentication available on the account one after the other -->
    <c:if test="${isAuthenticatorAppActive}">
      <div id="auth-app">
        <jsp:include page="authenticator-app/verify-authenticator-app-form.jsp" />
      </div>
    </c:if>
    <c:if test="${isPasskeyActive}">
      <div id="passkey">
        <jsp:include page="passkey/verify-passkey-form.jsp" />
      </div>
    </c:if>
  </jsp:body>
</t:page>