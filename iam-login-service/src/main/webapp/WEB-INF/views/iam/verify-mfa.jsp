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
    </jsp:attribute>
  <jsp:body>
    <div id="verify-error">
      <c:if test="${ param.error != null }">
        <div class="alert alert-danger">
          <strong>
            <spring:message code="login.error" />
          </strong>
          <!-- TODO - change code to below div when fixing issue with reading exception message -->
          <div>Bad code</div>
          <!-- <div>${SPRING_SECURITY_LAST_EXCEPTION.message}</div> -->
        </div>
      </c:if>
    </div>
    <div>
      <!-- Can be extended later on so that, instead of displaying each factor one after the other, display buttons which, when pressed, open up that factor -->
      <!-- Also, for the sake of convenience, detect that if only one additional factor is configured, automatically display that instead -->
      <c:forEach begin="0" end="${factors.size() -1}" var="index">
        <c:if test="${factors.authenticatorAppActive}">
          <jsp:include page="verify-authenticator-app-form.jsp" />
        </c:if>
      </c:forEach>
    </div>
    <div id="verify-confirm-back-btn" class="row text-center">
      <form action="/logout" method="post">
        <button type="submit" class="btn btn-warning">Back to Login Page</button>
      </form>
    </div>
  </jsp:body>
</t:page>