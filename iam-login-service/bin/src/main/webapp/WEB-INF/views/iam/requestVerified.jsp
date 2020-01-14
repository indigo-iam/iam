<%--

    Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019

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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<t:page title="Registration request verification">
  <c:choose>
    <c:when test="${verificationSuccess}">
      <h1 class="text-center">Request confirmed successfully</h1>
    </c:when>
    <c:otherwise>
      <h1 class="text-center">Request confirmation failure</h1>
    </c:otherwise>
  </c:choose>
  <div id="register-confirm-message">
    <c:choose>
      <c:when test="${verificationSuccess}">
        <p>Your registration request has been confirmed successfully, and is now waiting for administrator approval.
          As soon as your request is approved you will receive a confirmation email.</p>
      </c:when>
      <c:otherwise>
        <p>Something went wrong with your request.</p>
        <p>Detailed error message:</p>
        <p>${verificationMessage}</p>
      </c:otherwise>
    </c:choose>
    <div id="register-confirm-back-btn" class="row text-center">
      <a class="btn btn-primary" href='/login'>Back to Login Page</a>
    </div>
  </div>
</t:page>