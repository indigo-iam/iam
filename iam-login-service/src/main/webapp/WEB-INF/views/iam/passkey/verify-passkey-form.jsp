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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
<div>
  <form id="passkey-verify-form" class="verify-form" action="/iam/verify" method="post">
    <div class="verify-preamble text-muted">
      <c:choose>
        <c:when test="${isAuthenticatorAppActive}">Or use a passkey registered on your account</c:when>
        <c:otherwise>For your security, please confirm your identity with a passkey registered on your account</c:otherwise>
      </c:choose>
    </div>
    <div id="passkey-verify-error" class="alert alert-danger" role="alert" style="display: none;"></div>
    <input type="hidden" id="passkey-assertion" name="passkey" value="">
    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}">
    <button id="passkey-verify-btn" type="button" class="btn btn-primary btn-block"
      <c:if test="${!isAuthenticatorAppActive}">autofocus</c:if>>
      <i class="fa fa-key"></i> Sign in with passkey
    </button>
  </form>
  <c:if test="${!isAuthenticatorAppActive}">
    <form class="verify-form text-center" action="/logout" method="post">
      <button type="submit" class="btn btn-warning">Back to Login Page</button>
    </form>
  </c:if>
</div>
</html>
