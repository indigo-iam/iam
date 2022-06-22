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
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<t:page title="Sign Acceptable Usage Policy">
  <h2 class="text-center">Sign Acceptable Usage Policy</h2>
  <form id="sign-aup-form" class="sign-aup-form form" action="/iam/aup/sign" method="post">
    <c:if test="${aup.text != null}">
      <p id="sign-aup-subtitle">In order to proceed, you need to sign the Acceptable Usage Policy (AUP) for this
        organization:</p>
      <div class="form-group">
        <div class="aup-text">${aup.text}</div>
      </div>
    </c:if>
    <c:if test="${aup.url != null}">
      <p id="sign-aup-subtitle">
        In order to proceed, you need to declare that you have read and that you accept the terms of this organization
        <a href="${aup.url}" target="_blank" rel="noopener noreferrer">Acceptable Usage Policy (AUP).</a>
      </p>
    </c:if>
    <div class="form-group sign-aup-btns">
      <input id="sign-aup-btn" class="btn btn-success" type="submit" value="I agree with the AUP terms">
    </div>
  </form>
</t:page>
