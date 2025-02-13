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
<t:page title="Verify registration request">
  <h1 class="text-center">Verify registration request</h1>
  <div id="verify-registration-form">
    <p>In order to proceed with the registration request, please confirm</p>
    <div id="verify-registration-btn" class="row text-center">
      <form name="confirmationForm"
          action="${pageContext.request.contextPath.endsWith('/') ? pageContext.request.contextPath : pageContext.request.contextPath.concat('/') }registration/verify"
          method="post">
        <input type="hidden" name="token" value="${token}" />
        <input class="btn btn-primary" type="submit" name="confirm_registration_request" value="Confirm Request" />
      </form>
    </div>
  </div>
</t:page>