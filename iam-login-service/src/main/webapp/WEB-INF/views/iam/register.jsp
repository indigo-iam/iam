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
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>

<t:page title="Register">
    <jsp:attribute name="footer">
        <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
        <script type="text/javascript" src="/webjars/angular-animate/angular-animate.min.js"></script>
        <script type="text/javascript" src="/webjars/angular-cookies/angular-cookies.min.js"></script>
        <script type="text/javascript" src="/webjars/angular-ui-bootstrap/dist/ui-bootstrap-tpls.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/registration.app.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/registration.controller.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/registration.directive.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/registration.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/authn-info.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/aup.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/registration/privacy-policy.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/js/toaster/toaster.min.js"></script>
        <script type="text/javascript" src="<c:url value='/webjars/angular-ui-router/release/angular-ui-router.min.js'/>"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/dashboard-app/services/utils.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/apps/dashboard-app/services/http-utils.service.js"></script>
    </jsp:attribute>
    <jsp:body>
        <div ng-app="registrationApp">
            <div ng-include src="'${resourcesPrefix}/iam/apps/registration/registration.html'">
            </div>
        <script>
           var IAM_X509_CRED = "${IAM_X509_CRED.certificateChainPemString}";
        </script>

    <c:if test="${not empty IAM_X509_CRED}">
        <div id="x509-authn-info">
            You have been successfully authenticated as<br>
            <strong>${IAM_X509_CRED.subject}</strong>
            <c:if test="${!IAM_X509_CAN_LOGIN && !IAM_X509_SUSPENDED_ACCOUNT}">
                <p>
                This certificate is not linked to any account in this organization
                </p>
            </c:if>
            <c:if test="${IAM_X509_SUSPENDED_ACCOUNT}">
                <p>
                This certificate is linked to a suspended account in this organization
                </p>
            </c:if>
    </div>
    </c:if>
    </jsp:body>
</t:page>

<o:iamHeader title="Register">
    <jsp:body>
        <div ng-app="registrationApp">
            <div ng-include src="'${resourcesPrefix}/iam/apps/registration/registration.html'">
            </div>
        </div> 
    </jsp:body>
</o:iamHeader>