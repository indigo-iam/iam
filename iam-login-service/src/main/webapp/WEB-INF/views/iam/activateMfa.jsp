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
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam" %>
<t:page title="Activate multi factor authentication">
  <jsp:attribute name="footer">
        <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
        <script type="text/javascript" src="/webjars/angular-animate/angular-animate.min.js"></script>
        <script type="text/javascript" src="/webjars/angular-ui-bootstrap/dist/ui-bootstrap-tpls.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/js/activateMfa.app.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/js/service/activateMfa.service.js"></script>
        <script type="text/javascript" src="${resourcesPrefix}/iam/js/controller/activateMfa.controller.js"></script>
        <script type="text/javascript">
            angular.element(document).ready(function () { angular.bootstrap(document, ['activateMfaApp']); });
        </script>
  </jsp:attribute>
  <jsp:body>
    <div>
      
      <div ng-controller="ActivateMfaController as activateMfaCtrl">
        <ng-include src="'/resources/iam/apps/dashboard-app/templates/home/activateMfa.html'"></ng-include>
      </div>

      <form class="verify-form text-center" action="/logout" method="post">
        <button type="submit" class="btn btn-warning">Back to Login Page</button>
      </form>
    </div>
  </jsp:body>
</t:page>