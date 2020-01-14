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
<%@ taglib
  prefix="c"
  uri="http://java.sun.com/jsp/jstl/core"%>
  
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>

<t:page title="Log in">
  <jsp:attribute name="footer">
    <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
    <script type="text/javascript" src="/webjars/angularjs/angular-animate.js"></script>
    <script type="text/javascript" src="/webjars/angularjs/angular-cookies.js"></script>
    <script type="text/javascript" src="/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/saml-discovery/discovery.app.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/saml-discovery/discovery.component.js"></script>
  </jsp:attribute>
  <jsp:body>
      <div class="row" ng-app="discoveryApp">
          <discovery></discovery>
      </div>
  </jsp:body>
</t:page>