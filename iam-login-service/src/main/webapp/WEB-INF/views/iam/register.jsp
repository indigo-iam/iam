<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="t" tagdir="/WEB-INF/tags/iam"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<t:page title="Register">
  <jsp:attribute name="footer">
    <script type="text/javascript" src="/webjars/angularjs/angular.min.js"></script>
    <script type="text/javascript" src="/webjars/angularjs/angular-animate.js"></script>
    <script type="text/javascript" src="/webjars/angularjs/angular-cookies.js"></script>
    <script type="text/javascript" src="/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/registration/registration.app.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/registration/registration.controller.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/registration/registration.directive.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/registration/registration.service.js"></script>
    <script type="text/javascript" src="/resources/iam/apps/registration/authn-info.service.js"></script>
  </jsp:attribute>
  <jsp:body>
    <div ng-app="registrationApp">
      <div ng-include src="'resources/iam/apps/registration/registration.html'">
      </div>
    </div>
  </jsp:body>
</t:page> 