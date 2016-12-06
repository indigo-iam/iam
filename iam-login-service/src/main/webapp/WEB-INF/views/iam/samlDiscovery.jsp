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