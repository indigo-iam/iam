<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<o:iamHeader title="INDIGO IAM | User Dashboard" />

<body class="skin-blue" ng-app="dashboardApp">

<script type="text/ng-template" id="noConnectionTemplate.html">
<div class="modal-header">
    <h3 class="modal-title">Connection to IAM server broken</h3>
</div>
<div class="modal-body">
    <p>The connection was interrupted while the page was loading.</p>
            <ul>
                <li>The site could be temporarily unavailable or too busy. Try again in a few moments.</li>
            </ul>
</div>
<div class="modal-footer" class="text-center">
    <button class="btn btn-primary" data-dismiss="modal" type="button" data-ng-click="$root.refresh()">Retry</button>
</div>
</script>

    <header class="main-header"></header>

    <aside class="main-sidebar">
      <mainsidebar />
    </aside>

    <!-- Content Wrapper. Contains page content -->
    <div class="content-wrapper" ui-view="content"></div>
    <!-- /.content-wrapper -->

    <footer class="footer">
      <div class="footer_contents">
        <div class="pull-right hidden-xs">
          <b>Version</b> ${iamVersion} (${gitCommitId})
        </div>
        <div class="pull-left">
          <img src="resources/iam/img/logo_new_1.png" class="footer-indigo-logo"/>
          <a href="https://www.indigo-datacloud.eu/the_project"><strong>INDIGO DataCloud</strong></a> - <small><i>Better software for better science</i></small>
        </div>
      </div>
    </footer>

	<script type="text/javascript" src="<c:url value='/webjars/jquery/jquery.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-animate.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-router/angular-ui-router.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-select/select.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-sanitize/angular-sanitize.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-resource.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/bootstrap/bootstrap.min.js'/>"></script>

	<script type="text/javascript" src="/resources/iam/js/adminLTE.js"></script>
	<script type="text/javascript" src="/resources/iam/js/directive/angular-relative-date.min.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.module.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/box.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/header.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/mainsidebar.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/sidebar.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/registration.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/operation-result.directive.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/userinfo-box.directive.js"></script>

    <script type="text/javascript" src="/resources/iam/js/dashboard-app/factory/gatewayerror.interceptor.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/factory/sessionexpired.interceptor.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/scim-factory.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/modal.service.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/services/passwordreset.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/registration.service.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/services/utils.service.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/home.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/user.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/users.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/groups.controller.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/registration.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-oidc-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-sshkey.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-saml-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-x509-certificate.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-group.controller.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-password.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-user.controller.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-me.controller.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/filters/start-from.filter.js"></script>

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.config.js"></script>

</body>
