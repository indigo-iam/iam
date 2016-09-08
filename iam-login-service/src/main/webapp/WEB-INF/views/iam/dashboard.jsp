<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<o:iamHeader title="INDIGO IAM | User Dashboard" />

<body class="skin-blue" ng-app="dashboardApp">
	<div class="wrapper">

		<header class="main-header" ng-controller="TopbarController"></header>


		<aside class="main-sidebar" ng-controller="NavController as navCtrl">
			<mainsidebar />
		</aside>

		<!-- Content Wrapper. Contains page content -->
		<div class="content-wrapper" ui-view="content"></div>
		<!-- /.content-wrapper -->
	</div>

	<footer class="main-footer">
		<div class="pull-right hidden-xs">
			<b>Version</b> 0.3.0
		</div>
		<strong> Copyright &copy; <a
			href="https://www.indigo-datacloud.eu/the_project">The INDIGO
				Project</a>.
		</strong> All rights reserved.
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

	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.module.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/box.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/header.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/mainsidebar.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/ng-confirm-click.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/sidebar.directive.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/scim-factory.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/utils.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/modal.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/registration.service.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/home.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/user.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/group.controller.js"></script>
    <script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/nav.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/topbar.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/error.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/unauthorized.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/users.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/groups.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-oidc-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-sshkey.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-saml-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-x509-certificate.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/registration.controller.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/filters/start-from.filter.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.config.js"></script>


</body>