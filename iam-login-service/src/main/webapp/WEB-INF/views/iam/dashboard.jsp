<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<o:iamHeader title="INDIGO IAM | Dashboard" />

<body id="body" class="skin-blue" ng-app="dashboardApp" ng-cloak style="display: none">
	
	<script type="text/ng-template" id="noConnectionTemplate.html">
		<div class="modal-header">
			<h3 class="modal-title">Lost connection to the IAM server</h3>
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
	
	<div class="wrapper">
		<toaster-container
				toaster-options="{'close-button': true, 'time-out':{ 'toast-error': 0, 'toast-success': 5000, 'toast-warning': 5000 }, 'position-class': 'toast-top-center'}">
		</toaster-container>
		
		<header class="main-header" ng-cloak></header>
		<aside class="main-sidebar" ng-cloak>
			<mainsidebar />
		</aside>

		<!-- Content Wrapper. Contains page content -->
		<div class="content-wrapper" ng-cloak>
			<div id="iam-content" ui-view="content" ng-cloak>
			</div>			
		</div>
		<!-- /.content-wrapper -->
	</div>

	<!-- Libraries -->
	<script type="text/javascript" src="<c:url value='/webjars/jquery/jquery.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-animate.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-resource.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-cookies.min.js'/>"></script>
	
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-router/angular-ui-router.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-select/select.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-sanitize/angular-sanitize.min.js'/>"></script>

	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/bootstrap/bootstrap.min.js'/>"></script>

	<script type="text/javascript" src="/resources/iam/js/adminLTE.js"></script>
	<script type="text/javascript" src="/resources/iam/js/toaster/toaster.min.js"></script>
	<script type="text/javascript" src="/resources/iam/js/directive/angular-relative-date.min.js"></script>

	<!-- Dashboard app -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.module.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/dashboard-app.config.js"></script>

	<!-- Directives -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/box.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/header.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/mainsidebar.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/sidebar.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/registration.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/operation-result.directive.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/directives/userinfo-box.directive.js"></script>

	<!-- Interceptors -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/factory/gatewayerror.interceptor.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/factory/sessionexpired.interceptor.js"></script>

	<!-- Filters -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/filters/start-from.filter.js"></script>

	<!-- Services -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/scim-factory.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/modal.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/passwordreset.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/registration.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/utils.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/authorities.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/user.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/load-templates.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/services/account-linking.service.js"></script>

	<!-- Controllers -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/users.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/groups.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/registration.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/account-privileges.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-user.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-group.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-oidc-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/add-user-saml-account.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/controllers/edit-password.controller.js"></script>

	<!-- Components -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/common/result.component.js"></script>

	<!-- User components -->
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/detail/user.detail.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/edit/user.edit.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/status/user.status.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/privileges/user.privileges.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/password/user.password.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/groups/user.groups.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/oidc/user.oidc.component.js"></script>
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/saml/user.saml.component.js"></script>
	
	<script type="text/javascript" src="/resources/iam/js/dashboard-app/components/user/user.component.js"></script>

</body>
