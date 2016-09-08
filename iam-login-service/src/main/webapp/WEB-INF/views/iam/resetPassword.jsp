<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>

<o:iamHeader title="IAM Reset Password" />

<body ng-app="passwordResetApp" class="ng-cloak">

	<div class="absolute-center is-responsive">
		<div>

			<div id="logo-container"></div>

			<c:choose>
				<c:when test="${errorMessage != null}">
					<div class="alert alert-danger">Error: ${errorMessage}</div>
					
					<div style="width: 200px; margin: auto;">
						<a class="btn btn-primary btn-block" style="align: center" href='/login'>Back to Login Page</a>
					</div>
				</c:when>
				
				<c:otherwise>
					<div ng-controller="ResetPasswordController as ctrl">
					
						<h4 class="test-center">Change your Indigo password</h4>
						
						<div ng-show="ctrl.operationResult != null">
							<div class="alert" ng-class="{'alert-success': ctrl.operationResult=='ok', 'alert-danger': ctrl.operationResult=='err'}">
								<button class="close" ng-click="ctrl.operationResult=null" aria-label="close">&times;</button>
								{{ctrl.textAlert}}
							</div>
							
							<div style="width: 200px; margin: auto;" ng-show="ctrl.operationResult == 'ok'">
								<a class="btn btn-primary btn-block" style="align: center" href='/login'>Back to Login Page</a>
							</div>
						</div>
						
						<form class="form-horizontal" id="changePasswdForm" name="changePasswdForm" ng-submit="ctrl.submit()" ng-show="ctrl.operationResult != 'ok'">
						
							<input type="hidden" name="resetkey" value="${resetKey}" id="resetkey" ng-init="ctrl.resetKey='${resetKey}'">
						
							<div class="form-group">
								<label class="control-label col-sm-3" for="password">Password</label>
								<div class="col-sm-9" ng-class="{'has-error': changePasswdForm.password.$dirty && changePasswdForm.password.$invalid, 'has-success': changePasswdForm.password.$dirty && !changePasswdForm.password.$invalid}">
									<input class="form-control" type="password" placeholder="Password" 
									   autocorrect="off" autocapitalize="off" autocomplete="off" 
									   spellcheck="false" id="password" name="password" ng-model="ctrl.password"
									   required ng-minlength="6">
									<span class="glyphicon form-control-feedback" 
										  ng-class="{'glyphicon-remove': changePasswdForm.password.$dirty && changePasswdForm.password.$invalid, 'glyphicon-ok': changePasswdForm.password.$dirty && changePasswdForm.password.$valid}" 
										  style="right: 15px"></span>
									<span class="help-block" ng-show="changePasswdForm.password.$dirty && changePasswdForm.password.$error.required"> This is a required field</span> 
									<span class="help-block" ng-show="changePasswdForm.password.$dirty && changePasswdForm.password.$error.minlength">Minimum length required is 6</span> 
									<span class="help-block" ng-show="changePasswdForm.password.$dirty && changePasswdForm.password.$invalid">This field is invalid</span>
								</div>
							</div>
						
							<div class="form-group">
								<label class="control-label col-sm-3" for="passwordrepeat">Repeat</label>
								<div class="col-sm-9" ng-class="{'has-error': changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$invalid, 'has-success': changePasswdForm.passwordrepeat.$dirty && !changePasswdForm.passwordrepeat.$invalid}">
									<input class="form-control" type="password" placeholder="Repeat Password" 
										   autocorrect="off" autocapitalize="off" autocomplete="off" 
										   spellcheck="false" id="passwordrepeat" name="passwordrepeat" ng-model="ctrl.passwordrepeat"
										   required iam-password-check="ctrl.password">
								   <span class="glyphicon form-control-feedback" 
									  ng-class="{'glyphicon-remove': changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$invalid, 'glyphicon-ok': changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$valid}" 
									  style="right: 15px"></span>
									<span class="help-block" ng-show="changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$error.required"> This is a required field</span> 
									<span class="help-block" ng-show="changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$error.iamPasswordCheck"> Password doesn't match</span> 
									<span class="help-block" ng-show="changePasswdForm.passwordrepeat.$dirty && changePasswdForm.passwordrepeat.$invalid">This field is invalid</span>
								</div>
							</div>
		
							<div class="form-group">
								<div class="col-sm-offset-9 col-sm-3">
									<input type="submit" class="btn btn-primary" value="Save" name="submit" ng-disabled="changePasswdForm.$invalid">
								</div>
							</div>
						</form>
					</div>
					
				</c:otherwise>
			</c:choose>

		</div>
	</div>
	
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular.min.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angularjs/angular-animate.js'/>"></script>
	<script type="text/javascript" src="<c:url value='/webjars/angular-ui-bootstrap/ui-bootstrap-tpls.min.js'/>"></script>
	
	<script type="text/javascript" src="/resources/iam/js/passwordreset.app.js"></script>
	<script type="text/javascript" src="/resources/iam/js/service/passwordreset.service.js"></script>
	<script type="text/javascript" src="/resources/iam/js/controller/passwordreset.controller.js"></script>
	<script type="text/javascript" src="/resources/iam/js/directive/passwordreset.directive.js"></script>

</body>
