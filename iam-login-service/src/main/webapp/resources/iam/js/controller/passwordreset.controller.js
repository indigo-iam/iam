'use strict'

angular.module('passwordResetApp').controller('ResetPasswordController', ResetPasswordController);

ResetPasswordController.$inject = ['$scope', 'ResetPasswordService']

function ResetPasswordController($scope, ResetPasswordService){
	var vm = this;
	vm.password;
	vm.passwordrepeat;
	vm.resetkey;
	vm.operationResult;
	vm.textAlert;
	
	vm.submit = submit;
	vm.reset = reset;
	
	vm.messages = {
		'ok': "Your password has been update successfully. Go back to home page and log into Indigo!",
		'err': "An error occuors. Password has not been changed!"
	};
	
	
	function submit(){
		ResetPasswordService.changePassword(vm.resetKey, vm.password).then(
			function(response){
				vm.operationResult = response.data;
				vm.textAlert = vm.messages[vm.operationResult];
				vm.reset();
			}
		);
	};
	
	function reset(){
		vm.password = '';
		vm.passwordrepeat = '';
		$scope.changePasswdForm.$setPristine();
	};
};


angular.module('passwordResetApp').controller('ForgotPasswordController', ForgotPasswordController);

ForgotPasswordController.$inject = ['$scope', '$uibModalInstance', 'ResetPasswordService']

function ForgotPasswordController($scope, $uibModalInstance, ResetPasswordService){

	$scope.email;
	
	$scope.submit = function(){
		ResetPasswordService.forgotPassword($scope.email);
		$scope.operationResult = 'ok';
		$scope.textAlert='If the email address specified is registered within a valid user, an email will be sent with a URL for reset password.'
		$scope.reset();
	}
	
	$scope.dismiss = function() {
		$uibModalInstance.close();
	};
	
	$scope.reset = function(){
		$scope.email = '';
		$scope.forgotPasswordForm.$setPristine();
	}
};


angular.module('passwordResetApp').controller('ForgotPasswordModalController', ForgotPasswordModalController);

ForgotPasswordModalController.$inject = ['$scope', '$uibModal'];

function ForgotPasswordModalController($scope, $uibModal){
	$scope.open = function() {
		$uibModal.open({
			templateUrl : "/resources/iam/template/forgotPassword.html",
			controller : "ForgotPasswordController",
			size : '600px',
			animation : true
		});
	};
};