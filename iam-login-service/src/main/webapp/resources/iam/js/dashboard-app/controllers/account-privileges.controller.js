'use strict';

angular.module('dashboardApp').controller('AccountPrivilegesController',
		AccountPrivilegesController);

AccountPrivilegesController.$inject= [ '$scope', '$rootScope', '$uibModalInstance', 'Utils',
                       		'Authorities', 'user'];

function AccountPrivilegesController($scope, $rootScope, $uibModalInstance, Utils, Authorities, user){
	
	var ctrl = this;

	ctrl.user = user;
	
	ctrl.enabled = true;
	ctrl.cancel = cancel;
	ctrl.assign = assign;
	ctrl.revoke = revoke;
	
	ctrl.userName = user.name.formatted;
	
	function successHandler(result){
		$uibModalInstance.close(result);
	}
	
	function errorHandler(error){
		var data = error.data;
		if (data.error){
			console.error('Error:', data.error);
			$scope.operationResult = Utils.buildErrorResult(data.error);
		}else{
			console.error(data);
			$scope.operationResult = Utils.buildErrorResult(data);
		}
		
		ctrl.enabled = true;
	}
	
	function assign() {
		ctrl.enabled = false;
				
		Authorities.assignAdminPrivileges(ctrl.user.id).then(successHandler, errorHandler);
	}
	
	function revoke() {
		ctrl.enabled = false;
				
		Authorities.revokeAdminPrivileges(ctrl.user.id).then(
				successHandler,
				errorHandler);
	}
	
	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}