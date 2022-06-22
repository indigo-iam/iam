/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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