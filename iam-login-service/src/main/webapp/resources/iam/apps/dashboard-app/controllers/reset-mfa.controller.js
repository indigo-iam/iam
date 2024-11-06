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

angular.module('dashboardApp')
	.controller('ResetMfaController', ResetMfaController);

ResetMfaController.$inject = [
	'$http', '$scope', '$state', '$uibModalInstance', 'Utils', 'AuthenticatorAppService', 'user', '$uibModal', 'toaster'
];

function ResetMfaController(
	$http, $scope, $state, $uibModalInstance, Utils, AuthenticatorAppService, user, $uibModal, toaster) {
	var resetMfaCtrl = this;

	resetMfaCtrl.userToEdit = user;

	resetMfaCtrl.resetMfa = function () {
		AuthenticatorAppService.resetAuthenticatorApp(user.id).then(function(result) {
			if (result != null && result.status === 200) {
			  $uibModalInstance.close('Multi-factor authentication settings reset');
			} else {
			  var message = "Unable to reset Multi-factor authentication settings";
			  console.error(message);
			  $uibModalInstance.close(message);
			}
		  }).catch(function(error) { 
			console.error(error);
			toaster.pop({ type: 'error', body: error.data.error });
			$uibModalInstance.dismiss();
		  });
	};

	resetMfaCtrl.cancel = function () { return $uibModalInstance.close('Cancel'); };

}
