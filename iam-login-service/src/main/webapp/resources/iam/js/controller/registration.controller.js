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

angular.module('registrationApp').controller('RegistrationController', RegistrationController);

RegistrationController.$inject = [ '$scope', '$q', '$uibModalInstance', '$window', 'RegistrationRequestService' ];

function RegistrationController($scope, $q, $uibModalInstance, $window, RegistrationRequestService) {
	$scope.request = {
		givenname : '',
		familyname : '',
		username : '',
		email : '',
		notes : '',
	};

	$scope.textAlert;
	$scope.operationResult;

	$scope.createRequest = createRequest; 
	$scope.submit = submit;
	$scope.reset = reset;
	$scope.dismiss = dismiss;
	$scope.submitButtonDisabled = false;
	
		
	function createRequest(request) {
		RegistrationRequestService.createRequest(request).then(
			function() {
				$window.location.href = "/registration/submitted";
			},
			function(errResponse) {
				$scope.operationResult = 'err';
				$scope.textAlert = errResponse.data.error_description || errResponse.data.detail;
				$scope.submitButtonDisabled = false;
				return $q.reject(errResponse);
			})
	};

	function submit() {
		$scope.submitButtonDisabled = true;
		$scope.createRequest($scope.request);
	};

	function reset() {
		$scope.request = {
			givenname : '',
			familyname : '',
			username : '',
			email : '',
			notes : '',
		};
		$scope.registrationForm.$setPristine();
	};

	function dismiss() {
		$uibModalInstance.close();
	};
};

angular.module('registrationApp').controller('RegistrationFormModalController', RegistrationFormModalController);

RegistrationFormModalController.$inject = [ '$scope', '$uibModal' ];

function RegistrationFormModalController($scope, $uibModal) {
	$scope.open = function() {
		$uibModal.open({
			templateUrl : "/resources/iam/template/registration.html",
			controller : "RegistrationController",
			size : '600px',
			animation : true
		});
	};
};
