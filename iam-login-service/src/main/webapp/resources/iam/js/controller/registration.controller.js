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
	
		
	function createRequest(request) {
		RegistrationRequestService.createRequest(request).then(
			function() {
				$window.location.href = "/registration/submitted";
			},
			function(errResponse) {
				$scope.operationResult = 'err';
				$scope.textAlert = errResponse.data.error_description || errResponse.data.detail;
				return $q.reject(errResponse);
			})
	};

	function submit() {
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
