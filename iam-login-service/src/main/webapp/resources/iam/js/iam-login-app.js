'use strict';

angular
		.module('iam-login-app', [ 'ui.bootstrap' ])
		.controller(
				'idp-selection',
				[
						'$scope',
						'$http',
						'$uibModalInstance',
						'$log',
						'$window',
						function($scope, $http, $uibModalInstance, $log,
								$window) {

							$scope.ok = function() {
								$window.location.href = "/saml/login?idp="
										+ $scope.idpSelected.entityId;
							};

							$scope.cancel = function() {
								$uibModalInstance.close();
							};

							$scope.lookupIdp = function(val) {

								var result = $http.get('/saml/idps', {
									params : {
										q : val
									}
								}).then(function(response) {
									return response.data;
								});

								return result;
							}
						} ])
		.controller(
				'idp-selection-modal-ctrl',
				[
						'$scope',
						'$uibModal',
						function($scope, $uibModal) {

							$scope.open = function() {
								$uibModal
										.open({
											templateUrl : "/resources/iam/template/idpSelectionModalContent.html",
											controller : "idp-selection",
											size : 'lg',
											animation : true
										});
							};
						} ]);
