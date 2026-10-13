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
	.controller('UserMfaController', UserMfaController);

UserMfaController.$inject = [
	'$http', '$scope', '$state', '$uibModalInstance', 'Utils', 'user', '$uibModal', 'toaster', 'PasskeyService'
];

function UserMfaController(
	$http, $scope, $state, $uibModalInstance, Utils, user, $uibModal, toaster, PasskeyService) {
	var userMfaCtrl = this;

	userMfaCtrl.passkeyEnabled = Utils.isPasskeyEnabled();
	userMfaCtrl.mfaMandatory = Utils.isMfaMandatory();
	userMfaCtrl.passkeys = [];

	// Under mandatory MFA the authenticator app can only be disabled when a passkey remains
	userMfaCtrl.canDisableAuthenticatorApp = function() {
		return !userMfaCtrl.mfaMandatory || userMfaCtrl.passkeys.length > 0;
	};

	userMfaCtrl.$onInit = function() {
		console.log('UserMfaController onInit');
		getMfaSettings();
		getPasskeys();
	};

	// TODO include this data in what is fetched from the /scim/me endpoint
	function getMfaSettings() {
		$http.get('/iam/multi-factor-settings').then(function(response) {
			userMfaCtrl.authenticatorAppActive = response.data.authenticatorAppActive;
		});
	}

	function getPasskeys() {
		if (!userMfaCtrl.passkeyEnabled) {
			return;
		}
		PasskeyService.getPasskeys().then(function(response) {
			userMfaCtrl.passkeys = response.data;
		}).catch(function(error) {
			console.error('Error loading passkeys', error);
		});
	}

	userMfaCtrl.userToEdit = user;

	userMfaCtrl.enableAuthenticatorApp = enableAuthenticatorApp;
	userMfaCtrl.disableAuthenticatorApp = disableAuthenticatorApp;
	userMfaCtrl.addPasskey = addPasskey;
	userMfaCtrl.removePasskey = removePasskey;

	function addPasskey() {
		var modalInstance = $uibModal.open({
			templateUrl: '/resources/iam/apps/dashboard-app/templates/home/add-passkey.html',
			controller: 'AddPasskeyController',
			controllerAs: 'passkeyCtrl'
		});
		modalInstance.result.then(function(msg) {
			return $uibModalInstance.close(msg);
		});
	}

	function removePasskey(passkey) {
		var modalInstance = $uibModal.open({
			templateUrl: '/resources/iam/apps/dashboard-app/templates/home/remove-passkey.html',
			controller: 'RemovePasskeyController',
			controllerAs: 'passkeyCtrl',
			resolve: { passkey: function() { return passkey; } }
		});
		modalInstance.result.then(function(msg) {
			return $uibModalInstance.close(msg);
		});
	}

	function enableAuthenticatorApp() {
		var modalInstance = $uibModal.open({
			templateUrl: '/resources/iam/apps/dashboard-app/templates/home/enable-authenticator-app.html',
			controller: 'EnableAuthenticatorAppController',
			controllerAs: 'authAppCtrl',
			resolve: { user: function() { return self.user; } }
		});

		modalInstance.result.then(function(msg) {
			return $uibModalInstance.close(msg);
		});
	}

	function disableAuthenticatorApp() {
		var modalInstance = $uibModal.open({
			templateUrl: '/resources/iam/apps/dashboard-app/templates/home/disable-authenticator-app.html',
			controller: 'DisableAuthenticatorAppController',
			controllerAs: 'authAppCtrl',
			resolve: { user: function() { return self.user; } }
		});

		modalInstance.result.then(function(msg) {
			return $uibModalInstance.close(msg);
		});
	}

	userMfaCtrl.dismiss = dismiss;
	userMfaCtrl.reset = reset;

	function reset() {
		console.log('reset form');

		userMfaCtrl.enabled = true;

		if ($scope.userMfaForm) {
			$scope.userMfaForm.$setPristine();
		}
	}

	userMfaCtrl.reset();

	function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

	userMfaCtrl.message = '';

	userMfaCtrl.submit = function() {
		return $uibModalInstance.close('Updated settings');
	};
}
