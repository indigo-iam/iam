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
	'$http', '$q', '$scope', '$state', '$uibModalInstance', 'Utils', 'user', '$uibModal', 'toaster',
	'PasskeyService'
];

function UserMfaController(
	$http, $q, $scope, $state, $uibModalInstance, Utils, user, $uibModal, toaster, PasskeyService) {
	var userMfaCtrl = this;

	userMfaCtrl.passkeyEnabled = Utils.isPasskeyEnabled();
	userMfaCtrl.passkeyMandatory = Utils.isPasskeyMandatory();
	userMfaCtrl.mfaMandatory = Utils.isMfaMandatory();
	userMfaCtrl.authenticatorAppActive = false;
	userMfaCtrl.passkeys = [];
	// The factor buttons are decided on both the settings and the passkey list: they stay hidden
	// until both have been loaded
	userMfaCtrl.loaded = false;

	// The same rules the server enforces: under a mandatory policy the last factor stays. When
	// passkeys are mandatory only another passkey counts, otherwise the authenticator app does too.
	// Stored passkeys count only while the feature is enabled: otherwise they are inert
	userMfaCtrl.canDisableAuthenticatorApp = function() {
		return !(userMfaCtrl.mfaMandatory || userMfaCtrl.passkeyMandatory)
			|| (userMfaCtrl.passkeyEnabled && userMfaCtrl.passkeys.length > 0);
	};

	userMfaCtrl.canRemovePasskey = function() {
		if (!userMfaCtrl.passkeyEnabled) {
			// An inert credential is not a factor: the server removes it without a policy check
			return true;
		}
		if (userMfaCtrl.passkeyMandatory) {
			return userMfaCtrl.passkeys.length > 1;
		}
		if (userMfaCtrl.mfaMandatory) {
			return userMfaCtrl.passkeys.length > 1 || userMfaCtrl.authenticatorAppActive;
		}
		return true;
	};

	// Stored passkeys are shown even while the feature is disabled, so that they can be removed
	userMfaCtrl.showPasskeys = function() {
		return userMfaCtrl.passkeyEnabled || userMfaCtrl.passkeys.length > 0;
	};

	userMfaCtrl.$onInit = function() {
		console.log('UserMfaController onInit');
		$q.all([getMfaSettings(), getPasskeys()]).finally(function() {
			userMfaCtrl.loaded = true;
		});
	};

	// TODO include this data in what is fetched from the /scim/me endpoint
	function getMfaSettings() {
		return $http.get('/iam/multi-factor-settings').then(function(response) {
			userMfaCtrl.authenticatorAppActive = !!response.data.authenticatorAppActive;
		}).catch(function(error) {
			console.error('Error loading multi-factor settings', error);
		});
	}

	function getPasskeys() {
		return PasskeyService.getPasskeys().then(function(response) {
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
			resolve: {
				passkey: function() { return passkey; },
				proofOptions: function() {
					return {
						passkeyEnabled: userMfaCtrl.passkeyEnabled,
						// The authenticator app proves the removal only where it is accepted at login
						authenticatorAppActive: userMfaCtrl.authenticatorAppActive
							&& !userMfaCtrl.passkeyMandatory
					};
				}
			}
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
