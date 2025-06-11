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

angular.module('registrationApp')
	.controller('RegistrationController', RegistrationController);

RegistrationController.$inject = [
	'$scope', '$q', '$window', '$cookies', 'RegistrationRequestService',
	'AuthnInfo', 'Aup', 'PrivacyPolicy', '$uibModal', 'toaster', '$state'
];

function RegistrationController(
	$scope, $q, $window, $cookies, RegistrationRequestService, AuthnInfo, Aup,
	PrivacyPolicy, $uibModal,  toaster,  $state, Utils) {

	var vm = this;
	var EXT_AUTHN_ROLE = 'ROLE_EXT_AUTH_UNREGISTERED';

	$scope.organisationName = getOrganisationName();
	$scope.request = {};
	
	const cred = window.IAM_X509_CRED;

	$scope.iamX509Required = window.IAM_X509_REQUIRED;
	
	if(cred){
		$scope.iamX509Cred = window.IAM_X509_CRED;
		$scope.iamX509Subject = window.IAM_X509_CRED_SUBJECT;
		$scope.iamX509Issuer = window.IAM_X509_CRED_ISSUER;
		$scope.iamX509CanLogin = !!window.IAM_X509_CAN_LOGIN;
		$scope.iamX509SuspendedAccount = !!window.IAM_X509_SUSPENDED_ACCOUNT;
		$scope.iamX509AlmostExpired = !!window.IAM_X509_ALMOST_EXPIRED;
		$scope.iamX509ExpirationDate = window.IAM_X509_EXPIRATION_DATE;
	}
	

	$scope.textAlert = undefined;
	$scope.operationResult = undefined;

	$scope.privacyPolicy = undefined;

	$scope.busy = false;

	$scope.config = undefined;

	// Form `fields` with necessary properties and validations.
	$scope.fields = {
		name: {
			name: "name",
			label: "Given Name",
			ngModelName: "givenname",
			articleToUse: "a",
			placeholder: "Enter your first name",
			type: "text",
			minlength: 2,
			required: true,
			showField: true,
		},
		surname: {
			name: "surname",
			label: "Family Name",
			ngModelName: "familyname",
			articleToUse: "a",
			placeholder: "Enter your family name",
			type: "text",
			minlength: 2,
			required: true,
			showField: true,
		},
		email: {
			name: "email",
			label: "Email",
			ngModelName: "email",
			articleToUse: "an",
			placeholder: "Enter a valid email address",
			type: "email",
			required: true,
			showField: true,
			debounceTime: 500
		},
		username: {
			name: "username",
			label: "Username",
			ngModelName: "username",
			articleToUse: "a",
			placeholder: "Choose a username for your account",
			type: "text",
			minlength: 2,
			required: true,
			showField: true,
			debounceTime: 500
		},
		notes: {
			name: "notes",
			label: "Notes",
			ngModelName: "notes",
			articleToUse: "a",
			placeholder:
				"Providing a clear explanation on the motivation behind this request will likely speed up the approval process",
			type: "textarea",
			rows: 5,
			required: true,
			showField: true,
		},
		registerCertificate:{

		}			
		
	};

	vm.createRequest = createRequest;
	vm.populateRequest = populateRequest;
	vm.resetRequest = resetRequest;
	vm.activate = activate;
	vm.submit = submit;
	vm.reset = reset;
	vm.fieldValid = fieldValid;
	vm.fieldInvalid = fieldInvalid;
	vm.fieldReadonly = fieldReadonly;
	vm.clearSessionCookies = clearSessionCookies;
	vm.populateFieldsWithAdminPreference = populateFieldsWithAdminPreference;
	vm.getFieldErrorMessage = getFieldErrorMessage;
	vm.openExpiringCertificateDialog = openExpiringCertificateDialog;
	vm.registerCertificate = true;

	vm.activate();
	vm.openExpiringCertificateDialog();

	function ExpiringCertificateController (
        $uibModalInstance, cert, expirationDate) {
        var self = this;
        self.enabled = true;
        self.cert = cert;
		self.expirationDate = expirationDate;

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };
    }


	function openExpiringCertificateDialog () {

			if($scope.iamX509AlmostExpired){

				var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/registration/certificate-expiration.html',
                controller: ExpiringCertificateController,
                controllerAs: '$ctrl',
				backdrop: 'static',
                resolve: {
                    cert: {
                        subjectDn: $scope.iamX509Subject,
                        issuerDn: $scope.iamX509Issuer
                    },
					expirationDate: {
						date: $scope.iamX509ExpirationDate
					}
                }
            });

            modalInstance.result.then(self.handleSuccess);

			}
        };

	function activate() {
		RegistrationRequestService.getConfig()
			.then(function(res) {
				$scope.config = res.data;
				vm.resetRequest();
				vm.populateFieldsWithAdminPreference();
				vm.populateRequest();
			})
			.catch(function(err) {
				console.error(
					'Error fetching registration config: ' + res.status + ' ' +
					res.statusText);
			});

		Aup.getAup()
			.then(function(res) {
				if (res != null) {
					$scope.aup = res.data;
				}
			})
			.catch(function(res) {
				console.error(
					'Error getting AUP : ' + res.status + ' ' + res.statusText);
			});
		PrivacyPolicy.getPrivacyPolicy()
			.then(function(res) {
				$scope.privacyPolicy = res;
			})
			.catch(function(res) {
				console.error(
					'Error fetching privacy policy: ' + res.status + ' ' +
					res.statusText);
			});
	}

	function userIsExternallyAuthenticated() {
		return getUserAuthorities().indexOf(EXT_AUTHN_ROLE) > -1;
	}

	function lookupAuthInfo(info, propertyName) {
		if (typeof info[propertyName] != 'undefined') {
			return info[propertyName];
		} else if (typeof info['additional_attributes'][propertyName] != 'undefined') {
			return info.additional_attributes[propertyName];
		} else {
			return undefined;
		}
	}

	function populateValue(info, name) {
		if (typeof $scope.config.fields != 'undefined' && typeof $scope.config.fields[name] != 'undefined' && typeof $scope.config.fields[name].externalAuthAttribute != 'undefined') {
			return lookupAuthInfo(info, $scope.config.fields[name].externalAuthAttribute);
		}
	}

	function populateRequest() {
		var success = function(res) {
			var info = res.data;
			$scope.extAuthInfo = info;
			$scope.request = {
				givenname: populateValue(info, 'name'),
				familyname: populateValue(info, 'surname'),
				username: populateValue(info, 'username'),
				email: populateValue(info, 'email'),
				notes: '',
				registerCertificate: true,
			};

			if (info.type === 'OIDC') {
				$scope.extAuthProviderName = 'an OIDC identity provider';
			} else {
				$scope.extAuthProviderName = 'a SAML identity provider';
			}

			angular.forEach($scope.registrationForm.$error.required, function(field) {
				field.$setDirty();
			});
		};

		var error = function(err) {
			$scope.operationResult = 'err';
			$scope.textAlert = err.data.error_description || err.data.detail;
			$scope.busy = false;
		};

		if (userIsExternallyAuthenticated()) {
			$scope.isExternallyAuthenticated = true;
			AuthnInfo.getInfo().then(success, error);
		} else {
			console.info('User is NOT externally authenticated');
		}
	}

	function createRequest() {
		var success = function(res) {
			$window.location.href = '/registration/submitted';
		};

		var error = function(err) {
			$scope.operationResult = 'err';
			$scope.textAlert = err.data.error;
			$scope.busy = false;
		};

		RegistrationRequestService.createRequest($scope.request)
			.then(success, error);
	}

	function submit() {
		$scope.busy = true;
		vm.createRequest();
	}

	function resetRequest() {
		$scope.request = {
			givenname: '',
			familyname: '',
			username: '',
			email: '',
			notes: '',
			registerCertificate: true
		};
	}

	function reset() {
		resetRequest();
		populateRequest();
		$scope.registrationForm.$setPristine();
	}

	function clearSessionCookies() {
		$window.location.href = '/reset-session';
	}

	function fieldValid(name) {
		return $scope.registrationForm[name].$dirty &&
			$scope.registrationForm[name].$valid;
	}

	function fieldInvalid(name) {
		return $scope.registrationForm[name].$dirty &&
			$scope.registrationForm[name].$invalid;
	}

	function fieldReadonly(name) {
		return $scope.config?.fields?.[name]?.readOnly === true;
	}

	function populateFieldsWithAdminPreference() {
		if ($scope.config.fields) {
			for (let field in $scope.config.fields) {
				if (
					$scope.config.fields[field]["fieldBehaviour"].toLowerCase() == "mandatory"
				) {
					$scope.fields[field].showField = true;
					$scope.fields[field].required = true;
				} else if (
					$scope.config.fields[field]["fieldBehaviour"].toLowerCase() === "optional"
				) {
					$scope.fields[field].showField = true;
					$scope.fields[field].required = false;
				} else {
					$scope.fields[field].showField = false;
					$scope.fields[field].required = false;
				}
			}
		}
	}

	function getFieldErrorMessage(fieldName) {
		let field = $scope.registrationForm[fieldName];
		let fieldInfo = $scope.fields[fieldName];

		if (!fieldInfo) {
			return null;
		}

		if (field.$error.required) {
			if (fieldName === 'notes') {
				return 'Please provide a reason for your registration request';
			}
			return 'Please provide ' + fieldInfo.articleToUse + ' ' + fieldInfo.label.toLowerCase();
		} else if (field.$error.minlength) {
			return fieldInfo.label + ' must be at least ' + fieldInfo.minlength + ' characters long';
		} else if (field.$error.email) {
			return 'This is not a valid email';
		} else if (field.$error.emailAvailable) {
			return 'This email is already linked to another user';
		} else if (field.$error.usernameAvailable) {
			return 'This username is already linked to another user';
		}

		return null;
	}


}
