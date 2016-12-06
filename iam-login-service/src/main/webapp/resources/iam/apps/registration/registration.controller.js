'use strict';

angular.module('registrationApp').controller('RegistrationController',
		RegistrationController);

RegistrationController.$inject = [ '$scope', '$q', '$window', '$cookies',
		'RegistrationRequestService', 'AuthnInfo' ];

function RegistrationController($scope, $q, $window, $cookies,
		RegistrationRequestService, AuthnInfo) {

	var vm = this;
	var EXT_AUTHN_ROLE = 'ROLE_EXT_AUTH_UNREGISTERED';
	
	$scope.organisationName = getOrganisationName();
	$scope.request = {};
	
	$scope.textAlert = undefined;
	$scope.operationResult = undefined;

	$scope.submitDisabled = false;

	vm.createRequest = createRequest;
	vm.populateRequest = populateRequest;
	vm.resetRequest = resetRequest;

	vm.activate = activate;
	vm.submit = submit;
	vm.reset = reset;
	vm.fieldValid = fieldValid;
	vm.fieldInvalid = fieldInvalid;
	vm.clearSessionCookies = clearSessionCookies;
	
	vm.activate();
	
	function activate(){
		vm.resetRequest();
		vm.populateRequest();
	}

	function userIsExternallyAuthenticated(){
		return getUserAuthorities().indexOf(EXT_AUTHN_ROLE) > -1;
	}
	
	function populateRequest(){
		
		var success = function(res){
			var info = res.data;
			$scope.extAuthInfo = info;
			$scope.request = {
					givenname : info.given_name,
					familyname : info.family_name,
					username : '',
					email : info.email,
					notes : '',
			};
			
			if (info.type === 'OIDC'){
				$scope.extAuthProviderName = 'Google';
			} else {
				$scope.extAuthProviderName = 'a SAML identity provider';
			}
			 
			angular.forEach($scope.registrationForm.$error.required, function(field) {
			    field.$setDirty();
			});
		}
		
		var error = function(err){
			$scope.operationResult = 'err';
			$scope.textAlert = err.data.error_description || err.data.detail;
			vm.submitDisabled = false;
		}
		
		if (userIsExternallyAuthenticated()){
			$scope.isExternallyAuthenticated = true;
			AuthnInfo.getInfo().then(success, error);
		} else {
			console.info("User is NOT externally authenticated");
		}
	}
	
	function createRequest() {
		var success = function(res) {
			$window.location.href = "/registration/submitted";
		}

		var error = function(err) {
			$scope.operationResult = 'err';
			$scope.textAlert = err.data.error_description || err.data.detail;
			vm.submitDisabled = false;
		}

		RegistrationRequestService.createRequest($scope.request).then(success, error);
	}

	function submit() {
		vm.submitDisabled = true;
		vm.createRequest();
	}

	function resetRequest(){
		$scope.request = {
				givenname : '',
				familyname : '',
				username : '',
				email : '',
				notes : '',
		};
	}
	
	function reset() {
		resetRequest();
		$scope.registrationForm.$setPristine();
	}

	function clearSessionCookies() {
		$window.location.href = "/reset-session";
	}

	function fieldValid(name){
		return $scope.registrationForm[name].$dirty && $scope.registrationForm[name].$valid;
	}
	
	function fieldInvalid(name){
		return $scope.registrationForm[name].$dirty && $scope.registrationForm[name].$invalid;
	}

}