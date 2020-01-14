/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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

angular.module('registrationApp').controller('RegistrationController',
    RegistrationController);

RegistrationController.$inject = ['$scope', '$q', '$window', '$cookies',
    'RegistrationRequestService', 'AuthnInfo', 'Aup', 'PrivacyPolicy'
];

function RegistrationController($scope, $q, $window, $cookies, RegistrationRequestService, AuthnInfo, Aup, PrivacyPolicy) {

    var vm = this;
    var EXT_AUTHN_ROLE = 'ROLE_EXT_AUTH_UNREGISTERED';

    $scope.organisationName = getOrganisationName();
    $scope.request = {};

    $scope.textAlert = undefined;
    $scope.operationResult = undefined;

    $scope.privacyPolicy = undefined;

    $scope.busy = false;

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

    function activate() {
        vm.resetRequest();
        vm.populateRequest();
        Aup.getAup().then(function (res) {
            if (res != null) {
                $scope.aup = res.data;
            }
        }).catch(function (res) {
            console.error("Error getting AUP : " +
                res.status + " " + res.statusText);
        });
        PrivacyPolicy.getPrivacyPolicy().then(function (res) {
            $scope.privacyPolicy = res;
        }).catch(function (res) {
            console.error("Error fetching privacy policy: " + res.status + " " + res.statusText);
        })
    }

    function userIsExternallyAuthenticated() {
        return getUserAuthorities().indexOf(EXT_AUTHN_ROLE) > -1;
    }

    function populateRequest() {

        var success = function (res) {
            var info = res.data;
            $scope.extAuthInfo = info;
            $scope.request = {
                givenname: info.given_name,
                familyname: info.family_name,
                username: info.suggested_username,
                email: info.email,
                notes: '',
            };

            if (info.type === 'OIDC') {
                $scope.extAuthProviderName = 'an OIDC identity provider';
            } else {
                $scope.extAuthProviderName = 'a SAML identity provider';
            }

            angular.forEach($scope.registrationForm.$error.required, function (field) {
                field.$setDirty();
            });
        };

        var error = function (err) {
            $scope.operationResult = 'err';
            $scope.textAlert = err.data.error_description || err.data.detail;
            $scope.busy = false;
        };

        if (userIsExternallyAuthenticated()) {
            $scope.isExternallyAuthenticated = true;
            AuthnInfo.getInfo().then(success, error);
        } else {
            console.info("User is NOT externally authenticated");
        }
    }

    function createRequest() {
        var success = function (res) {
            $window.location.href = "/registration/submitted";
        };

        var error = function (err) {
            $scope.operationResult = 'err';
            $scope.textAlert = err.data.error_description || err.data.detail;
            $scope.busy = false;
        };

        RegistrationRequestService.createRequest($scope.request).then(success, error);
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
        };
    }

    function reset() {
        resetRequest();
        $scope.registrationForm.$setPristine();
    }

    function clearSessionCookies() {
        $window.location.href = "/reset-session";
    }

    function fieldValid(name) {
        return $scope.registrationForm[name].$dirty && $scope.registrationForm[name].$valid;
    }

    function fieldInvalid(name) {
        return $scope.registrationForm[name].$dirty && $scope.registrationForm[name].$invalid;
    }

}