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

angular.module('dashboardApp').controller('AccountLinkingController',
		AccountLinkingController);

AccountLinkingController.$inject= [ '$scope', '$rootScope', '$log', '$uibModalInstance', '$window', 'Utils','opts'];

function AccountLinkingController($scope, $rootScope, $log, $uibModalInstance, $window, Utils, opts){
	
    var vm = this;

	vm.opts = opts;
    vm.link = link;
    vm.unlink = unlink;
    vm.cancel = cancel;

    function link(){

        $log.info("account link called");

        if (opts.type === 'Google'){
            $window.location.href = '/iam/account-linking/OIDC';
        } else if (opts.type === 'SAML'){
            $window.location.href = '/iam/account-linking/SAML';
        }
    }

    function unlink() {
        $log.info("account unlink called");
        $uibModalInstance.close();
    }

	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}