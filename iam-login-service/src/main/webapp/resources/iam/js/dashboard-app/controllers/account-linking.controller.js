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