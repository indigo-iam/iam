'use strict';

angular.module('dashboardApp').controller('AddOIDCAccountController',
		AddOIDCAccountController);

AddOIDCAccountController.$inject = [ '$scope', '$uibModalInstance',
		'scimFactory', '$state', 'user' ];

function AddOIDCAccountController($scope, $uibModalInstance, scimFactory,
		$state, user) {

	var addOidcCtrl = this;
	addOidcCtrl.user = user;
	addOidcCtrl.cancel = cancel;

	addOidcCtrl.addOidcAccount = addOidcAccount;
	addOidcCtrl.reset = reset;

	function reset() {

		addOidcCtrl.issuer = "";
		addOidcCtrl.subject = "";
	}
	;

	function addOidcAccount() {
		scimFactory.addOpenIDAccount(addOidcCtrl.user.id, addOidcCtrl.issuer,
				addOidcCtrl.subject).then(function(response) {
			$uibModalInstance.close(response.data);
		}, function(error) {
			console.error('Error creating group: ' + error);
			$state.go("error", {
				"error" : error
			});
		});
	}

	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}