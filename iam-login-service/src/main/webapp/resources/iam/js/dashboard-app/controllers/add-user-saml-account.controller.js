'use strict';

angular.module('dashboardApp').controller('AddSamlAccountController', AddSamlAccountController);

AddSamlAccountController.$inject = ['$scope', '$uibModalInstance', 'scimFactory', '$state', 'user'];

function AddSamlAccountController($scope, $uibModalInstance, scimFactory, $state, user) {
	
	var addSamlAccountCtrl = this;
	addSamlAccountCtrl.user = user;
	addSamlAccountCtrl.cancel = cancel;
	
	addSamlAccountCtrl.addSamlAccount = addSamlAccount;
	addSamlAccountCtrl.reset = reset;
	
	function reset() {

		addSamlAccountCtrl.idpId = "";
		addSamlAccountCtrl.userId = "";
	};
	
	function addSamlAccount() {
		
		scimFactory.addSamlId(addSamlAccountCtrl.user.id, addSamlAccountCtrl.idpId, addSamlAccountCtrl.userId).then(function(response) {
			$uibModalInstance.close(response.data);
		},function(error) {
			console.error('Error creating new saml account: ' + error);
			$state.go("error", {
				"error" : error
			});
		});
	}
	
	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}