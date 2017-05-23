'use strict';

angular.module('dashboardApp').controller('AddSamlAccountController', AddSamlAccountController);

AddSamlAccountController.$inject = ['$scope', '$uibModalInstance', 'scimFactory', 'Utils', '$state', 'user'];

function AddSamlAccountController($scope, $uibModalInstance, scimFactory, Utils, $state, user) {
	
	var addSamlAccountCtrl = this;
	addSamlAccountCtrl.user = user;
	addSamlAccountCtrl.cancel = cancel;
	
	addSamlAccountCtrl.addSamlAccount = addSamlAccount;
	addSamlAccountCtrl.reset = reset;
	
	addSamlAccountCtrl.reset();
	
	function reset() {

		addSamlAccountCtrl.idpId = "";
		addSamlAccountCtrl.userId = "";
		addSamlAccountCtrl.attributeId = "";
		addSamlAccountCtrl.enabled = true;
	};
	
	function addSamlAccount() {

		addSamlAccountCtrl.enabled = false;
		scimFactory.addSamlId(addSamlAccountCtrl.user.id, addSamlAccountCtrl.idpId,		
			addSamlAccountCtrl.attributeId, addSamlAccountCtrl.userId).then(function(response) {
			$uibModalInstance.close(response.data);
			addSamlAccountCtrl.enabled = true;
		},function(error) {
			console.error('Error creating new saml account: ' + error);
			$scope.operationResult = Utils.buildErrorOperationResult(error);
			addSamlAccountCtrl.enabled = true;
		});
	}
	
	function cancel() {
		$uibModalInstance.dismiss("Cancel");
	}
}