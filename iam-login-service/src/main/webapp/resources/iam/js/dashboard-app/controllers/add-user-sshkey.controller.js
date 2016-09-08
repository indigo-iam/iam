'use strict';

angular.module('dashboardApp').controller('AddSshKeyController',
		AddSshKeyController);

AddSshKeyController.$inject = [ '$scope', '$uibModalInstance', 'scimFactory',
		'$state', 'user' ];

function AddSshKeyController($scope, $uibModalInstance, scimFactory, $state,
		user) {

	var addSshKeyCtrl = this;
	addSshKeyCtrl.user = user;
	addSshKeyCtrl.cancel = cancel;

	addSshKeyCtrl.addSshKey = addSshKey;
	addSshKeyCtrl.reset = reset;

	function reset() {

		addSshKeyCtrl.label = "";
		addSshKeyCtrl.value = "";
	}

	function checkBase64Encoding() {

		var base64Matcher = new RegExp(
				"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$");
		return (base64Matcher.test(addSshKeyCtrl.value));
	}

	function addSshKey() {

		if (!checkBase64Encoding()) {
			alert("Key is not a base64 encoded string!");
			return;
		}

		scimFactory.addSshKey(addSshKeyCtrl.user.id, addSshKeyCtrl.label,
				false, addSshKeyCtrl.value).then(
				function(response) {
					console.log("Added SSH-key: ", addSshKeyCtrl.label,
							addSshKeyCtrl.value);
					$uibModalInstance.close(response.data);
				}, function(error) {
					console.error('Error creating ssh key: ' + error);
					$state.go("error", {
						"error" : error
					});
				});
	}

	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}