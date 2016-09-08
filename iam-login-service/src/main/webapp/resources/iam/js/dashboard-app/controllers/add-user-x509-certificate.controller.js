'use strict';

angular.module('dashboardApp').controller('AddX509CertificateController',
		AddX509CertificateController);

AddX509CertificateController.$inject = [ '$scope', '$uibModalInstance',
		'scimFactory', '$state', 'user' ];

function AddX509CertificateController($scope, $uibModalInstance, scimFactory,
		$state, user) {

	var addX509CertCtrl = this;
	addX509CertCtrl.user = user;
	addX509CertCtrl.cancel = cancel;

	addX509CertCtrl.addCertificate = addCertificate;
	addX509CertCtrl.reset = reset;

	function reset() {

		addX509CertCtrl.label = "";
		addX509CertCtrl.value = "";
	}

	function checkBase64Encoding() {

		var base64Matcher = new RegExp(
				"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$");
		return (base64Matcher.test(addX509CertCtrl.value));
	}

	function addCertificate() {

		console.log("Adding Certificate ", addX509CertCtrl.label,
				addX509CertCtrl.value);
		if (!checkBase64Encoding()) {
			alert("Key is not a base64 encoded string!");
			return;
		}

		scimFactory.addX509Certificate(addX509CertCtrl.user.id,
				addX509CertCtrl.label, false, addX509CertCtrl.value).then(
				function(response) {
					console.log("Added x509 Certificate: ",
							addX509CertCtrl.label, addX509CertCtrl.value);
					$uibModalInstance.close(response.data);
				}, function(error) {
					addX509CertCtrl.cancel();
					console.error('Error creating x509 certificate: ', error);
					$state.go("error", {
						"error" : error
					});
				});
	}

	function cancel() {
		$uibModalInstance.dismiss("cancel");
	}
}