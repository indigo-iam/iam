angular.module('dashboardApp').factory("Utils", Utils);

Utils.$inject = [];

function Utils() {
	
	var service = {
			s4: s4,
			uuid: uuid,
			isMe: isMe,
			isAdmin: isAdmin,
			isUser: isUser,
			getLoggedUser: getLoggedUser,
			isRegistrationEnabled: isRegistrationEnabled,
			buildErrorOperationResult: buildErrorOperationResult,
			buildSuccessOperationResult: buildSuccessOperationResult,
			buildGenericErrorOperationResult: buildGenericErrorOperationResult
		};

	return service;
	
	function s4() {
		return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
	}
	
	function uuid() {
		return this.s4() + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4()
			+ this.s4() + this.s4();
	}
	
	function isMe(id) {
		
		return (id == getUserInfo().sub);
	}
	
	function isAdmin() {
		
		return (getUserAuthorities().indexOf("ROLE_ADMIN") != -1);
	}
	
	function isUser() {
		
		return (getUserAuthorities().indexOf("ROLE_USER") != -1);
	}
	
	function getLoggedUser() {
		
		return { info: getUserInfo(), auth: getUserAuthorities(), isAdmin: isAdmin() };
	}

	function isRegistrationEnabled() {

		return getRegistrationEnabled();
	}

	function buildErrorOperationResult(error) {

		return { 
			type: "error",
			text: error.data.error_description || error.data.detail || error.data.message
		}
	}

	function buildGenericErrorOperationResult(message) {

		return { 
			type: "error",
			text: message
		}
	}

	function buildSuccessOperationResult(message) {

		return {
			type: "success",
			text: message
		}
	}
}