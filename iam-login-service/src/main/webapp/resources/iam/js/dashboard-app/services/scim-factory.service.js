angular.module('dashboardApp').factory("scimFactory", [ '$http', '$httpParamSerializer', function($http, $httpParamSerializer) {

	var urlBase = '/scim';
	var urlUsers = urlBase + '/Users';
	var urlGroups = urlBase + '/Groups';
	
	var scimFactory = {};

	scimFactory.getUsers = function(startIndex, count) {
		
		console.info("Getting users from-to: ", startIndex, count);
		var qs = $httpParamSerializer({
			'startIndex': startIndex,
			'count': count
		});
		var url = urlUsers + '?' + qs;
		
		return $http.get(url);
	};

	scimFactory.getGroups = function(startIndex, count) {
		
		console.info("Getting groups from-to: ", startIndex, count);
		var qs = $httpParamSerializer({
			'startIndex': startIndex,
			'count': count
		});
		var url = urlGroups + '?' + qs;
		
		return $http.get(url);
	};

	scimFactory.getUser = function(userId) {
		
		console.info("Getting user: ", userId);
		var url = urlUsers + '/' + userId;
		
		return $http.get(url);
	};

	scimFactory.getGroup = function(groupId) {
		
		console.info("Getting group: ", groupId);
		var url = urlGroups + '/' + groupId;
		
		return $http.get(url);
	};

	scimFactory.getMe = function() {
		
		console.info("Getting Me endpoint");
		var url = urlBase + '/Me';

		return $http.get(url);
	};

	scimFactory.createGroup = function(group) {

		console.info("Creating group: ", group);
		var config = {
			headers : {
				'Accept' : 'application/scim+json',
				'Content-Type' : 'application/scim+json'
			}
		}

		return $http.post(urlGroups, group, config);
	};
	
	scimFactory.deleteGroup = function(groupId) {
		
		console.info("Deleting group: ", groupId);
		var url = urlGroups + '/' + groupId;

		return $http.delete(url);
	};
	
	scimFactory.addUserToGroup = function(groupId, userId) {
		
		console.info("Patch groupId, add user ", groupId, userId);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};

		var data = {
			
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					path: "members",
					value: [{
//						display: user.name,
						value: userId,
//						$ref: user.indigoUserInfo.meta.location
					}]
				}]
		};
		
		var url = urlGroups + '/' + groupId;

		return $http.patch(url, data, config);
	};

	scimFactory.removeUserFromGroup = function(groupId, userId, userLocation, userDisplayName) {
		
		console.info("Patch groupId, remove user", groupId, userId, userLocation);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					path: "members",
					value: [{
						display: userDisplayName,
						value: userId,
						$ref: userLocation
					}]
				}]
		};
		var url = urlGroups + '/' + groupId;

		return $http.patch(url, data, config);
	};

	scimFactory.addOpenIDAccount = function(userId, issuer, subject) {
		
		console.info("Patch user-id, add oidc account ", userId, issuer, subject);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
			
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							oidcIds: [{
								"issuer": issuer,
								"subject": subject
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	scimFactory.removeOpenIDAccount = function(userId, issuer, subject) {
		
		console.info("Patch user-id, remove oidc account ", userId, issuer, subject);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
			
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							oidcIds: [{
								"issuer": issuer,
								"subject": subject
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;

		return $http.patch(url, data, config);
	};

	scimFactory.addSshKey = function(userId, label, isPrimary, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, label, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							sshKeys: [{
								"display": label,
								"primary": isPrimary,
								"value": value
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};

	scimFactory.removeSshKey = function(userId, fingerprint) {
		
		console.info("Patch user-id, remove ssh-key ", userId, fingerprint);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							sshKeys: [{
								"fingerprint": fingerprint
								}
							]
						}
					}
				}]
		};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	scimFactory.addX509Certificate = function(userId, label, isPrimary, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, label, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						x509Certificates: [{
								"display": label,
								"primary": isPrimary,
								"value": value
							}]
						}
					}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	scimFactory.removeX509Certificate = function(userId, value) {
		
		console.info("Patch user-id, add ssh-key ", userId, value);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						x509Certificates: [{
								"value": value
							}]
						}
					}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	scimFactory.addSamlId = function(userId, samlIdpId, samlUserId) {
		
		console.info("Patch user-id, add saml-account ", userId, samlIdpId, samlUserId);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "add",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							samlIds: [{
								"idpId": samlIdpId,
								"userId": samlUserId
								}
							]
						}
					}
				}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	scimFactory.removeSamlId = function(userId, samlId) {
		
		console.info("Patch user-id, remove saml-account ", userId, samlId.idpId, samlId.userId);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "remove",
					value: {
						"urn:indigo-dc:scim:schemas:IndigoUser": {
							samlIds: [{
								"idpId": samlId.idpId,
								"userId": samlId.userId
								}
							]
						}
					}
				}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	};
	
	scimFactory.setUserActiveStatus = function(userId, status) {
		
		console.info("Patch user-id, set active to ", userId, status);
		
		var config = {
				headers: { 'Content-Type': 'application/scim+json' }
			};
		var data = {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				operations: [{
					op: "replace",
					value: {
						active: status
					}
				}]
			};
		var url = urlUsers + '/' + userId;
		
		return $http.patch(url, data, config);
	}
	return scimFactory;
} ]);
