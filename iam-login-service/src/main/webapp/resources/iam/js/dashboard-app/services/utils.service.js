angular.module('dashboardApp').factory("Utils",
	function() {
		return {
			s4 : function() {
				return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
			},
			uuid : function() {
				return this.s4() + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4() + '-' + this.s4()
					+ this.s4() + this.s4();
			},
			isMe: function(id) {
				
				var loggedUser = getUserInfo();
				return (id != loggedUser.sub);
			},
			isAdmin: function() {
				
				var loggedUserAuth = getUserAuthorities();
				return (loggedUserAuth.indexOf("ROLE_ADMIN") != -1);
			}
		}
	});