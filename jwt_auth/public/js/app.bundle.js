// Copyright (c) 2026, Avunu LLC and contributors
// For license information, please see license.txt

document.addEventListener("DOMContentLoaded", () => {
	// Wait for frappe to be initialized
	const onFrappeApplication = () => {
		if (window.frappe?.app) {
			// Override the logout function
			frappe.app.logout = function () {
				var me = this;
				me.logged_out = true;

				return frappe.call({
					method: "jwt_auth.auth.jwt_logout",
					callback: function (r) {
						if (r.exc) {
							return;
						}
						if (r.message.redirect_url) {
							window.location.href = r.message.redirect_url;
						} else {
							me.redirect_to_login();
						}
					},
				});
			};
		} else {
			// Check again in a moment if frappe isn't ready
			setTimeout(onFrappeApplication, 100);
		}
	};

	onFrappeApplication();
});
