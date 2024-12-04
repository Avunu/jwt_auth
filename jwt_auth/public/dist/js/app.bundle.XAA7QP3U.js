(() => {
  // ../jwt_auth/jwt_auth/public/js/app.bundle.js
  document.addEventListener("DOMContentLoaded", () => {
    const onFrappeApplication = () => {
      var _a;
      if ((_a = window.frappe) == null ? void 0 : _a.app) {
        const originalLogout = frappe.app.logout;
        frappe.app.logout = function() {
          var me = this;
          me.logged_out = true;
          return frappe.call({
            method: "jwt_auth.auth.jwt_logout",
            callback: function(r) {
              if (r.exc) {
                return;
              }
              console.log(r.message);
              if (r.message.redirect_url) {
                window.location.href = r.message.redirect_url;
              } else {
                me.redirect_to_login();
              }
            }
          });
        };
      } else {
        setTimeout(onFrappeApplication, 100);
      }
    };
    onFrappeApplication();
  });
})();
//# sourceMappingURL=app.bundle.XAA7QP3U.js.map
