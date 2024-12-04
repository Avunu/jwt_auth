app_name = "jwt_auth"
app_title = "JWT Auth"
app_publisher = "Avunu LLC"
app_description = "JWT Auth"
app_email = "kevin@avu.nu"
app_license = "mit"
auth_hooks = ["jwt_auth.auth.validate_auth"]
page_renderer = ["jwt_auth.auth.SessionJWTAuth"]

app_include_js = [
	"app.bundle.js"
]