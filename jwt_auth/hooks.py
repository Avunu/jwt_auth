app_name = "jwt_auth"
app_title = "JWT Auth"
app_publisher = "Avunu LLC"
app_description = "JWT Auth"
app_email = "kevin@avu.nu"
app_license = "mit"
before_request = ["jwt_auth.auth.before_request"]
page_renderer = ["jwt_auth.auth.SessionJWTAuth"]
