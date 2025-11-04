# Copyright (c) 2024, Avunu LLC and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class JWTAuthSettings(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		enable_login: DF.Check
		enable_user_reg: DF.Check
		enabled: DF.Check
		jwks_url: DF.Data
		jwt_header: DF.Data
		jwt_private_secret: DF.Password
		login_url: DF.Data
		logout_url: DF.Data
		redirect_param: DF.Data | None
	# end: auto-generated types

	pass
