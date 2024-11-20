# Copyright (c) 2024, Avunu LLC and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class JWTAuthSettings(Document):
	def validate(self):
		if self.enable_jwt_user_auth and not self.jwt_header:
			frappe.throw("Please set the JWT Header")
