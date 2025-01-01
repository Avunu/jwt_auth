import frappe

def on_update(doc, method):
	# update the user's name(s) if the contact's name is updated
	if not doc.user:
		return
	if doc.has_value_changed("first_name"):
		frappe.db.set_value("User", doc.user, "first_name", doc.first_name)
	if doc.has_value_changed("middle_name"):
		frappe.db.set_value("User", doc.user, "middle_name", doc.middle_name)
	if doc.has_value_changed("last_name"):
		frappe.db.set_value("User", doc.user, "last_name", doc.last_name)