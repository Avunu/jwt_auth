# Copyright (c) 2026, Avunu LLC and Contributors
# See license.txt

import random
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.classes import IntegrationTestCase
from frappe.utils import random_string

if TYPE_CHECKING:
	from frappe.core.doctype.user.user import User


class TestJWTAuthUserRegistration(IntegrationTestCase):
	"""Test cases for JWT Auth user registration functionality."""

	def _get_jwt_auth_instance(self) -> Any:
		"""Get a JWTAuth instance for testing."""
		from jwt_auth.auth import JWTAuth

		return JWTAuth()

	def _create_test_contact(self, email: str, **kwargs: Any) -> Any:
		"""Helper to create a test contact with an email."""
		defaults = {
			"doctype": "Contact",
			"first_name": f"Test{random_string(6)}",
			"last_name": "Contact",
		}
		defaults.update(kwargs)
		contact = frappe.get_doc(defaults)
		contact.append("email_ids", {"email_id": email, "is_primary": 1})
		contact.insert(ignore_permissions=True)
		return contact

	def test_register_user_creates_user_without_contact(self) -> None:
		"""Test that register_user creates a new User when no Contact exists."""
		jwt_auth = self._get_jwt_auth_instance()
		# Use lowercase email to match Frappe's normalization
		test_email = f"test{random_string(8).lower()}@example.com"

		# Register user without existing contact
		jwt_auth.register_user(test_email)

		# Verify user was created (Frappe lowercases emails)
		self.assertTrue(frappe.db.exists("User", test_email.lower()))

		# Verify user properties
		user: User = frappe.get_doc("User", test_email.lower())  # type: ignore[assignment]
		self.assertEqual(user.email.lower(), test_email.lower())
		self.assertEqual(user.first_name, "[Change Me]")
		self.assertEqual(user.user_type, "Website User")

		# Verify redirect is set for profile completion
		self.assertIsNotNone(jwt_auth.redirect_to)
		self.assertIn("update-profile", jwt_auth.redirect_to)

	def test_register_user_uses_existing_contact_data(self) -> None:
		"""Test that register_user populates User from existing Contact."""
		jwt_auth = self._get_jwt_auth_instance()
		test_email = f"test{random_string(8).lower()}@example.com"
		# Use unique phone number to avoid conflicts with existing test data
		test_phone = f"+1202555{random.randint(1000, 9999)}"

		# Create contact first
		contact = self._create_test_contact(
			email=test_email,
			first_name="John",
			last_name="Doe",
			mobile_no=test_phone,
		)

		# Register user with existing contact
		jwt_auth.register_user(test_email)

		# Verify user was created with contact data
		self.assertTrue(frappe.db.exists("User", test_email.lower()))
		user: User = frappe.get_doc("User", test_email.lower())  # type: ignore[assignment]
		self.assertEqual(user.first_name, "John")
		self.assertEqual(user.last_name, "Doe")
		self.assertEqual(user.mobile_no, test_phone)

		# Verify contact is linked to user
		contact.reload()
		self.assertEqual(contact.user.lower(), test_email.lower())

		# Verify no redirect when contact has first_name
		self.assertIsNone(jwt_auth.redirect_to)

	def test_register_user_sets_redirect_when_contact_missing_name(self) -> None:
		"""Test that redirect is set when Contact lacks first_name."""
		jwt_auth = self._get_jwt_auth_instance()
		test_email = f"test{random_string(8).lower()}@example.com"

		# Create contact without first_name (use a placeholder that will be treated as empty)
		contact = frappe.get_doc(
			{
				"doctype": "Contact",
				"first_name": "",  # Empty first name
				"last_name": "Doe",
			}
		)
		contact.append("email_ids", {"email_id": test_email, "is_primary": 1})
		contact.insert(ignore_permissions=True)

		# Register user
		jwt_auth.register_user(test_email)

		# Verify redirect is set for profile completion
		self.assertIsNotNone(jwt_auth.redirect_to)
		self.assertIn("update-profile", jwt_auth.redirect_to)

	def test_register_user_creates_website_user_type(self) -> None:
		"""Test that new users are created as Website Users."""
		jwt_auth = self._get_jwt_auth_instance()
		test_email = f"test{random_string(8).lower()}@example.com"

		jwt_auth.register_user(test_email)

		user: User = frappe.get_doc("User", test_email.lower())  # type: ignore[assignment]
		self.assertEqual(user.user_type, "Website User")

	def test_register_user_does_not_send_welcome_email(self) -> None:
		"""Test that welcome email is not sent during JWT registration."""
		jwt_auth = self._get_jwt_auth_instance()
		test_email = f"test{random_string(8).lower()}@example.com"

		# Mock sendmail to track calls
		with patch.object(frappe, "sendmail", MagicMock()) as mock_sendmail:
			jwt_auth.register_user(test_email)
			# Verify sendmail was not called
			mock_sendmail.assert_not_called()


class TestJWTAuthURLGeneration(IntegrationTestCase):
	"""Test cases for JWT Auth URL generation."""

	def _get_jwt_auth_instance(self) -> Any:
		"""Get a JWTAuth instance for testing."""
		from jwt_auth.auth import JWTAuth

		auth = JWTAuth()
		auth.path = "/test-page"
		return auth

	def test_get_login_url_basic(self) -> None:
		"""Test basic login URL generation."""
		jwt_auth = self._get_jwt_auth_instance()

		# Only test if login_url is configured
		if jwt_auth.settings.login_url:
			login_url = jwt_auth.get_login_url()
			self.assertIsInstance(login_url, str)
			self.assertTrue(len(login_url) > 0)

	def test_get_logout_url_basic(self) -> None:
		"""Test basic logout URL generation."""
		jwt_auth = self._get_jwt_auth_instance()

		# Only test if logout_url is configured
		if jwt_auth.settings.logout_url:
			# Create a mock request since it doesn't exist in test context
			mock_request = MagicMock()
			mock_request.url = "https://example.com/current-page"

			# Set the request attribute directly on frappe.local
			frappe.local.request = mock_request
			try:
				logout_url = jwt_auth.get_logout_url()
				self.assertIsInstance(logout_url, str)
				self.assertTrue(len(logout_url) > 0)
			finally:
				# Clean up
				del frappe.local.request
