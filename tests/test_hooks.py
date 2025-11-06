# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

from unittest.mock import Mock, patch, MagicMock

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from jwt_auth.jwt_auth.hooks.contact import on_update
from jwt_auth.jwt_auth.hooks.error_page import JWTAuthErrorPage


class TestContactHooksUnit(UnitTestCase):
	"""Unit tests for contact hooks."""

	def test_on_update_rename_contact_with_change_me(self):
		"""Test contact rename when name contains '[Change Me]'."""
		mock_doc = Mock()
		mock_doc.name = 'Contact [Change Me]'
		mock_doc.get.return_value = 'John Doe'
		mock_doc.full_name = 'John Doe'
		
		with patch('jwt_auth.jwt_auth.hooks.contact.frappe.enqueue') as mock_enqueue:
			on_update(mock_doc, 'on_update')
			
			mock_enqueue.assert_called_once_with(
				"frappe.model.rename_doc.rename_doc",
				doctype=mock_doc.get("doctype"),
				old=mock_doc.get("name"),
				new=mock_doc.get("full_name"),
				force=False,
				show_alert=True,
			)

	def test_on_update_no_rename_without_change_me(self):
		"""Test that contact is not renamed when name doesn't contain '[Change Me]'."""
		mock_doc = Mock()
		mock_doc.name = 'Normal Contact Name'
		mock_doc.get.return_value = 'John Doe'
		
		with patch('jwt_auth.jwt_auth.hooks.contact.frappe.enqueue') as mock_enqueue:
			on_update(mock_doc, 'on_update')
			
			mock_enqueue.assert_not_called()

	def test_on_update_no_rename_without_full_name(self):
		"""Test that contact is not renamed when full_name is not provided."""
		mock_doc = Mock()
		mock_doc.name = 'Contact [Change Me]'
		mock_doc.get.return_value = None
		
		with patch('jwt_auth.jwt_auth.hooks.contact.frappe.enqueue') as mock_enqueue:
			on_update(mock_doc, 'on_update')
			
			mock_enqueue.assert_not_called()

	def test_on_update_user_fields_update(self):
		"""Test user fields update when contact has a linked user."""
		mock_doc = Mock()
		mock_doc.name = 'Test Contact'
		mock_doc.get.side_effect = lambda field, default=None: {
			'user': 'test@example.com',
			'first_name': 'John',
			'middle_name': 'Michael',
			'last_name': 'Doe',
			'full_name': 'John Michael Doe',
			'phone': '123-456-7890',
			'mobile_no': '987-654-3210',
			'gender': 'Male',
			'full_name': None  # For the first call in rename logic
		}.get(field, default)
		
		mock_doc.has_value_changed.side_effect = lambda field: field in ['first_name', 'phone']
		
		mock_user = Mock()
		
		with patch('jwt_auth.jwt_auth.hooks.contact.User') as mock_user_class:
			mock_user_class.return_value = mock_user
			
			on_update(mock_doc, 'on_update')
			
			# Verify User was instantiated correctly
			mock_user_class.assert_called_once_with("User", "test@example.com")
			
			# Verify only changed fields were updated
			expected_update_fields = {
				'first_name': 'John',
				'phone': '123-456-7890'
			}
			mock_user.update.assert_called_once_with(expected_update_fields)
			mock_user.save.assert_called_once_with(ignore_permissions=True)

	def test_on_update_no_user_fields_update_when_no_user(self):
		"""Test that user fields are not updated when contact has no linked user."""
		mock_doc = Mock()
		mock_doc.name = 'Test Contact'
		mock_doc.get.side_effect = lambda field, default=None: {
			'user': False,
			'full_name': None  # For the rename logic
		}.get(field, default)
		
		with patch('jwt_auth.jwt_auth.hooks.contact.User') as mock_user_class:
			on_update(mock_doc, 'on_update')
			
			mock_user_class.assert_not_called()

	def test_on_update_no_user_fields_update_when_no_changes(self):
		"""Test that user fields are not updated when no fields have changed."""
		mock_doc = Mock()
		mock_doc.name = 'Test Contact'
		mock_doc.get.side_effect = lambda field, default=None: {
			'user': 'test@example.com',
			'first_name': 'John',
			'last_name': 'Doe',
			'full_name': None  # For the rename logic
		}.get(field, default)
		
		# No fields have changed
		mock_doc.has_value_changed.return_value = False
		
		with patch('jwt_auth.jwt_auth.hooks.contact.User') as mock_user_class:
			on_update(mock_doc, 'on_update')
			
			mock_user_class.assert_not_called()

	def test_on_update_user_fields_filter_none_values(self):
		"""Test that None values are filtered out from user updates."""
		mock_doc = Mock()
		mock_doc.name = 'Test Contact'
		mock_doc.get.side_effect = lambda field, default=None: {
			'user': 'test@example.com',
			'first_name': 'John',
			'middle_name': None,  # This should be filtered out
			'last_name': 'Doe',
			'phone': None,  # This should be filtered out
			'full_name': None  # For the rename logic
		}.get(field, default)
		
		# Mock that first_name and last_name changed, but middle_name and phone are None
		mock_doc.has_value_changed.side_effect = lambda field: field in ['first_name', 'middle_name', 'last_name', 'phone']
		
		mock_user = Mock()
		
		with patch('jwt_auth.jwt_auth.hooks.contact.User') as mock_user_class:
			mock_user_class.return_value = mock_user
			
			on_update(mock_doc, 'on_update')
			
			# Verify only non-None changed fields were updated
			expected_update_fields = {
				'first_name': 'John',
				'last_name': 'Doe'
			}
			mock_user.update.assert_called_once_with(expected_update_fields)


class TestErrorPageHooksUnit(UnitTestCase):
	"""Unit tests for error page hooks."""

	def test_jwt_auth_error_page_initialization(self):
		"""Test JWTAuthErrorPage initialization."""
		error_page = JWTAuthErrorPage(
			path='/test/path',
			http_status_code=500,
			exception=Exception('Test error'),
			title='Test Error',
			message='Test error message'
		)
		
		# Path should be overridden to jwt_auth_error
		self.assertEqual(error_page.path, 'jwt_auth_error')
		self.assertEqual(error_page.http_status_code, 500)
		self.assertEqual(error_page.title, 'Test Error')
		self.assertEqual(error_page.message, 'Test error message')

	def test_jwt_auth_error_page_initialization_minimal(self):
		"""Test JWTAuthErrorPage initialization with minimal parameters."""
		error_page = JWTAuthErrorPage()
		
		self.assertEqual(error_page.path, 'jwt_auth_error')
		self.assertIsNone(error_page.http_status_code)
		self.assertIsNone(error_page.exception)
		self.assertIsNone(error_page.title)
		self.assertIsNone(error_page.message)

	def test_can_render(self):
		"""Test can_render method always returns True."""
		error_page = JWTAuthErrorPage()
		self.assertTrue(error_page.can_render())

	def test_init_context_with_explicit_values(self):
		"""Test init_context with explicitly provided values."""
		error_page = JWTAuthErrorPage(
			http_status_code=404,
			title='Page Not Found',
			message='The requested page could not be found'
		)
		
		# Mock parent init_context
		with patch('jwt_auth.jwt_auth.hooks.error_page.ErrorPage.init_context') as mock_parent_init:
			error_page.context = Mock()
			error_page.init_context()
			
			mock_parent_init.assert_called_once()
			self.assertEqual(error_page.context.http_status_code, 404)
			self.assertEqual(error_page.context.title, 'Page Not Found')
			self.assertEqual(error_page.context.message, 'The requested page could not be found')

	def test_init_context_with_exception_values(self):
		"""Test init_context with values from exception."""
		mock_exception = Mock()
		mock_exception.http_status_code = 403
		mock_exception.title = 'Access Denied'
		mock_exception.message = 'You do not have permission to access this resource'
		
		error_page = JWTAuthErrorPage(exception=mock_exception)
		
		with patch('jwt_auth.jwt_auth.hooks.error_page.ErrorPage.init_context') as mock_parent_init:
			error_page.context = Mock()
			error_page.init_context()
			
			mock_parent_init.assert_called_once()
			self.assertEqual(error_page.context.http_status_code, 403)
			self.assertEqual(error_page.context.title, 'Access Denied')
			self.assertEqual(error_page.context.message, 'You do not have permission to access this resource')

	def test_init_context_fallback_to_defaults(self):
		"""Test init_context fallback to default values."""
		error_page = JWTAuthErrorPage()
		
		with patch('jwt_auth.jwt_auth.hooks.error_page.ErrorPage.init_context') as mock_parent_init:
			error_page.context = Mock()
			error_page.init_context()
			
			mock_parent_init.assert_called_once()
			self.assertEqual(error_page.context.http_status_code, 500)  # Default fallback
			self.assertIsNone(error_page.context.title)
			self.assertIsNone(error_page.context.message)

	def test_init_context_priority_explicit_over_exception(self):
		"""Test that explicit values take priority over exception values."""
		mock_exception = Mock()
		mock_exception.http_status_code = 403
		mock_exception.title = 'Exception Title'
		mock_exception.message = 'Exception Message'
		
		error_page = JWTAuthErrorPage(
			exception=mock_exception,
			http_status_code=500,  # This should override exception value
			title='Explicit Title',  # This should override exception value
			message='Explicit Message'  # This should override exception value
		)
		
		with patch('jwt_auth.jwt_auth.hooks.error_page.ErrorPage.init_context') as mock_parent_init:
			error_page.context = Mock()
			error_page.init_context()
			
			mock_parent_init.assert_called_once()
			self.assertEqual(error_page.context.http_status_code, 500)
			self.assertEqual(error_page.context.title, 'Explicit Title')
			self.assertEqual(error_page.context.message, 'Explicit Message')


class TestHooksIntegration(IntegrationTestCase):
	"""Integration tests for hooks functionality."""

	def setUp(self):
		"""Set up test environment."""
		# Create test user and contact
		self.test_email = 'test-contact-hook@example.com'
		
		# Clean up any existing test data
		self.cleanup_test_data()
		
		# Create test user
		self.test_user = frappe.get_doc({
			'doctype': 'User',
			'email': self.test_email,
			'first_name': 'Test',
			'last_name': 'User',
			'send_welcome_email': 0
		})
		self.test_user.insert(ignore_permissions=True)
		
		# Create test contact
		self.test_contact = frappe.get_doc({
			'doctype': 'Contact',
			'first_name': 'Test',
			'last_name': 'Contact',
			'full_name': 'Test Contact',
			'user': self.test_email
		})
		self.test_contact.insert(ignore_permissions=True)

	def test_contact_hook_integration(self):
		"""Test contact hook integration with real documents."""
		# Update contact fields
		self.test_contact.first_name = 'Updated'
		self.test_contact.phone = '555-1234'
		
		# Mock the has_value_changed method to simulate changes
		original_has_value_changed = self.test_contact.has_value_changed
		self.test_contact.has_value_changed = lambda field: field in ['first_name', 'phone']
		
		try:
			# Trigger the hook
			on_update(self.test_contact, 'on_update')
			
			# Reload user to check if changes were applied
			updated_user = frappe.get_doc('User', self.test_email)
			self.assertEqual(updated_user.first_name, 'Updated')
			self.assertEqual(updated_user.phone, '555-1234')
			
		finally:
			# Restore original method
			self.test_contact.has_value_changed = original_has_value_changed

	def test_contact_rename_integration(self):
		"""Test contact rename integration."""
		# Create a contact with '[Change Me]' in the name
		change_me_contact = frappe.get_doc({
			'doctype': 'Contact',
			'first_name': '[Change Me]',
			'last_name': 'User',
			'full_name': 'John Doe'
		})
		change_me_contact.insert(ignore_permissions=True)
		
		try:
			# Mock frappe.enqueue to capture the rename call
			with patch('jwt_auth.jwt_auth.hooks.contact.frappe.enqueue') as mock_enqueue:
				on_update(change_me_contact, 'on_update')
				
				# Verify enqueue was called with correct parameters
				mock_enqueue.assert_called_once()
				call_args = mock_enqueue.call_args
				self.assertEqual(call_args[0][0], "frappe.model.rename_doc.rename_doc")
				self.assertEqual(call_args[1]['old'], change_me_contact.name)
				self.assertEqual(call_args[1]['new'], 'John Doe')
				
		finally:
			# Clean up
			change_me_contact.delete(ignore_permissions=True)

	def cleanup_test_data(self):
		"""Clean up test data."""
		# Delete test contact if exists
		contacts = frappe.get_all('Contact', filters={'user': self.test_email})
		for contact in contacts:
			frappe.delete_doc('Contact', contact.name, ignore_permissions=True)
		
		# Delete test user if exists
		if frappe.db.exists('User', self.test_email):
			frappe.delete_doc('User', self.test_email, ignore_permissions=True)

	def tearDown(self):
		"""Clean up after tests."""
		self.cleanup_test_data()