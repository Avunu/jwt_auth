# Copyright (c) 2026, Avunu LLC and Contributors
# See license.txt

import base64
import json
import random
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import MagicMock, patch

import frappe
import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from frappe.tests.classes import IntegrationTestCase
from frappe.utils import random_string
from jwt.algorithms import RSAAlgorithm

if TYPE_CHECKING:
	from frappe.core.doctype.user.user import User
	from frappe.utils.redis_wrapper import RedisWrapper

	from jwt_bearer_auth.jwt_auth.doctype.jwt_auth_settings.jwt_auth_settings import JWTAuthSettings


class TestJWTAuthUserRegistration(IntegrationTestCase):
	"""Test cases for JWT Auth user registration functionality."""

	@classmethod
	def tearDownClass(cls) -> None:  # frappe-vulture:ignore
		frappe.db.rollback()
		super().tearDownClass()

	def _get_jwt_auth_instance(self) -> Any:
		"""Get a JWTAuth instance for testing."""
		from jwt_bearer_auth.auth import JWTAuth

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
		user: User = cast("User", frappe.get_doc("User", test_email.lower()))
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

		# Create contact first. Contact.validate sets mobile_no from the primary mobile row in phone_nos,
		# so the number goes there rather than in the field itself.
		contact = self._create_test_contact(
			email=test_email,
			first_name="John",
			last_name="Doe",
			phone_nos=[{"phone": test_phone, "is_primary_mobile_no": 1}],
		)

		# Register user with existing contact
		jwt_auth.register_user(test_email)

		# Verify user was created with contact data
		self.assertTrue(frappe.db.exists("User", test_email.lower()))
		user: User = cast("User", frappe.get_doc("User", test_email.lower()))
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

		user: User = cast("User", frappe.get_doc("User", test_email.lower()))
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

	def test_register_user_handles_existing_user(self) -> None:
		"""Test that register_user gracefully handles when user already exists."""
		jwt_auth = self._get_jwt_auth_instance()
		test_email = f"test{random_string(8).lower()}@example.com"

		# Create a user first
		existing_user = frappe.get_doc(
			{
				"doctype": "User",
				"email": test_email,
				"first_name": "Existing",
				"last_name": "User",
				"user_type": "Website User",
			}
		)
		existing_user.insert(ignore_permissions=True)

		# Verify user exists
		self.assertTrue(frappe.db.exists("User", test_email))

		# Try to register the same user again - should not raise error
		jwt_auth.register_user(test_email)

		# Verify user still exists and was not duplicated
		self.assertTrue(frappe.db.exists("User", test_email))
		user: User = cast("User", frappe.get_doc("User", test_email))
		# Verify original user data is preserved
		self.assertEqual(user.first_name, "Existing")
		self.assertEqual(user.last_name, "User")

	def test_auth_handles_existing_user_without_contact(self) -> None:
		"""Test that auth() handles existing user without associated contact."""
		from jwt_bearer_auth.auth import JWTAuth

		test_email = f"test{random_string(8).lower()}@example.com"

		# Create a user without an associated contact
		existing_user = frappe.get_doc(
			{
				"doctype": "User",
				"email": test_email,
				"first_name": "John",
				"last_name": "Doe",
				"user_type": "Website User",
			}
		)
		existing_user.insert(ignore_permissions=True)

		# Mock the JWT auth flow
		jwt_auth = JWTAuth()
		jwt_auth.claims = {"email": test_email}
		jwt_auth.settings.enable_user_reg = True

		# Mock login_manager to track login calls
		mock_login_manager = MagicMock()
		frappe.local.login_manager = mock_login_manager

		# Call auth() - should not raise DuplicateEntryError
		jwt_auth.auth()

		# Verify login was called with the existing user
		mock_login_manager.login_as.assert_called_once_with(test_email)

		# Verify no duplicate user was created
		self.assertTrue(frappe.db.exists("User", test_email))


class TestJWTAuthURLGeneration(IntegrationTestCase):
	"""Test cases for JWT Auth URL generation."""

	@classmethod
	def tearDownClass(cls) -> None:  # frappe-vulture:ignore
		frappe.db.rollback()
		super().tearDownClass()

	def _get_jwt_auth_instance(self) -> Any:
		"""Get a JWTAuth instance for testing."""
		from jwt_bearer_auth.auth import JWTAuth

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


AUDIENCE = "test-audience-tag"
JWKS_URL = "https://idp.example.com/cdn-cgi/access/certs"
LOGIN_URL = "https://idp.example.com/login"
LOGOUT_URL = "https://idp.example.com/logout"
HEADER = "Cf-Access-Jwt-Assertion"


def _new_key() -> rsa.RSAPrivateKey:
	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(*keys: rsa.RSAPrivateKey) -> dict[str, Any]:
	return {"keys": [json.loads(RSAAlgorithm.to_jwk(key.public_key())) for key in keys]}


def _token(key: rsa.RSAPrivateKey, **claims: Any) -> str:
	now = datetime.now(UTC)
	payload: dict[str, Any] = {
		"aud": AUDIENCE,
		"email": "someone@example.com",
		"iat": now,
		"exp": now + timedelta(minutes=5),
	}
	payload.update(claims)
	return jwt.encode(payload, key, algorithm="RS256")


def _unsigned_token(payload: dict[str, Any]) -> str:
	"""An `alg: none` token: a well-formed JWT with no signature."""

	def b64(data: dict[str, Any]) -> str:
		return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

	return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(payload)}."


def _cache() -> RedisWrapper:
	cache = frappe.cache
	assert cache is not None
	return cache


def _jwks_response(jwks: dict[str, Any]) -> MagicMock:
	response = MagicMock()
	response.json.return_value = jwks
	response.raise_for_status.return_value = None
	return response


def _settings(**values: Any) -> JWTAuthSettings:
	"""A fresh, unsaved JWT Auth Settings, so a test never touches the cached single."""
	settings = cast("JWTAuthSettings", frappe.get_doc("JWT Auth Settings"))
	settings.update(
		{
			"enabled": 1,
			"enable_user_reg": 0,
			"enable_login": 0,
			"jwt_header": HEADER,
			"jwks_url": JWKS_URL,
			"jwt_private_secret": AUDIENCE,
			"login_url": LOGIN_URL,
			"logout_url": LOGOUT_URL,
			"redirect_param": "redirect_url",
		}
	)
	settings.update(values)
	return settings


def _request(path: str = "/app", token: str | None = None, in_cookie: bool = False) -> MagicMock:
	request = MagicMock()
	request.path = path
	request.url = f"https://site.example.com{path}"
	request.args = {}
	carrier = {HEADER: token} if token else {}
	request.cookies = carrier if in_cookie else {}
	request.headers = {} if in_cookie else carrier
	return request


class JWTAuthTestCase(IntegrationTestCase):
	"""Installs a JWTAuth on frappe.local with test settings, and puts frappe.local back afterwards."""

	def setUp(self) -> None:
		super().setUp()
		from jwt_bearer_auth.auth import JWTAuth

		self.key = _new_key()
		self.auth = JWTAuth()
		self.auth.settings = _settings()
		self._saved_session = frappe.local.session
		self._saved_login_manager = getattr(frappe.local, "login_manager", None)
		self.login_manager = MagicMock()
		frappe.local.login_manager = self.login_manager
		frappe.local.jwt_auth = self.auth
		frappe.local.request = _request()
		self.jwks = patch("jwt_bearer_auth.auth.requests.get", return_value=_jwks_response(_jwks(self.key)))
		self.requests_get = self.jwks.start()

	def tearDown(self) -> None:
		self.jwks.stop()
		frappe.local.session = self._saved_session
		frappe.local.login_manager = self._saved_login_manager
		frappe.flags.pop("jwt_logout_redirect", None)
		frappe.local.flags.commit = False
		for attr in ("jwt_auth", "request"):
			if hasattr(frappe.local, attr):
				delattr(frappe.local, attr)
		frappe.db.rollback()
		super().tearDown()

	def as_guest(self) -> None:
		frappe.local.session = frappe._dict(user="Guest", data=frappe._dict())


class TestTokenValidation(JWTAuthTestCase):
	"""is_valid_token: signature, expiry, audience, unknown keys and the missing-secret case."""

	def test_valid_token_is_accepted_and_sets_claims(self) -> None:
		token = _token(self.key, email="valid@example.com")
		self.assertTrue(self.auth.is_valid_token(token))
		self.assertEqual(self.auth.claims["email"], "valid@example.com")
		self.requests_get.assert_called_once()
		self.assertEqual(self.requests_get.call_args.args[0], JWKS_URL)
		self.assertIn("timeout", self.requests_get.call_args.kwargs)

	def test_expired_token_is_rejected(self) -> None:
		past = datetime.now(UTC) - timedelta(hours=1)
		token = _token(self.key, iat=past - timedelta(minutes=5), exp=past)
		self.assertFalse(self.auth.is_valid_token(token))
		self.assertEqual(self.auth.claims, {})

	def test_token_from_an_unknown_issuer_is_rejected(self) -> None:
		"""A token signed by a key that isn't in the provider's JWKS."""
		token = _token(_new_key())
		self.assertFalse(self.auth.is_valid_token(token))

	def test_token_for_another_audience_is_rejected(self) -> None:
		token = _token(self.key, aud="some-other-application")
		self.assertFalse(self.auth.is_valid_token(token))

	def test_missing_secret_rejects_every_token(self) -> None:
		self.auth.settings.jwt_private_secret = ""
		token = _token(self.key)
		self.assertFalse(self.auth.is_valid_token(token))
		self.requests_get.assert_not_called()

	def test_unsigned_token_is_rejected(self) -> None:
		token = _unsigned_token({"aud": AUDIENCE, "email": "x@example.com"})
		self.assertFalse(self.auth.is_valid_token(token))

	def test_garbage_token_is_rejected(self) -> None:
		self.assertFalse(self.auth.is_valid_token("not-a-jwt"))

	def test_matching_key_is_found_among_several(self) -> None:
		self.requests_get.return_value = _jwks_response(_jwks(_new_key(), self.key))
		self.assertTrue(self.auth.is_valid_token(_token(self.key)))

	def test_unreachable_jwks_rejects_the_token(self) -> None:
		self.requests_get.side_effect = requests.ConnectionError("down")
		self.assertFalse(self.auth.is_valid_token(_token(self.key)))

	def test_malformed_jwks_rejects_the_token(self) -> None:
		self.requests_get.return_value = _jwks_response({"not-keys": []})
		self.assertFalse(self.auth.is_valid_token(_token(self.key)))


class TestCanAuth(JWTAuthTestCase):
	"""can_auth / get_token: when a request is a candidate for JWT login."""

	def test_guest_with_valid_header_token(self) -> None:
		self.as_guest()
		frappe.local.request = _request(token=_token(self.key))
		self.assertTrue(self.auth.can_auth())

	def test_guest_with_valid_cookie_token(self) -> None:
		self.as_guest()
		frappe.local.request = _request(token=_token(self.key), in_cookie=True)
		self.assertTrue(self.auth.can_auth())

	def test_guest_without_token(self) -> None:
		self.as_guest()
		self.assertFalse(self.auth.can_auth())

	def test_logged_in_user_is_left_alone(self) -> None:
		frappe.local.session = frappe._dict(user="Administrator", data=frappe._dict())
		frappe.local.request = _request(token=_token(self.key))
		self.assertFalse(self.auth.can_auth())

	def test_disabled_settings(self) -> None:
		self.as_guest()
		self.auth.settings.enabled = 0
		frappe.local.request = _request(token=_token(self.key))
		self.assertFalse(self.auth.can_auth())

	def test_pending_redirect(self) -> None:
		self.as_guest()
		self.auth.redirect_to = "/update-profile/x/edit"
		self.assertFalse(self.auth.can_auth())

	def test_logout_in_progress(self) -> None:
		self.as_guest()
		frappe.flags["jwt_logout_redirect"] = LOGOUT_URL
		frappe.local.request = _request(token=_token(self.key))
		self.assertFalse(self.auth.can_auth())


class TestAuthHook(JWTAuthTestCase):
	"""The auth_hooks entry point and the login or registration it leads to."""

	def test_validate_auth_logs_in_an_existing_user(self) -> None:
		from jwt_bearer_auth.auth import validate_auth

		email = f"jwt{random_string(8).lower()}@example.com"
		frappe.get_doc(
			{"doctype": "User", "email": email, "first_name": "Jay", "user_type": "Website User"}
		).insert(ignore_permissions=True)
		self.as_guest()
		frappe.local.request = _request(token=_token(self.key, email=email))

		validate_auth()

		self.login_manager.login_as.assert_called_once_with(email)

	def test_validate_auth_ignores_an_invalid_token(self) -> None:
		from jwt_bearer_auth.auth import validate_auth

		self.as_guest()
		frappe.local.request = _request(token=_token(_new_key()))

		validate_auth()

		self.login_manager.login_as.assert_not_called()

	def test_token_without_email_logs_nobody_in(self) -> None:
		self.auth.claims = {"sub": "no-email"}
		self.auth.auth()
		self.login_manager.login_as.assert_not_called()

	def test_contact_linked_user_is_logged_in(self) -> None:
		"""An email known only as a Contact's secondary address logs in that Contact's user."""
		user_email = f"jwt{random_string(8).lower()}@example.com"
		alias = f"alias{random_string(8).lower()}@example.com"
		frappe.get_doc(
			{"doctype": "User", "email": user_email, "first_name": "Kay", "user_type": "Website User"}
		).insert(ignore_permissions=True)
		contact = frappe.get_doc({"doctype": "Contact", "first_name": "Kay", "user": user_email})
		contact.append("email_ids", {"email_id": alias, "is_primary": 1})
		contact.insert(ignore_permissions=True)
		self.auth.claims = {"email": alias}

		self.auth.auth()

		self.login_manager.login_as.assert_called_once_with(user_email)

	def test_unknown_email_without_registration_logs_nobody_in(self) -> None:
		self.auth.claims = {"email": f"nobody{random_string(8).lower()}@example.com"}
		self.auth.auth()
		self.login_manager.login_as.assert_not_called()

	def test_unknown_email_with_registration_registers_and_logs_in(self) -> None:
		email = f"new{random_string(8).lower()}@example.com"
		self.auth.settings.enable_user_reg = 1
		self.auth.claims = {"email": email}
		frappe.local.request = _request(path="/orders")
		frappe.local.session = frappe._dict(user="Guest", data=frappe._dict())

		self.auth.auth()

		self.assertTrue(frappe.db.exists("User", email))
		self.login_manager.login_as.assert_called_once_with(email)
		self.assertTrue(frappe.local.flags.commit)
		self.assertEqual(frappe.session.data["jwt_auth_redirect"], f"/update-profile/{email}/edit")
		cache_key = f"jwt_original_location_{email}"
		self.assertEqual(_cache().get_value(cache_key), "/orders")
		_cache().delete_value(cache_key)


class TestURLs(JWTAuthTestCase):
	def test_login_url_carries_the_redirect(self) -> None:
		self.assertEqual(self.auth.get_login_url("app/todo"), f"{LOGIN_URL}?redirect_url=%2Fapp%2Ftodo")

	def test_login_url_takes_a_redirect_with_a_leading_slash(self) -> None:
		# Frappe's redirect-to starts with "/"; the target must not become "//app/todo".
		self.assertEqual(self.auth.get_login_url("/app/todo"), f"{LOGIN_URL}?redirect_url=%2Fapp%2Ftodo")

	def test_login_url_falls_back_to_the_current_path(self) -> None:
		self.auth.update("orders", None)
		self.assertEqual(self.auth.get_login_url(), f"{LOGIN_URL}?redirect_url=%2Forders")

	def test_login_url_appends_to_an_existing_query(self) -> None:
		self.auth.settings.login_url = f"{LOGIN_URL}?team=x"
		self.assertEqual(self.auth.get_login_url("a"), f"{LOGIN_URL}?team=x&redirect_url=%2Fa")

	def test_login_url_without_redirect_param(self) -> None:
		self.auth.settings.redirect_param = None
		self.assertEqual(self.auth.get_login_url("a"), LOGIN_URL)

	def test_logout_url_carries_the_current_url(self) -> None:
		frappe.local.request = _request(path="/app")
		self.assertEqual(
			self.auth.get_logout_url(), f"{LOGOUT_URL}?redirect_url=https://site.example.com/app"
		)


class TestLogout(JWTAuthTestCase):
	"""The whitelisted logout endpoints and the on_logout hook."""

	def test_jwt_logout_returns_the_provider_logout_url(self) -> None:
		from jwt_bearer_auth.auth import jwt_logout

		result = jwt_logout()

		self.login_manager.logout.assert_called_once()
		self.assertTrue(result["redirect_url"].startswith(LOGOUT_URL))

	def test_jwt_logout_when_disabled_returns_login(self) -> None:
		from jwt_bearer_auth.auth import jwt_logout

		self.auth.settings.enabled = 0
		self.assertEqual(jwt_logout(), {"redirect_url": "/login"})

	def test_web_logout_redirects_to_the_provider(self) -> None:
		from jwt_bearer_auth.auth import web_logout

		web_logout()

		self.login_manager.logout.assert_called_once()
		self.assertEqual(frappe.local.response["type"], "redirect")
		self.assertTrue(frappe.local.response["location"].startswith(LOGOUT_URL))

	def test_web_logout_when_disabled_redirects_to_login(self) -> None:
		from jwt_bearer_auth.auth import web_logout

		self.auth.settings.enabled = 0
		web_logout()
		self.assertEqual(frappe.local.response["location"], "/login")

	def test_on_logout_flags_the_provider_logout(self) -> None:
		from jwt_bearer_auth.auth import on_logout

		on_logout()

		self.assertTrue(frappe.flags["jwt_logout_redirect"].startswith(LOGOUT_URL))


class TestHandleRedirects(JWTAuthTestCase):
	"""The after_request hook."""

	def _response(self) -> MagicMock:
		response = MagicMock()
		response.status_code = 200
		response.headers = {}
		return response

	def test_no_response(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		handle_redirects(None, _request())

	def test_logout_redirect_for_guest(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		self.as_guest()
		frappe.flags["jwt_logout_redirect"] = LOGOUT_URL
		response = self._response()

		handle_redirects(response, _request())

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.headers["Location"], LOGOUT_URL)
		self.assertNotIn("jwt_logout_redirect", frappe.flags)

	def test_post_registration_redirect(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		frappe.local.session = frappe._dict(
			user="new@example.com", data=frappe._dict(jwt_auth_redirect="/update-profile/x/edit")
		)
		response = self._response()

		handle_redirects(response, _request())

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.headers["Location"], "/update-profile/x/edit")
		self.assertNotIn("jwt_auth_redirect", frappe.session.data)

	def test_me_returns_to_the_original_location(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		user = f"back{random_string(8).lower()}@example.com"
		frappe.local.session = frappe._dict(user=user, data=frappe._dict())
		_cache().set_value(f"jwt_original_location_{user}", "/orders")
		response = self._response()

		handle_redirects(response, _request(path="/me"))

		self.assertEqual(response.headers["Location"], "/orders")
		self.assertIsNone(_cache().get_value(f"jwt_original_location_{user}"))

	def test_plain_request_is_untouched(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		frappe.local.session = frappe._dict(user="Administrator", data=frappe._dict())
		response = self._response()

		handle_redirects(response, _request(path="/app"))

		self.assertEqual(response.status_code, 200)
		self.assertNotIn("Location", response.headers)

	def test_session_without_data(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		frappe.local.session = frappe._dict(user="Administrator", data=None)
		response = self._response()

		handle_redirects(response, _request())

		self.assertEqual(response.status_code, 200)

	def _login_request(self, redirect_to: str | None = None) -> MagicMock:
		request = _request(path="/login")
		request.args = {"redirect-to": redirect_to} if redirect_to else {}
		return request

	def test_login_override_sends_a_guest_to_the_provider(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		self.auth.settings.enable_login = 1
		self.as_guest()
		response = self._response()

		handle_redirects(response, self._login_request("/app/todo"))

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.headers["Location"], f"{LOGIN_URL}?redirect_url=%2Fapp%2Ftodo")

	def test_login_override_without_redirect_to(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		self.auth.settings.enable_login = 1
		self.as_guest()
		response = self._response()

		handle_redirects(response, self._login_request())

		self.assertEqual(response.headers["Location"], f"{LOGIN_URL}?redirect_url=%2F")

	def test_login_page_is_left_alone_when_the_override_is_off(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		self.as_guest()
		response = self._response()

		handle_redirects(response, self._login_request("/app"))

		self.assertEqual(response.status_code, 200)
		self.assertNotIn("Location", response.headers)

	def test_login_override_leaves_a_logged_in_user_alone(self) -> None:
		from jwt_bearer_auth.auth import handle_redirects

		self.auth.settings.enable_login = 1
		frappe.local.session = frappe._dict(user="Administrator", data=frappe._dict())
		response = self._response()

		handle_redirects(response, self._login_request("/app"))

		self.assertEqual(response.status_code, 200)
		self.assertNotIn("Location", response.headers)
