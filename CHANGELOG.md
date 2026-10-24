# Changelog

## [16.0.0](https://github.com/Avunu/jwt_bearer_auth/compare/v0.0.1...v16.0.0) (2026-10-24)


### Features

* Add JWT Auth Settings doctype and middleware functions ([4d2ecda](https://github.com/Avunu/jwt_bearer_auth/commit/4d2ecdac4adbcba5ee33ef9113fa8d68d4458fb6))
* add login redirect handling in session JWT auth ([df32c2e](https://github.com/Avunu/jwt_bearer_auth/commit/df32c2e1f8493eed15c6a164ffd3374d85bb06b9))
* Add login URL and redirect parameter fields to JWT Auth Settings ([3985717](https://github.com/Avunu/jwt_bearer_auth/commit/398571725ce3b8b78cd423b649cbeb4f82b3f056))
* fix logout ([03bc09a](https://github.com/Avunu/jwt_bearer_auth/commit/03bc09a6f31685404befff9edd5c89d584d5d19f))
* frontend logout functionality ([154db1c](https://github.com/Avunu/jwt_bearer_auth/commit/154db1c48fbf4bf2bba4359238f0f26e693283ae))
* Initialize App ([5df4583](https://github.com/Avunu/jwt_bearer_auth/commit/5df4583fc3052f39eb4544a5c9e7ea4c45e628ab))
* lay groundwork for multiple providers ([1a687ca](https://github.com/Avunu/jwt_bearer_auth/commit/1a687cadb4798b5fe448d27144598d8bd044ef0c))
* match multiple email addresses to users ([37b0926](https://github.com/Avunu/jwt_bearer_auth/commit/37b09263329a35d8ffae77ee5e0dd1389c1c6847))
* typing hints ([2977ee1](https://github.com/Avunu/jwt_bearer_auth/commit/2977ee17777eed1111eb5eb9325e2c8d2720fce7))
* Update JWT Auth middleware and validation logic ([d4f21e6](https://github.com/Avunu/jwt_bearer_auth/commit/d4f21e6c4fe8421d2af2c8e20acada7a0569f8e5))
* update user name(s) w/ contact ([8ec6e1f](https://github.com/Avunu/jwt_bearer_auth/commit/8ec6e1fd7b04ef4a0aefa98e33960624f2746825))


### Bug Fixes

* add logging for PermissionError in JWTAuth render function ([c15c30d](https://github.com/Avunu/jwt_bearer_auth/commit/c15c30dcd0ad403d570abe78c8114df52505e827))
* add teardown rollback for user registration and URL generation tests ([08e87f7](https://github.com/Avunu/jwt_bearer_auth/commit/08e87f74b1bee0c854632b5a1f79d4b9e90c36a1))
* add type hinting for contact document in on_update function ([7e1e60c](https://github.com/Avunu/jwt_bearer_auth/commit/7e1e60cc84ba220736d78068edb37fc98b549be3))
* allow the PyJWT that frappe v16 requires and lock the workspace ([b0028cf](https://github.com/Avunu/jwt_bearer_auth/commit/b0028cfdaaeb0bfba66b9aee8ff6e06abfa13b93))
* **auth:** make Override Frappe Login redirect guests on /login. Sites with Override Frappe Login ticked (the default) will now send guests who open /login to the identity provider's Login URL; untick it to keep Frappe's login page. ([#24](https://github.com/Avunu/jwt_bearer_auth/issues/24)) ([18684e6](https://github.com/Avunu/jwt_bearer_auth/commit/18684e631bb5ec3aa609154315c405e02628a647))
* better login detection ([dded509](https://github.com/Avunu/jwt_bearer_auth/commit/dded509c549d1b23896912436fa331b22b86190b))
* cast contact document and set user_type for new users ([7c9b8c8](https://github.com/Avunu/jwt_bearer_auth/commit/7c9b8c8758306595e5b8c262345d39795a3f703c))
* contact update hook ([16031e6](https://github.com/Avunu/jwt_bearer_auth/commit/16031e6390c9cf39318495e31862849eee9bcaeb))
* don't rename contacts to [Change Me] ([3e6aebe](https://github.com/Avunu/jwt_bearer_auth/commit/3e6aebe7765d5d4ef76db2bdef9e41b550b22cad))
* existing user check ([7dc388c](https://github.com/Avunu/jwt_bearer_auth/commit/7dc388c4c45f020864aee93be182afadc00e391a))
* ignore_permissions on contact rename ([b7caadf](https://github.com/Avunu/jwt_bearer_auth/commit/b7caadf7c32caa3fe105f205e9913a688998e66b))
* improve contact renaming logic in on_update function ([3d527db](https://github.com/Avunu/jwt_bearer_auth/commit/3d527db241fa84db3b9643a3ca53f6af462d902f))
* improve user field updates in contact hook ([22ca02f](https://github.com/Avunu/jwt_bearer_auth/commit/22ca02f5e416dcb8890a279eed47c4b169285525))
* redirect handling ([5d90702](https://github.com/Avunu/jwt_bearer_auth/commit/5d9070251d465dd8a7eb3659448d4951709d4eb6))
* remove unnecessary import of random in user registration tests ([dea163e](https://github.com/Avunu/jwt_bearer_auth/commit/dea163e7ee3c9d14db451a06f609def71883f5f5))
* switch back to session object ([90350ee](https://github.com/Avunu/jwt_bearer_auth/commit/90350ee319347be522cf9701d2269c8dfd690cee))
* update session handling in JWTAuth to use local context ([7629823](https://github.com/Avunu/jwt_bearer_auth/commit/762982333cbafad2ec072eac03c9749853aa75ac))
* use lazy annotations to avoid contact creation crash ([3e7bc0a](https://github.com/Avunu/jwt_bearer_auth/commit/3e7bc0a0a625fe57a8dd89372d8f7056ff95f3e6))
* user by email checker ([bc3cae3](https://github.com/Avunu/jwt_bearer_auth/commit/bc3cae32c6797420b0d5dd40bd0a017277236f61))


### Performance Improvements

* only setup cache if needed ([9e38482](https://github.com/Avunu/jwt_bearer_auth/commit/9e38482d9d87ee603ff51b3c58788cb7f5185bb0))


### Reverts

* page render class ([21f801c](https://github.com/Avunu/jwt_bearer_auth/commit/21f801c696a232b4950b95ddbb8f820d2ffed44e))


### Continuous Integration

* adopt the shared CI gates ([1c7231d](https://github.com/Avunu/jwt_bearer_auth/commit/1c7231d0c7a54fa1896b46ef3fe041f7f912490a))
