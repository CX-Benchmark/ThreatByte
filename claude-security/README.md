# Claude Security findings — threatbyte

Exported from Claude Security on 2026-10-27. 18 findings: 2 critical, 11 high, 5 medium, 0 low.

| # | Severity | CWE | Title | Primary location |
|---|---|---|---|---|
| 1 | critical | CWE-321 | [Hard-coded Flask SECRET_KEY lets anyone forge session cookies for any account](findings/001-critical-hard-coded-flask-secret-key-lets-anyone-forge-session-cookie.md) | `server/config.py:7` |
| 2 | critical | CWE-307 | [Web /login has no brute-force protection, lockout or rate limiting](findings/002-critical-web-login-has-no-brute-force-protection-lockout-or-rate-limi.md) | `server/routes.py:36` |
| 3 | high | CWE-250 | [Docker image runs Flask as root, so /upload traversal can overwrite application code](findings/003-high-docker-image-runs-flask-as-root-so-upload-traversal-can-over.md) | `Dockerfile:1` |
| 4 | high | CWE-916 | [Passwords stored and verified as unsalted, fast MD5 digests](findings/004-high-passwords-stored-and-verified-as-unsalted-fast-md5-digests.md) | `server/routes.py:392` |
| 5 | high | CWE-22 | [Path traversal in /upload filename allows arbitrary file write and RCE](findings/005-high-path-traversal-in-upload-filename-allows-arbitrary-file-writ.md) | `server/routes.py:262` |
| 6 | high | CWE-79 | [Reflected XSS: dashboard search query rendered with \|safe into an input attribute](findings/006-high-reflected-xss-dashboard-search-query-rendered-with-safe-into.md) | `client/templates/dashboard.html:64` |
| 7 | high | CWE-1004 | [Session cookie served without HttpOnly, so page XSS exfiltrates the login session](findings/007-high-session-cookie-served-without-httponly-so-page-xss-exfiltrat.md) | `server/config.py:6` |
| 8 | high | CWE-639 | [Shared upload namespace lets any user overwrite, delete or read other users' files](findings/008-high-shared-upload-namespace-lets-any-user-overwrite-delete-or-re.md) | `server/routes.py:262` |
| 9 | high | CWE-489 | [Shipped DEBUG=True runs Werkzeug debugger and reloader under run.py](findings/009-high-shipped-debug-true-runs-werkzeug-debugger-and-reloader-under.md) | `server/config.py:5` |
| 10 | high | CWE-89 | [SQL injection in dashboard file search via f-string built LIKE query](findings/010-high-sql-injection-in-dashboard-file-search-via-f-string-built-li.md) | `server/routes.py:137` |
| 11 | high | CWE-79 | [Stored XSS via user country rendered with \|safe on the profile page](findings/011-high-stored-xss-via-user-country-rendered-with-safe-on-the-profil.md) | `client/templates/profile.html:41` |
| 12 | high | CWE-862 | [Unauthenticated deletion of any user via /api/v1/delete-user/<user_id>](findings/012-high-unauthenticated-deletion-of-any-user-via-api-v1-delete-user.md) | `server/api/v1/api_v1.py:223` |
| 13 | high | CWE-434 | [Unrestricted file type upload served inline enables stored XSS and session theft](findings/013-high-unrestricted-file-type-upload-served-inline-enables-stored-x.md) | `server/routes.py:261` |
| 14 | medium | CWE-352 | [CSRF on POST /delete/<filename> deletes a victim's files from a third-party page](findings/014-medium-csrf-on-post-delete-filename-deletes-a-victim-s-files-from-a.md) | `server/routes.py:340` |
| 15 | medium | CWE-639 | [Unauthenticated BOLA: /api/v1/profile returns any user's profile by user_id](findings/015-medium-unauthenticated-bola-api-v1-profile-returns-any-user-s-profi.md) | `server/api/v1/api_v1.py:158` |
| 16 | medium | CWE-639 | [Unauthenticated replacement of any user's profile picture via /api/v1/update_picture](findings/016-medium-unauthenticated-replacement-of-any-user-s-profile-picture-vi.md) | `server/api/v1/api_v1.py:240` |
| 17 | medium | CWE-918 | [Unauthenticated SSRF via user-supplied picture_url in /api/v1/update_picture](findings/017-medium-unauthenticated-ssrf-via-user-supplied-picture-url-in-api-v1.md) | `server/api/v1/api_v1.py:254` |
| 18 | medium | CWE-915 | [Users can grant themselves admin role and permissions via update_profile form fields](findings/018-medium-users-can-grant-themselves-admin-role-and-permissions-via-up.md) | `server/routes.py:187` |
