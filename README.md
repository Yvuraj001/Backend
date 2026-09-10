<div align="center">

# Backend Server

**A production-ready authentication & user-security backend**
Email/password + Google OAuth · JWT sessions · 2FA · Account activation/deactivation · Avatar uploads

![Node.js](https://img.shields.io/badge/Node.js-Express-339933?logo=node.js&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-Mongoose-47A248?logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/Auth-JWT-black?logo=jsonwebtokens)
![License](https://img.shields.io/badge/License-MIT-blue)

</div>

---

## ✨ Features

- Email/password signup with email verification codes
- Google OAuth 2.0 login
- Access + refresh token auth via `httpOnly` cookies, with session tracking in MongoDB
- Two-Factor Authentication (enable / disable / sign-in verification)
- Forgot / reset password flow
- Account deactivation & reactivation with email confirmation
- Avatar upload (Multer + Cloudinary)
- Rate limiting on every sensitive route


</br>

## 📁 Project Structure

```
├── controller/       # Route handlers (auth, security, verification, upload, regenerate)
├── lib/
│   ├── db/           # MongoDB connection
│   ├── email/        # Email sending + templates
│   ├── generateCookies/
│   ├── multer/       # Avatar upload config
│   └── verifyAuthentication/
├── models/           # User, Session (Mongoose schemas)
├── routes/           # auth, security, verification, oAuth routers
├── utils/            # Zod schemas, Google/Cloudinary config, getAuth
└── index.js           # App entry point
```

## ⚙️ Setup

```bash
npm install
cp env.example .env   # fill in the values below
npm start
```

### Environment Variables

| Variable | Description |
|---|---|
| `JWT_SECRET` / `JWT_REFRESH_SECRET` | Signing secrets for access/refresh tokens |
| `MONGODB_URI` | MongoDB connection string |
| `GOOGLE_CLIENT` / `GOOGLE_SECRET` | Google OAuth credentials |
| `CLOUDINARY_CLOUD_NAME` / `CLOUDINARY_API_KEY` / `CLOUDINARY_API_SECRET` | Cloudinary credentials for avatar storage |
| `PORT` | Server port |
| `CORS_ORIGINS` | Comma-separated allowed origins |
| `COOKIE_SAME_SITE` | Cookie `SameSite` policy |
| `RESEND_API_KEY` | Resend email API key |
| `APP_NAME` / `COMPANY_NAME` / `SUPPORT_EMAIL` / `EMAIL_FROM` | Email template branding |
| `FRONTEND_URL` | Used in email links / redirects |

</br>
## General Response Type

Every JSON response follows one of these shapes:

```js
{
success: true || flase,
message: "success about route" || "failaure about route"
}
```

Auth cookies: **`ref`** (short-lived access token, 15m) and **`pass`** (refresh token, tied to a DB session).

---

# API Routes

Grouped by use case — click a section to expand it.

<br>

<details>
<summary><b> Auth</b> — signup, login, logout, avatar</summary>

<br>

### `POST /api/auth/signup`

Create an account and email a verification code.
```json

// Body
{ "email": "string", "password": "string (min 6)" }

// 200
{ "success": true, "message": "string" }

```

### `POST /api/auth/signin`

Log in. Sets `ref`/`pass` cookies, or emails a 2FA code if enabled on the account.
```json

// Body
{ "email": "string", "password": "string" }

// 200
{ "success": true, "message": "string" }

```

### `POST /api/auth/refresh`

Refreshes the access token using the current refresh token.

The route validates the `pass` refresh-token cookie, generates a new short-lived access token, and sets the new access token in the `ref` cookie.

*(refresh token required)*

```json
// 200
{ "success": true, "message": "string" }
```

### `GET /api/auth/logout`

Clears cookies and invalidates the current session. *(cookie required)*
```json
// 200
{ "success": true, "message": "string" }
```

### `GET /api/auth/logout-all`

Invalidates every session for the user. *(cookie required)*

```json

// 200
{ "success": true, "message": "string" }

```

### `POST /api/auth/upload/avatar`

Uploads to Cloudinary and updates the user's avatar. *(`ref` cookie required)*

```json

// Body: multipart/form-data, field "avatar"
// 200
{ "success": true, "message": "string", "url": "string" }

```

</details>

<br>

<details>
<summary><b>Security</b> — password reset, activation, 2FA, resend codes</summary>

<br>

### `POST /api/auth/security/forgot-user/start`

```json
// Body
{ "email": "string" }

// 200
{ "success": true, "message": "string" }  // reset link emailed
```

### `POST /api/auth/security/activate-user/start`

```json
// Body
{ "email": "string", "password": "string" }

// 200
{ "success": true, "message": "string" }  // reactivation code emailed
```

### `POST /api/auth/security/deactivate-user/start`

```json
// Body
{ "email": "string", "password": "string" }

// 200
{ "success": true, "message": "string" }  // deactivation code emailed
```

### `POST /api/auth/security/2fa/enable/start`
*(cookie required)*

```json
// 200
{ "success": true, "message": "string" }  // 2FA enable code emailed
```

### `POST /api/auth/security/2fa/disable/start`
*(cookie required)*

```json
// 200
{ "success": true, "message": "string" }  // 2FA disable code emailed

```

### Resend codes

```
POST /api/auth/security/resend/email-verification   { "email": "string" }

POST /api/auth/security/resend/password-reset        { "email": "string" }

POST /api/auth/security/resend/activation             { "email": "string" }

POST /api/auth/security/resend/deactivation            { "email": "string" }

POST /api/auth/security/resend/2fa   (cookie)          { "type": "enable" | "disable" | "signin" }
```

All return `200 { "success": true, "message": "string" }`.

</details>

<br>

<details>
<summary><b>Verification</b> — confirming codes sent by the routes above</summary>

<br>

### `GET /api/auth/verification/verify`

Checks the current session. *(`ref` or `pass` cookie)*

```json
// 200
{ "success": true, "userId": "string", "message": "string" }
```

### `POST /api/auth/verification/email/verify`

Activates the account and sets auth cookies.

```json
// Body
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

### `POST /api/auth/verification/forgot-user/verify/:auth_token`

Resets the password.

```json

// Body
{ "password": "string" }

// 200
{ "success": true, "message": "string" }

```

### `POST /api/auth/verification/deactivate-user/verify`

```json
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

### `POST /api/auth/verification/activate-user/verify`
Reactivates the account and sets auth cookies.

```json
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

### `POST /api/auth/verification/2fa/enable/verify`

```json
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

### `POST /api/auth/verification/2fa/disable/verify`

```json
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

### `POST /api/auth/verification/2fa/signin/verify`
Completes 2FA login and sets auth cookies.

```json
{ "verificationToken": "number" }

// 200
{ "success": true, "message": "string" }
```

</details>

<br>

<details>
<summary><b>Google OAuth</b></summary>

<br>

```
GET /api/auth/oAuth/google/initialize   → redirects to Google's consent screen
GET /api/auth/oAuth/google/callback     → 200 { "success": true, "message": "string" }
```

</details>

<br>

<details>
<summary><b>Health</b></summary>

<br>

```
GET /health   → 200 { "health": "OK", "message": "string" }
```

</details>
