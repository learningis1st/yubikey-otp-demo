# Cloudflare Pages YubiKey OTP Auth

A lightweight, serverless demonstration of how to protect a Cloudflare Pages site using YubiKey OTP (One-Time Password) authentication.

This project uses **Cloudflare Pages Functions** (Middleware) to intercept requests and enforce authentication before serving any static content.

## Features

- **Serverless:** Runs entirely on Cloudflare Pages (Edge Network).
- **Secure:** Validates OTPs directly with the Yubico API.
- **Session Management:** Uses signed, HTTP-only cookies to maintain sessions.
- **Access Control:** Restricts access to specific Yubikey Device IDs.

## Prerequisites

1.  **Cloudflare Account** (for Cloudflare Pages).
2.  **YubiKey** (any YubiKey that supports OTP).
3.  **Yubico API Keys:** Get your Client ID and Secret Key from [Yubico API Key Signup](https://upgrade.yubico.com/getapikey/).

## Configuration

You must set the following environment variables.

| Variable Name        | Description                                                                 |
| -------------------- | --------------------------------------------------------------------------- |
| `YUBICO_CLIENT_ID`   | Your Client ID from Yubico.                                                 |
| `YUBICO_SECRET_KEY`  | Your Secret Key from Yubico.                                                |
| `ALLOWED_YUBIKEY_ID` | Comma-separated list of allowed YubiKey IDs (first 12 characters of OTP).   |
| `SESSION_SECRET`     | A long, random string used to sign session cookies (e.g., generated via `openssl rand -base64 32`). |
