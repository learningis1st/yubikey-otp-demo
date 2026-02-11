// --- TYPES & CONSTANTS ---

interface Env {
    YUBICO_CLIENT_ID: string;
    YUBICO_SECRET_KEY: string;
    ALLOWED_YUBIKEY_ID: string;
    SESSION_SECRET: string;
}

const SESSION_DURATION_MS = 3600 * 1000; // 1 hour
const SESSION_MAX_AGE_SECONDS = 3600;
const YUBIKEY_ID_LENGTH = 12;

// --- MIDDLEWARE ---

export const onRequest: PagesFunction<Env> = async (context) => {
    const url = new URL(context.request.url);

    // Allow static assets to bypass authentication immediately
    if (/\.(ico|png|jpg|jpeg|css|js|svg)$/.test(url.pathname)) {
        return context.next();
    }

    const cookieHeader = context.request.headers.get("Cookie");
    const sessionData = await verifySessionCookie(
        cookieHeader,
        context.env.SESSION_SECRET,
        context.env.ALLOWED_YUBIKEY_ID
    );

    // Authenticated user
    if (sessionData) {
        context.data.yubikeyId = sessionData.yubikeyId;

        if (url.pathname === "/login" || url.pathname === "/auth") {
            return Response.redirect(new URL("/", context.request.url).toString(), 302);
        }
        return context.next();
    }

    // Handle login form submission
    if (url.pathname === "/auth" && context.request.method === "POST") {
        return handleAuth(context);
    }

    // Allow access to login page
    if (url.pathname === "/login") {
        return context.next();
    }

    // Redirect unauthenticated users to login
    return Response.redirect(new URL("/login", context.request.url).toString(), 302);
};

// --- AUTH HANDLER ---

async function handleAuth(context: EventContext<Env, string, Record<string, unknown>>): Promise<Response> {
    const formData = await context.request.formData();
    const otp = formData.get("otp") as string;

    const redirectWithError = (msg: string) => {
        const errorUrl = new URL("/login", context.request.url);
        errorUrl.searchParams.set("error", msg);
        return Response.redirect(errorUrl.toString(), 302);
    };

    if (!otp) {
        return redirectWithError("No OTP provided");
    }

    const yubikeyId = otp.substring(0, YUBIKEY_ID_LENGTH).toLowerCase();
    const allowedIds = parseAllowedIds(context.env.ALLOWED_YUBIKEY_ID);

    if (!allowedIds.includes(yubikeyId)) {
        return redirectWithError("Unauthorized Device ID");
    }

    try {
        const isValid = await verifyYubicoOTP(
            otp,
            context.env.YUBICO_CLIENT_ID,
            context.env.YUBICO_SECRET_KEY
        );

        if (!isValid) {
            return redirectWithError("Invalid OTP");
        }

        const sessionCookieValue = await createSignedSessionValue(context.env.SESSION_SECRET, yubikeyId);
        return new Response(null, {
            status: 303,
            headers: {
                "Location": "/",
                "Set-Cookie": `auth_session=${sessionCookieValue}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE_SECONDS}`
            }
        });
    } catch (error) {
        console.error("Auth System Error:", error);
        return redirectWithError("Verification Service Unavailable. Try again.");
    }
}

// --- SESSION MANAGEMENT ---

async function createSignedSessionValue(secret: string, yubikeyId: string): Promise<string> {
    const expiration = Date.now() + SESSION_DURATION_MS;
    const data = JSON.stringify({ status: "valid", yubikeyId, exp: expiration });
    const encodedData = base64ToBase64Url(btoa(data));
    const signature = base64ToBase64Url(await signHmacSha256(encodedData, secret));

    return `${encodedData}.${signature}`;
}

async function verifySessionCookie(
    cookieHeader: string | null,
    secret: string,
    allowedYubiKeys: string
): Promise<{ yubikeyId: string } | null> {
    if (!cookieHeader) return null;

    const match = cookieHeader.match(/(?:^|; )\s*auth_session=([^;]+)/);
    if (!match) return null;

    const [encodedDataUrl, signatureUrl] = match[1].split('.');
    if (!encodedDataUrl || !signatureUrl) return null;

    const expectedSignature = base64ToBase64Url(await signHmacSha256(encodedDataUrl, secret));
    if (!timingSafeEqual(signatureUrl, expectedSignature)) return null;

    try {
        const data = JSON.parse(atob(base64UrlToBase64(encodedDataUrl)));

        if (Date.now() > data.exp) return null;

        const allowedIds = parseAllowedIds(allowedYubiKeys);
        if (!data.yubikeyId || !allowedIds.includes(data.yubikeyId.toLowerCase())) {
            return null;
        }

        return { yubikeyId: data.yubikeyId };
    } catch {
        return null;
    }
}

// --- YUBICO OTP VALIDATION ---

async function verifyYubicoOTP(otp: string, clientId: string, secretKeyB64: string): Promise<boolean> {
    const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 40);
    const params: Record<string, string> = { id: clientId, otp, nonce };

    params['h'] = await generateYubicoSignature(params, secretKeyB64);

    const response = await fetch(`https://api.yubico.com/wsapi/2.0/verify?${new URLSearchParams(params)}`);
    if (!response.ok) {
        throw new Error(`Yubico API responded with status ${response.status}`);
    }

    const responseParams = parseYubicoResponse(await response.text());

    if (responseParams['status'] !== 'OK') return false;
    if (responseParams['nonce'] !== nonce) return false;
    if (responseParams['otp'] !== otp) return false;

    const receivedSignature = responseParams['h'];
    if (!receivedSignature) return false;

    delete responseParams['h'];
    const expectedSignature = await generateYubicoSignature(responseParams, secretKeyB64);

    return timingSafeEqual(receivedSignature, expectedSignature);
}

async function generateYubicoSignature(params: Record<string, string>, secretKeyB64: string): Promise<string> {
    const message = Object.keys(params).sort().map(key => `${key}=${params[key]}`).join('&');
    const keyBytes = base64ToBytes(secretKeyB64);

    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));

    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

function parseYubicoResponse(text: string): Record<string, string> {
    return Object.fromEntries(
        text.trim().split(/\r?\n/).map(line => {
            const [key, ...rest] = line.split('=');
            return [key.trim(), rest.join('=').trim()];
        })
    );
}

// --- CRYPTO UTILITIES ---

async function signHmacSha256(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
        mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return mismatch === 0;
}

// --- ENCODING UTILITIES ---

function base64ToBase64Url(base64: string): string {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBase64(base64url: string): string {
    const padded = base64url.padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
    return padded.replace(/-/g, '+').replace(/_/g, '/');
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
}

// --- HELPERS ---

function parseAllowedIds(allowedYubiKeys: string): string[] {
    return (allowedYubiKeys || "").split(',').map(id => id.trim().toLowerCase());
}