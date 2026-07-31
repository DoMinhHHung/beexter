import type { NextResponse } from "next/server";

export const accessCookieName = "beexster_access";
export const refreshCookieName = "beexster_refresh";
export const demoCookieName = "beexster_demo_session";

const secure = process.env.NODE_ENV === "production";

interface AuthCookieExpirations {
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

export function setAuthCookies(
  response: NextResponse,
  accessToken: string,
  refreshToken: string,
  expirations: AuthCookieExpirations
) {
  clearCookie(response, demoCookieName);
  response.cookies.set(accessCookieName, accessToken, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    expires: cookieExpiration(expirations.accessTokenExpiresAt),
    priority: "high"
  });
  response.cookies.set(refreshCookieName, refreshToken, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    expires: cookieExpiration(expirations.refreshTokenExpiresAt),
    priority: "high"
  });
}

export function setDemoCookie(response: NextResponse) {
  clearCookie(response, accessCookieName);
  clearCookie(response, refreshCookieName);
  response.cookies.set(demoCookieName, "active", {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: 604800,
    priority: "high"
  });
}

export function clearAuthCookies(response: NextResponse) {
  for (const name of [accessCookieName, refreshCookieName, demoCookieName]) {
    clearCookie(response, name);
  }
}

export function demoModeEnabled() {
  return process.env.NODE_ENV !== "production" && process.env.DEMO_MODE === "true";
}

function cookieExpiration(value: string) {
  const expiration = new Date(value);
  if (!Number.isFinite(expiration.getTime())) {
    throw new Error("Identity token expiration is invalid");
  }
  return expiration;
}

function clearCookie(response: NextResponse, name: string) {
  response.cookies.set(name, "", {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    expires: new Date(0),
    priority: "high"
  });
}
