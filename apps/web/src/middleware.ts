import { NextResponse, type NextRequest } from "next/server";
import { demoModeEnabled } from "@/lib/server/auth-cookies";

const protectedRoutes = ["/onboarding", "/dashboard", "/profile", "/portfolio"];

export function middleware(request: NextRequest) {
  const isProtected = protectedRoutes.some((route) => request.nextUrl.pathname.startsWith(route));
  if (!isProtected) {
    return NextResponse.next();
  }

  const hasSession = Boolean(
      request.cookies.get("beexster_access")?.value ||
      request.cookies.get("beexster_refresh")?.value ||
      (demoModeEnabled() && request.cookies.get("beexster_demo_session")?.value)
  );

  if (hasSession) {
    return NextResponse.next();
  }

  const signInUrl = new URL("/sign-in", request.url);
  signInUrl.searchParams.set("next", request.nextUrl.pathname);
  return NextResponse.redirect(signInUrl);
}

export const config = {
  matcher: ["/onboarding/:path*", "/dashboard/:path*", "/profile/:path*", "/portfolio/:path*"]
};
