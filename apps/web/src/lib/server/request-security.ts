import { NextResponse } from "next/server";

interface MutationRequestOptions {
  requireJson?: boolean;
}

export function rejectUnsafeMutation(
  request: Request,
  options: MutationRequestOptions = {}
): NextResponse | null {
  const fetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    return forbiddenResponse();
  }

  const origin = request.headers.get("origin");
  if (origin && !sameOrigin(origin, publicRequestOrigin(request))) {
    return forbiddenResponse();
  }

  if (options.requireJson) {
    const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json") {
      return NextResponse.json(
        { error: { code: "ERR_INVALID_INPUT", message: "Content-Type phải là application/json" } },
        { status: 415 }
      );
    }
  }

  return null;
}

function sameOrigin(origin: string, expectedOrigin: string) {
  try {
    return new URL(origin).origin === expectedOrigin;
  } catch {
    return false;
  }
}

function publicRequestOrigin(request: Request) {
  const requestUrl = new URL(request.url);
  const forwardedHost = firstHeaderValue(request.headers.get("x-forwarded-host"));
  const host = forwardedHost || request.headers.get("host")?.trim();
  const forwardedProtocol = firstHeaderValue(request.headers.get("x-forwarded-proto"));
  const protocol = forwardedProtocol === "http" || forwardedProtocol === "https"
    ? `${forwardedProtocol}:`
    : requestUrl.protocol;

  if (!host) return requestUrl.origin;
  try {
    return new URL(`${protocol}//${host}`).origin;
  } catch {
    return requestUrl.origin;
  }
}

function firstHeaderValue(value: string | null) {
  return value?.split(",", 1)[0]?.trim() || "";
}

function forbiddenResponse() {
  return NextResponse.json(
    { error: { code: "ERR_FORBIDDEN", message: "Nguồn yêu cầu không được phép" } },
    { status: 403 }
  );
}
