import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import {
  accessCookieName,
  clearAuthCookies,
  demoCookieName,
  demoModeEnabled,
  refreshCookieName,
  setAuthCookies
} from "@/lib/server/auth-cookies";
import { withIdentityTokenRotation, type RotatedTokens } from "@/lib/server/refresh";
import { readBoundedJsonBody } from "@/lib/server/request-body";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

const maximumProfileBodyBytes = 256 * 1024;
const monthPattern = /^\d{4}-(?:0[1-9]|1[0-2])$/;
const optionalHttpUrl = z.string().trim().max(2048).transform((value) => {
  if (!value || /^[a-z][a-z0-9+.-]*:/i.test(value)) return value;
  return `https://${value}`;
}).refine((value) => {
  if (!value) return true;
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}, "Liên kết phải dùng HTTP hoặc HTTPS");

const profileSchema = z.object({
  personal: z.object({
    firstName: z.string().trim().min(1).max(80),
    lastName: z.string().trim().min(1).max(80),
    headline: z.string().trim().min(6).max(120),
    location: z.string().trim().min(2).max(120),
    about: z.string().trim().min(40).max(2000),
    workPreference: z.enum(["remote", "hybrid", "onsite"]),
    talentTrack: z.enum(["job_seeker", "freelancer", "open_to_both"])
  }).strict(),
  skills: z.array(z.object({
    id: z.string().uuid(),
    name: z.string().trim().min(1).max(80),
    level: z.enum(["learning", "working", "advanced", "expert"])
  }).strict()).max(50),
  experiences: z.array(z.object({
    id: z.string().uuid(),
    role: z.string().trim().min(1).max(120),
    company: z.string().trim().min(1).max(160),
    startDate: z.string().regex(monthPattern),
    endDate: z.union([z.literal(""), z.string().regex(monthPattern)]),
    current: z.boolean(),
    description: z.string().trim().max(2000)
  }).strict()).max(30),
  experienceSkipped: z.boolean(),
  projects: z.array(z.object({
    id: z.string().uuid(),
    title: z.string().trim().min(1).max(160),
    description: z.string().trim().max(3000),
    url: optionalHttpUrl,
    tags: z.array(z.string().trim().min(1).max(60)).max(20)
  }).strict()).max(30),
  links: z.object({
    linkedin: optionalHttpUrl,
    github: optionalHttpUrl,
    website: optionalHttpUrl
  }).strict(),
  completedAt: z.string().datetime({ offset: true }).nullable()
}).strict();

async function submitProfile(profileApiUrl: string, accessToken: string, payload: z.infer<typeof profileSchema>) {
  return fetch(`${profileApiUrl.replace(/\/$/, "")}/v1/profiles/onboarding`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload),
    cache: "no-store",
    signal: AbortSignal.timeout(15000)
  });
}

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request, { requireJson: true });
  if (rejected) return rejected;

  const body = await readBoundedJsonBody(request, maximumProfileBodyBytes);
  if (!body.success && body.tooLarge) {
    return NextResponse.json({ error: { code: "ERR_INVALID_INPUT", message: "Hồ sơ vượt quá kích thước cho phép" } }, { status: 413 });
  }
  const parsed = profileSchema.safeParse(body.success ? body.data : null);
  if (!parsed.success) {
    return NextResponse.json({ error: { code: "ERR_INVALID_INPUT", message: "Hồ sơ chưa hợp lệ" } }, { status: 400 });
  }

  const cookieStore = await cookies();
  const accessToken = cookieStore.get(accessCookieName)?.value;
  const refreshToken = cookieStore.get(refreshCookieName)?.value;
  const demoSession = cookieStore.get(demoCookieName)?.value;
  const profileApiUrl = process.env.PROFILE_API_URL?.trim();
  const demoSessionActive = Boolean(demoModeEnabled() && demoSession);
  const localProfileMode = process.env.NODE_ENV !== "production" && process.env.PROFILE_LOCAL_MODE === "true";

  if (!accessToken && !refreshToken && !demoSessionActive) {
    return NextResponse.json({ error: { code: "ERR_UNAUTHENTICATED", message: "Chưa đăng nhập" } }, { status: 401 });
  }
  if (demoSessionActive || localProfileMode) {
    return NextResponse.json({ data: { accepted: true, mode: "local" } }, { status: 202 });
  }
  if (!profileApiUrl) {
    return NextResponse.json({ error: { code: "ERR_PROFILE_UNAVAILABLE", message: "Profile service chưa được cấu hình" } }, { status: 503 });
  }

  try {
    if (accessToken) {
      const upstream = await submitProfile(profileApiUrl, accessToken, parsed.data);
      if (upstream.status !== 401 || !refreshToken) {
        const payload = await upstream.json().catch(() => ({}));
        return NextResponse.json(payload, { status: upstream.status });
      }
    }

    if (!refreshToken) {
      const response = NextResponse.json({ error: { code: "ERR_UNAUTHENTICATED", message: "Phiên đăng nhập đã hết hạn" } }, { status: 401 });
      clearAuthCookies(response);
      return response;
    }

    const requestHeaders = await headers();
    return await withIdentityTokenRotation(refreshToken, requestHeaders, async (rotation) => {
      if (!rotation.ok) {
        const response = NextResponse.json(rotation.body, {
          status: rotation.invalidSession && rotation.status === 400 ? 401 : rotation.status
        });
        if (rotation.invalidSession) {
          clearAuthCookies(response);
        }
        return response;
      }

      try {
        const retried = await submitProfile(profileApiUrl, rotation.tokens.accessToken, parsed.data);
        const payload = await retried.json().catch(() => ({}));
        const response = NextResponse.json(payload, { status: retried.status });
        if (retried.status === 401) {
          clearAuthCookies(response);
        } else {
          setRotatedAuthCookies(response, rotation.tokens);
        }
        return response;
      } catch {
        const response = profileUnavailableResponse();
        setRotatedAuthCookies(response, rotation.tokens);
        return response;
      }
    });
  } catch {
    return profileUnavailableResponse();
  }
}

function setRotatedAuthCookies(response: NextResponse, tokens: RotatedTokens) {
  setAuthCookies(response, tokens.accessToken, tokens.refreshToken, {
    accessTokenExpiresAt: tokens.accessTokenExpiresAt,
    refreshTokenExpiresAt: tokens.refreshTokenExpiresAt
  });
}

function profileUnavailableResponse() {
  return NextResponse.json(
    { error: { code: "ERR_PROFILE_UNAVAILABLE", message: "Profile service đang tạm thời không khả dụng" } },
    { status: 503 }
  );
}
