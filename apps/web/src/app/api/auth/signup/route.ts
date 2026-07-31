import { NextResponse } from "next/server";
import { z } from "zod";
import { demoModeEnabled } from "@/lib/server/auth-cookies";
import {
  identityApiUrl,
  identityErrorEnvelope,
  identityForwardedForHeaders,
  identityRequestFailure,
  IdentityProtocolError,
  readJson,
  type IdentityErrorBody
} from "@/lib/server/identity";
import { maximumAuthJsonBodyBytes, readBoundedJsonBody } from "@/lib/server/request-body";
import { rejectUnsafeMutation } from "@/lib/server/request-security";

const schema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(8).max(128)
}).strict();

interface SignupPayload extends IdentityErrorBody {
  data?: {
    id?: string;
    email?: string;
    email_verified?: boolean;
  };
}

export async function POST(request: Request) {
  const rejected = rejectUnsafeMutation(request, { requireJson: true });
  if (rejected) return rejected;

  const body = await readBoundedJsonBody(request, maximumAuthJsonBodyBytes);
  const parsed = schema.safeParse(body.success ? body.data : null);
  if (!parsed.success) {
    return NextResponse.json(
      {
        error: {
          code: body.success || !body.tooLarge ? "ERR_INVALID_INPUT" : "ERR_REQUEST_TOO_LARGE",
          message: body.success || !body.tooLarge ? "Thông tin đăng ký chưa hợp lệ" : "Yêu cầu vượt quá kích thước cho phép"
        }
      },
      { status: body.success || !body.tooLarge ? 400 : 413 }
    );
  }

  if (demoModeEnabled()) {
    return NextResponse.json(
      {
        data: {
          id: "0198f124-659f-7cbd-a441-dc7eea175073",
          email: parsed.data.email,
          email_verified: false
        }
      },
      { status: 201 }
    );
  }

  try {
    const upstream = await fetch(identityApiUrl("/v1/auth/signup"), {
      method: "POST",
      headers: {
        "Accept-Language": request.headers.get("accept-language")?.slice(0, 128) || "vi",
        "Content-Type": "application/json",
        "User-Agent": request.headers.get("user-agent")?.slice(0, 512) || "Beexster-Web",
        ...identityForwardedForHeaders(request.headers)
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(15000)
    });
    const payload = await readJson<SignupPayload>(upstream);

    if (!upstream.ok) {
      return NextResponse.json(
        identityErrorEnvelope(payload, "ERR_SIGNUP_FAILED", "Không thể tạo tài khoản"),
        { status: upstream.status }
      );
    }
    if (
      upstream.status !== 201 ||
      typeof payload.data?.id !== "string" ||
      typeof payload.data.email !== "string" ||
      payload.data.email_verified !== false
    ) {
      throw new IdentityProtocolError("Identity signup response is missing required fields");
    }

    return NextResponse.json(
      {
        data: {
          id: payload.data.id,
          email: payload.data.email,
          email_verified: false
        }
      },
      { status: 201 }
    );
  } catch (error) {
    const failure = identityRequestFailure(error, "Identity service đang tạm thời không khả dụng");
    return NextResponse.json(failure.body, { status: failure.status });
  }
}
