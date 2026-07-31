import type { ProfileDraft } from "@/types/profile";

interface SaveProfileResponse {
  accepted: boolean;
  mode: "api" | "local";
}

export async function saveProfileDraft(draft: ProfileDraft): Promise<SaveProfileResponse> {
  const response = await fetch("/api/profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(draft)
  });

  const payload = (await response.json()) as {
    data?: SaveProfileResponse;
    error?: { message?: string };
  };

  if (!response.ok || !payload.data) {
    throw new Error(payload.error?.message || "Không thể lưu hồ sơ lúc này");
  }

  return payload.data;
}
