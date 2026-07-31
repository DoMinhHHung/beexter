"use client";

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LoaderCircle, RefreshCcw, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { bindLocalDataToIdentity, clearLocalIdentityData } from "@/lib/client-storage";

export interface SessionUser {
  id: string;
  email: string;
  platformRole?: "ADMIN" | "VICE_ADMIN";
  emailVerified: boolean;
  mode: "api" | "demo";
}

interface SessionContextValue {
  user: SessionUser;
}

const SessionContext = createContext<SessionContextValue | null>(null);
let currentSessionRequest: Promise<SessionResult> | null = null;

type SessionResult =
  | { ok: true; user: SessionUser }
  | { ok: false; status: number; message: string };

export function SessionProvider({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    setError("");

    void loadSession().then((result) => {
      if (!active) return;

      if (result.ok) {
        bindLocalDataToIdentity(result.user.id);
        setUser(result.user);
        return;
      }

      if (result.status === 401 || result.status === 403) {
        clearLocalIdentityData();
        const destination = `${pathname || "/onboarding"}`;
        router.replace(`/sign-in?next=${encodeURIComponent(destination)}`);
        router.refresh();
        return;
      }

      setError(result.message);
    });

    return () => {
      active = false;
    };
  }, [attempt, pathname, router]);

  const contextValue = useMemo(() => (user ? { user } : null), [user]);
  if (contextValue) {
    return <SessionContext.Provider value={contextValue}>{children}</SessionContext.Provider>;
  }

  if (error) {
    return (
      <main id="main-content" className="flex min-h-dvh items-center justify-center px-4">
        <div className="w-full max-w-md rounded-3xl border border-white/10 bg-slate-950/70 p-7 text-center shadow-panel backdrop-blur-xl">
          <ShieldAlert className="mx-auto size-10 text-amber-300" />
          <h1 className="mt-5 font-[family-name:var(--font-heading)] text-2xl font-bold">Không thể kiểm tra phiên</h1>
          <p className="mt-3 leading-7 text-muted-foreground">{error}</p>
          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <Button type="button" variant="cosmic" onClick={() => setAttempt((value) => value + 1)}>
              <RefreshCcw /> Thử lại
            </Button>
            <Button asChild variant="outline">
              <Link href="/sign-in">Đăng nhập lại</Link>
            </Button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main id="main-content" className="flex min-h-dvh items-center justify-center" aria-live="polite">
      <div className="flex items-center gap-3 text-sm text-slate-300">
        <LoaderCircle className="size-5 animate-spin text-violet-300" /> Đang kiểm tra phiên đăng nhập...
      </div>
    </main>
  );
}

export function useSession() {
  const session = useContext(SessionContext);
  if (!session) {
    throw new Error("useSession must be used inside SessionProvider");
  }
  return session;
}

function loadSession() {
  if (!currentSessionRequest) {
    currentSessionRequest = requestSession().finally(() => {
      currentSessionRequest = null;
    });
  }
  return currentSessionRequest;
}

async function requestSession(): Promise<SessionResult> {
  try {
    const response = await fetch("/api/auth/session", { method: "POST", cache: "no-store" });
    const payload = (await response.json()) as {
      data?: {
        id?: string;
        email?: string;
        platform_role?: "ADMIN" | "VICE_ADMIN";
        email_verified?: boolean;
        mode?: "api" | "demo";
      };
      error?: { message?: string };
    };

    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        message: payload.error?.message || "Identity service đang tạm thời không khả dụng"
      };
    }

    const data = payload.data;
    if (!data?.id || !data.email || typeof data.email_verified !== "boolean") {
      return { ok: false, status: 502, message: "Dữ liệu phiên đăng nhập không hợp lệ" };
    }

    return {
      ok: true,
      user: {
        id: data.id,
        email: data.email,
        emailVerified: data.email_verified,
        mode: data.mode === "demo" ? "demo" : "api",
        ...(data.platform_role ? { platformRole: data.platform_role } : {})
      }
    };
  } catch {
    return { ok: false, status: 503, message: "Không thể kết nối để kiểm tra phiên đăng nhập" };
  }
}
