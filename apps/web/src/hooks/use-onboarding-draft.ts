"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useSession } from "@/components/auth/session-provider";
import {
  onboardingDraftStorageKey,
  readClientStorage,
  removeClientStorage,
  writeClientStorage
} from "@/lib/client-storage";
import { initialProfileDraft } from "@/lib/constants";
import type { Experience, PersonalProfile, PortfolioProject, ProfileDraft, Skill, SocialLinks } from "@/types/profile";

function readDraft(storageKey: string): ProfileDraft {
  if (typeof window === "undefined") {
    return initialProfileDraft;
  }

  const rawDraft = readClientStorage(storageKey);
  if (!rawDraft) {
    return initialProfileDraft;
  }

  try {
    const parsed = JSON.parse(rawDraft) as ProfileDraft;
    return {
      ...initialProfileDraft,
      ...parsed,
      personal: { ...initialProfileDraft.personal, ...parsed.personal },
      links: { ...initialProfileDraft.links, ...parsed.links }
    };
  } catch {
    return initialProfileDraft;
  }
}

export function useOnboardingDraft() {
  const { user } = useSession();
  const storageKey = onboardingDraftStorageKey(user.id);
  const [draft, setDraft] = useState<ProfileDraft>(initialProfileDraft);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setDraft(readDraft(storageKey));
    setHydrated(true);
  }, [storageKey]);

  useEffect(() => {
    if (hydrated) {
      writeClientStorage(storageKey, JSON.stringify(draft));
    }
  }, [draft, hydrated, storageKey]);

  const updatePersonal = useCallback((personal: PersonalProfile) => {
    setDraft((current) => ({ ...current, personal }));
  }, []);

  const updateSkills = useCallback((skills: Skill[]) => {
    setDraft((current) => ({ ...current, skills }));
  }, []);

  const updateExperiences = useCallback((experiences: Experience[], experienceSkipped: boolean) => {
    setDraft((current) => ({ ...current, experiences, experienceSkipped }));
  }, []);

  const updatePortfolio = useCallback((projects: PortfolioProject[], links: SocialLinks) => {
    setDraft((current) => ({ ...current, projects, links }));
  }, []);

  const complete = useCallback(() => {
    setDraft((current) => ({ ...current, completedAt: new Date().toISOString() }));
  }, []);

  const reset = useCallback(() => {
    setDraft(initialProfileDraft);
    removeClientStorage(storageKey);
  }, [storageKey]);

  const score = useMemo(() => {
    let value = 0;
    if (draft.personal.firstName && draft.personal.lastName) value += 12;
    if (draft.personal.headline) value += 12;
    if (draft.personal.about.length >= 40) value += 16;
    if (draft.skills.length >= 3) value += 20;
    if (draft.experiences.length > 0 || draft.experienceSkipped) value += 20;
    if (draft.projects.length > 0 || Object.values(draft.links).some(Boolean)) value += 20;
    return value;
  }, [draft]);

  return {
    draft,
    hydrated,
    score,
    updatePersonal,
    updateSkills,
    updateExperiences,
    updatePortfolio,
    complete,
    reset
  };
}
