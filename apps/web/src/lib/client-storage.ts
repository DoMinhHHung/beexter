const draftPrefix = "beexster:onboarding-draft:v2:";
const activeIdentityKey = "beexster:active-identity:v1";
const legacyDraftKey = "beexster:onboarding-draft:v1";

export function onboardingDraftStorageKey(identityId: string) {
  return `${draftPrefix}${identityId}`;
}

export function bindLocalDataToIdentity(identityId: string) {
  const previousIdentityId = readClientStorage(activeIdentityKey);
  if (previousIdentityId && previousIdentityId !== identityId) {
    removeClientStorage(onboardingDraftStorageKey(previousIdentityId));
  }
  removeClientStorage(legacyDraftKey);
  writeClientStorage(activeIdentityKey, identityId);
}

export function clearLocalIdentityData() {
  const identityId = readClientStorage(activeIdentityKey);
  if (identityId) {
    removeClientStorage(onboardingDraftStorageKey(identityId));
  }
  removeClientStorage(legacyDraftKey);
  removeClientStorage(activeIdentityKey);
}

export function readClientStorage(key: string) {
  try {
    return typeof window === "undefined" ? null : window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeClientStorage(key: string, value: string) {
  try {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(key, value);
    }
  } catch {
    // Draft persistence is best-effort and must never block authentication.
  }
}

export function removeClientStorage(key: string) {
  try {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Draft cleanup is best-effort and must never block navigation.
  }
}
