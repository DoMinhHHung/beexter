export type BoundedJsonBody =
  | { success: true; data: unknown }
  | { success: false; tooLarge: boolean };

export const maximumAuthJsonBodyBytes = 16 * 1024;

export async function readBoundedJsonBody(
  request: Request,
  maximumBytes: number
): Promise<BoundedJsonBody> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength)) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length > maximumBytes) {
      await request.body?.cancel().catch(() => undefined);
      return { success: false, tooLarge: true };
    }
  }

  if (!request.body) {
    return { success: false, tooLarge: false };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        return { success: false, tooLarge: true };
      }
      chunks.push(value);
    }
  } catch {
    return { success: false, tooLarge: false };
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { success: true, data: JSON.parse(text) as unknown };
  } catch {
    return { success: false, tooLarge: false };
  }
}
