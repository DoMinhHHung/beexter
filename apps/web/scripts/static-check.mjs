import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const src = path.join(root, "src");
const failures = [];

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

for (const file of ["package.json", "components.json", "tsconfig.json", ".eslintrc.json"]) {
  try {
    JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
  } catch {
    failures.push(`${file}: JSON không hợp lệ`);
  }
}

for (const file of walk(src).filter((target) => /\.(ts|tsx)$/.test(target))) {
  const source = fs.readFileSync(file, "utf8");
  const imports = [...source.matchAll(/(?:from\s+|import\s*)["'](@\/[^"']+)["']/g)];
  for (const match of imports) {
    const target = path.join(src, match[1].slice(2));
    const candidates = [target, `${target}.ts`, `${target}.tsx`, path.join(target, "index.ts"), path.join(target, "index.tsx")];
    if (!candidates.some((candidate) => fs.existsSync(candidate))) {
      failures.push(`${path.relative(root, file)}: thiếu import ${match[1]}`);
    }
  }
}

for (const required of [
  "src/app/(workspace)/onboarding/page.tsx",
  "src/app/(workspace)/dashboard/page.tsx",
  "src/app/(workspace)/profile/page.tsx",
  "src/app/(workspace)/portfolio/page.tsx",
  "src/app/(auth)/sign-up/page.tsx",
  "src/app/(auth)/forgot-password/page.tsx",
  "src/app/api/auth/signup/route.ts",
  "src/app/api/auth/login/route.ts",
  "src/app/api/auth/forgot-password/route.ts",
  "src/app/api/auth/refresh/route.ts",
  "src/components/auth/session-provider.tsx",
  "src/lib/server/request-body.ts",
  "src/lib/server/request-security.ts",
  "scripts/prepare-standalone.mjs",
  "design-system/beexster/MASTER.md"
]) {
  if (!fs.existsSync(path.join(root, required))) {
    failures.push(`${required}: không tồn tại`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exit(1);
}

process.stdout.write("Static project checks passed.\n");
