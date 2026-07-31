import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const nextDirectory = path.join(root, ".next");
const standaloneDirectory = path.join(nextDirectory, "standalone");

if (!fs.existsSync(path.join(standaloneDirectory, "server.js"))) {
  throw new Error("Standalone build is missing; run `next build` first");
}

copyDirectory(
  path.join(nextDirectory, "static"),
  path.join(standaloneDirectory, ".next", "static")
);
copyDirectory(path.join(root, "public"), path.join(standaloneDirectory, "public"));

function copyDirectory(source, destination) {
  if (!fs.existsSync(source)) return;
  fs.cpSync(source, destination, { recursive: true, force: true });
}
