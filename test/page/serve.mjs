import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

export const DOCS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "docs");

// Mirrors GitHub Pages: the site is served under /sayso/, so a root-relative path in the page would 404 here too.
export function serve(root = DOCS, port = 0) {
  const server = http.createServer((req, res) => {
    const { pathname } = new URL(req.url, "http://localhost");
    if (!pathname.startsWith("/sayso/")) {
      res.writeHead(404).end();
      return;
    }
    const relative = pathname.slice("/sayso/".length) || "index.html";
    const file = path.resolve(root, relative);
    if (!file.startsWith(path.resolve(root) + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": MIME[path.extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}/sayso/` })));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ? path.resolve(process.argv[2]) : DOCS;
  const { url } = await serve(root, Number(process.argv[3] ?? 0));
  console.log(url);
}
