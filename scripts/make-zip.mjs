// Packs plugin/ into dist/uaip-security-firewall.zip (folder name = plugin slug).
// Small dependency-free ZIP writer (deflate via node:zlib).
import { deflateRawSync, crc32 } from "node:zlib";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SLUG = "uaip-security-firewall";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "plugin");
const dist = join(root, "dist");
const EXCLUDE = [/(^|\/)\.distignore$/, /\.map$/, /(^|\/)\.DS_Store$/, /(^|\/)Thumbs\.db$/, /\.pdf$/i];

const files = [];
(function walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    const rel = relative(src, p).split(sep).join("/");
    if (EXCLUDE.some((re) => re.test(rel))) continue;
    if (e.isDirectory()) walk(p);
    else files.push({ path: p, name: `${SLUG}/${rel}` });
  }
})(src);
files.sort((a, b) => a.name.localeCompare(b.name));

function dosTime(d) {
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

const chunks = [];
const central = [];
let offset = 0;
let rawTotal = 0;
for (const f of files) {
  const data = readFileSync(f.path);
  rawTotal += data.length;
  const deflated = deflateRawSync(data, { level: 9 });
  const useDeflate = deflated.length < data.length;
  const body = useDeflate ? deflated : data;
  const name = Buffer.from(f.name, "utf8");
  const crc = crc32(data);
  const { time, date } = dosTime(statSync(f.path).mtime);

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x0800, 6); // UTF-8 names
  local.writeUInt16LE(useDeflate ? 8 : 0, 8);
  local.writeUInt16LE(time, 10);
  local.writeUInt16LE(date, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(body.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  chunks.push(local, name, body);

  const cen = Buffer.alloc(46);
  cen.writeUInt32LE(0x02014b50, 0);
  cen.writeUInt16LE(20, 4);
  cen.writeUInt16LE(20, 6);
  cen.writeUInt16LE(0x0800, 8);
  cen.writeUInt16LE(useDeflate ? 8 : 0, 10);
  cen.writeUInt16LE(time, 12);
  cen.writeUInt16LE(date, 14);
  cen.writeUInt32LE(crc, 16);
  cen.writeUInt32LE(body.length, 20);
  cen.writeUInt32LE(data.length, 24);
  cen.writeUInt16LE(name.length, 28);
  cen.writeUInt32LE(offset, 42);
  central.push(cen, name);
  offset += local.length + name.length + body.length;
}
const cenSize = central.reduce((n, b) => n + b.length, 0);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(files.length, 8);
end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(cenSize, 12);
end.writeUInt32LE(offset, 16);

mkdirSync(dist, { recursive: true });
const zip = Buffer.concat([...chunks, ...central, end]);
const target = join(dist, `${SLUG}.zip`);
writeFileSync(target, zip);
const mb = (n) => (n / 1048576).toFixed(2) + " MB";
console.log(`${files.length} files, ${mb(rawTotal)} unpacked -> ${relative(root, target)} (${mb(zip.length)})`);
