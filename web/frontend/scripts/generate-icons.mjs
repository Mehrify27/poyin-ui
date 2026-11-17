import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const iconsDir = path.resolve(__dirname, "../public/icons");

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePNG(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0; // filter none
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function clamp(v, lo = 0, hi = 1) {
  return v < lo ? lo : v > hi ? hi : v;
}

function smoothstep(edge0, edge1, x) {
  const t = clamp((x - edge0) / (edge1 - edge0));
  return t * t * (3 - 2 * t);
}

function sdRoundedBox(px, py, cx, cy, halfW, halfH, r) {
  const dx = Math.abs(px - cx) - (halfW - r);
  const dy = Math.abs(py - cy) - (halfH - r);
  const ox = Math.max(dx, 0);
  const oy = Math.max(dy, 0);
  return Math.hypot(ox, oy) + Math.min(Math.max(dx, dy), 0) - r;
}

function distToSegment(px, py, x1, y1, x2, y2) {
  const vx = x2 - x1;
  const vy = y2 - y1;
  const wx = px - x1;
  const wy = py - y1;
  const c1 = vx * wx + vy * wy;
  if (c1 <= 0) return Math.hypot(px - x1, py - y1);
  const c2 = vx * vx + vy * vy;
  if (c2 <= c1) return Math.hypot(px - x2, py - y2);
  const b = c1 / c2;
  return Math.hypot(px - (x1 + b * vx), py - (y1 + b * vy));
}

function pointInPoly(x, y, pts) {
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const xi = pts[i][0], yi = pts[i][1];
    const xj = pts[j][0], yj = pts[j][1];
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function distToPolygon(x, y, pts) {
  let minD = Infinity;
  for (let i = 0; i < pts.length; i++) {
    const a = pts[i];
    const b = pts[(i + 1) % pts.length];
    const d = distToSegment(x, y, a[0], a[1], b[0], b[1]);
    if (d < minD) minD = d;
  }
  return minD;
}

function blendOver(dst, sr, sg, sb, sa) {
  const a = clamp(sa);
  const da = dst[3];
  const outA = a + da * (1 - a);
  if (outA <= 0) return [0, 0, 0, 0];
  return [
    (sr * a + dst[0] * da * (1 - a)) / outA,
    (sg * a + dst[1] * da * (1 - a)) / outA,
    (sb * a + dst[2] * da * (1 - a)) / outA,
    outA,
  ];
}

function renderIcon(size, maskable) {
  const buf = Buffer.alloc(size * size * 4);
  const scale = maskable ? 80 / 128 : 112 / 128;
  const half = (128 * scale) / 2;
  const rx = 30 * (maskable ? 80 / 112 : 1);
  const shieldScale = maskable ? 80 / 112 : 1;

  // Polygon approximating shield M36 44 L64 28 L92 44 V67 ... in 128x128 coordinates
  const cx = 64;
  const cy = 64;
  const sPts = [
    [36, 44],
    [64, 28],
    [92, 44],
    [92, 67],
    [88, 79],
    [79, 90],
    [64, 99],
    [49, 90],
    [40, 79],
    [36, 67],
  ].map(([x, y]) => [cx + (x - cx) * shieldScale, cy + (y - cy) * shieldScale]);

  const chevPts = [
    [50, 64.5],
    [64, 50.5],
    [78, 64.5],
  ].map(([x, y]) => [cx + (x - cx) * shieldScale, cy + (y - cy) * shieldScale]);
  const stem = [
    [cx, cy + (51 - cy) * shieldScale],
    [cx, cy + (81 - cy) * shieldScale],
  ];

  const pxAA = 128 / size;

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      const x = ((px + 0.5) / size) * 128;
      const y = ((py + 0.5) / size) * 128;

      let col = [0, 0, 0, 0];
      if (maskable) {
        const gt = clamp((x + y) / 256);
        col = [(7 + gt * 3) / 255, (26 - gt * 8) / 255, (22 + gt * 12) / 255, 1];
      }

      // Squircle badge
      const dBox = sdRoundedBox(x, y, 64, 64, half, half, rx);
      const badgeAlpha = 1 - smoothstep(-pxAA, pxAA, dBox);
      if (badgeAlpha > 0) {
        const gt = clamp((x - (64 - half) + (y - (64 - half))) / (4 * half));
        // Gradient #008771 -> #1bbf9f
        const br = (0 + 27 * gt) / 255;
        const bg = (135 + 56 * gt) / 255;
        const bb = (113 + 46 * gt) / 255;
        col = blendOver(col, br, bg, bb, badgeAlpha);

        // Inner highlight border
        const borderDist = Math.abs(dBox + 1.5 * shieldScale);
        const borderAlpha = (1 - smoothstep(0.6 * shieldScale, 1.5 * shieldScale + pxAA, borderDist)) * 0.28 * badgeAlpha;
        if (borderAlpha > 0) col = blendOver(col, 1, 1, 1, borderAlpha);
      }

      // Shield fill + stroke
      const insideShield = pointInPoly(x, y, sPts);
      const dShieldEdge = distToPolygon(x, y, sPts);
      if (insideShield) {
        col = blendOver(col, 1, 1, 1, 0.14);
      }
      const shieldStrokeW = 2.75 * shieldScale;
      const shieldStrokeAlpha = 1 - smoothstep(shieldStrokeW - pxAA, shieldStrokeW + pxAA, dShieldEdge);
      if (shieldStrokeAlpha > 0) {
        col = blendOver(col, 1, 1, 1, shieldStrokeAlpha);
      }

      // Inner arrow chevron + stem
      const dChev = Math.min(
        distToSegment(x, y, chevPts[0][0], chevPts[0][1], chevPts[1][0], chevPts[1][1]),
        distToSegment(x, y, chevPts[1][0], chevPts[1][1], chevPts[2][0], chevPts[2][1]),
        distToSegment(x, y, stem[0][0], stem[0][1], stem[1][0], stem[1][1]),
      );
      const innerW = 3.0 * shieldScale;
      const innerAlpha = 1 - smoothstep(innerW - pxAA, innerW + pxAA, dChev);
      if (innerAlpha > 0) {
        col = blendOver(col, 1, 1, 1, innerAlpha);
      }

      const idx = (py * size + px) * 4;
      buf[idx] = Math.round(clamp(col[0]) * 255);
      buf[idx + 1] = Math.round(clamp(col[1]) * 255);
      buf[idx + 2] = Math.round(clamp(col[2]) * 255);
      buf[idx + 3] = Math.round(clamp(col[3]) * 255);
    }
  }
  return encodePNG(size, size, buf);
}

fs.mkdirSync(iconsDir, { recursive: true });
fs.writeFileSync(path.join(iconsDir, "icon-192.png"), renderIcon(192, false));
fs.writeFileSync(path.join(iconsDir, "icon-512.png"), renderIcon(512, false));
fs.writeFileSync(path.join(iconsDir, "icon-512-maskable.png"), renderIcon(512, true));
console.log("Generated PWA icons in", iconsDir);
