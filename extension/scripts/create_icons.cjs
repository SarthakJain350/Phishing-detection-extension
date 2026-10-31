/**
 * Creates placeholder icon PNG files for the Chrome extension.
 * Run once with: node scripts/create_icons.cjs
 * Replace icons/ with real artwork before publishing.
 */
const fs = require("fs");
const path = require("path");

// Minimal valid 16x16 transparent PNG (base64-encoded)
const TRANSPARENT_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAADklEQVQ4jWNgGAWDEwAAAjAAAX5LKRYAAAAASUVORK5CYII=";

const iconsDir = path.join(__dirname, "..", "public", "icons");
fs.mkdirSync(iconsDir, { recursive: true });

const sizes = [16, 32, 48, 128];
for (const size of sizes) {
  const filePath = path.join(iconsDir, `icon${size}.png`);
  fs.writeFileSync(filePath, Buffer.from(TRANSPARENT_PNG_BASE64, "base64"));
  console.log(`Created ${filePath}`);
}
console.log("Done. Replace these placeholder icons before publishing.");
