// Copies the pictures the site shares with the repository -- the README
// screenshots, the logo, the social preview -- into the site before a build,
// so they are stored once, in Icons/, and never drift apart. The copies are
// gitignored (src/assets/repo/, public/og.png, public/favicon.png).
//
// The favicon is shown tiny, so it is made small here (sharp) rather than
// shipping the 270 KB original. The header logo goes through <Image> in
// components/SiteTitle.astro.
import { copyFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const icons = join(site, '..', 'Icons');
const screens = join(site, 'src', 'assets', 'repo');
const logo = join(icons, 'logo_prev_ui.png');

mkdirSync(screens, { recursive: true });
mkdirSync(join(site, 'public'), { recursive: true });
for (const name of readdirSync(join(icons, 'readme'))) {
	if (name.endsWith('.png')) copyFileSync(join(icons, 'readme', name), join(screens, name));
}
copyFileSync(logo, join(screens, 'logo.png'));
copyFileSync(join(icons, 'social-preview.png'), join(site, 'public', 'og.png'));

await sharp(logo).resize(64, 64).png({ compressionLevel: 9, palette: true }).toFile(join(site, 'public', 'favicon.png'));

console.log('sync-assets: screenshots, logo and social preview copied from Icons/');
