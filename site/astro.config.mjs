// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const SITE = 'https://gadzhovski.github.io';
const BASE = '/TRACE-Forensic-Toolkit';
const REPO = 'https://github.com/Gadzhovski/TRACE-Forensic-Toolkit';
const OG_IMAGE = `${SITE}${BASE}/og.png`;

// Tells search engines this is an application, with what it runs on and
// what it costs -- the facts Google can show beside a result.
const SOFTWARE = {
	'@context': 'https://schema.org',
	'@type': 'SoftwareApplication',
	name: 'TRACE',
	alternateName: 'Toolkit for Retrieval and Analysis of Cyber Evidence',
	description:
		'Open-source digital forensics software for disk images: cases, triage, file carving, timelines, search, YARA and Sigma.',
	applicationCategory: 'SecurityApplication',
	operatingSystem: 'Windows, macOS, Linux',
	softwareVersion: '2.0.0',
	license: 'https://opensource.org/licenses/MIT',
	offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
	url: `${SITE}${BASE}/`,
	downloadUrl: `${REPO}/releases/latest`,
	codeRepository: REPO,
	image: OG_IMAGE,
	author: { '@type': 'Person', name: 'Radoslav Gadzhovski' },
};

export default defineConfig({
	site: SITE,
	base: BASE,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'TRACE',
			description:
				'TRACE is open-source digital forensics software for disk images: cases, triage, file carving, timelines, full-text search, YARA and Sigma -- on Windows, macOS and Linux.',
			logo: { src: './src/assets/repo/logo.png', alt: 'TRACE' },
			favicon: '/favicon.png',
			social: [{ icon: 'github', label: 'TRACE on GitHub', href: REPO }],
			editLink: { baseUrl: `${REPO}/edit/master/site/` },
			lastUpdated: true,
			customCss: [
				'@fontsource-variable/inter',
				'@fontsource-variable/jetbrains-mono',
				'./src/styles/theme.css',
			],
			components: {
				Footer: './src/components/SiteFooter.astro',
			},
			head: [
				{ tag: 'meta', attrs: { property: 'og:image', content: OG_IMAGE } },
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1280' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '640' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
				{ tag: 'meta', attrs: { name: 'twitter:image', content: OG_IMAGE } },
				{
					tag: 'meta',
					attrs: {
						name: 'keywords',
						content:
							'digital forensics, DFIR, forensic software, disk image analysis, E01, AFF4, file carving, data recovery, incident response, YARA, Sigma, open source',
					},
				},
				{ tag: 'script', attrs: { type: 'application/ld+json' }, content: JSON.stringify(SOFTWARE) },
			],
			sidebar: [
				{
					label: 'Get started',
					items: [
						{ label: 'Download', slug: 'start/download' },
						{ label: 'Install from source', slug: 'start/install' },
						{ label: 'Your first case', slug: 'start/first-case' },
						{ label: 'Quick triage', slug: 'start/quick-triage' },
					],
				},
				{
					label: 'Features',
					items: [
						{ label: 'Cases and integrity', slug: 'features/cases' },
						{ label: 'Triage and analysis', slug: 'features/triage' },
						{ label: 'File carving', slug: 'features/carving' },
						{ label: 'User activity and timeline', slug: 'features/activity' },
						{ label: 'Search and indicators', slug: 'features/search' },
						{ label: 'Detection: YARA, Sigma, keywords', slug: 'features/detection' },
						{ label: 'Viewers', slug: 'features/viewers' },
						{ label: 'Volumes and encryption', slug: 'features/volumes' },
						{ label: 'Reports', slug: 'features/reports' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Supported evidence', slug: 'reference/evidence' },
						{ label: 'Artifacts parsed', slug: 'reference/artifacts' },
						{ label: 'Where TRACE keeps data', slug: 'reference/data' },
					],
				},
				{
					label: 'Quality',
					items: [
						{ label: 'Testing and validation', slug: 'quality/testing' },
						{ label: 'Forensic soundness', slug: 'quality/soundness' },
						{ label: 'Building the app', slug: 'quality/building' },
					],
				},
				{ label: 'FAQ', slug: 'faq' },
			],
		}),
	],
});
