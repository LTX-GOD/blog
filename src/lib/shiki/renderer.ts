import { ExpressiveCodeEngine } from '@expressive-code/core';
import { toHtml } from 'hast-util-to-html';
import { pluginCollapsibleSections } from '@expressive-code/plugin-collapsible-sections';
import { pluginLineNumbers } from '@expressive-code/plugin-line-numbers';
import { pluginFrames } from '@expressive-code/plugin-frames';
import { pluginTextMarkers } from '@expressive-code/plugin-text-markers';
import { pluginCustomCopyButton } from '../../plugins/expressive-code/custom-copy-button.ts';
import { pluginLanguageBadge } from '../../plugins/expressive-code/language-badge.ts';
import { EC_DEFAULT_PROPS, EC_BASE_STYLE_OVERRIDES } from './ec-config';
import { getCodeHash } from './hash';
import { bundledThemes } from 'shiki';
import fs from 'node:fs';
import path from 'node:path';
import { normalizeCodeLanguage } from '../../utils/code-language';

const CACHE_DIR = path.join(process.cwd(), '.cache');
const CACHE_FILE = path.join(CACHE_DIR, 'shiki-cache.json');

// Ensure cache dir exists
if (!fs.existsSync(CACHE_DIR)) {
    try {
        fs.mkdirSync(CACHE_DIR, { recursive: true });
    } catch (e) {
        // ignore
    }
}

let cache = new Map<string, string>();

// Load cache
if (fs.existsSync(CACHE_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8'));
        cache = new Map(Object.entries(data));
    } catch (e) {
        // Ignore error
    }
}

function saveCache() {
    try {
        fs.writeFileSync(CACHE_FILE, JSON.stringify(Object.fromEntries(cache)), 'utf-8');
    } catch (e) {
        console.error('Failed to save shiki cache', e);
    }
}

// Save cache when process exits
process.on('exit', () => {
    saveCache();
});

let ec: ExpressiveCodeEngine | null = null;

async function getEc() {
    if (ec) return ec;

    // Load themes dynamically
    const githubLight = await bundledThemes['github-light']().then((m: any) => m.default || m);
    const githubDark = await bundledThemes['github-dark']().then((m: any) => m.default || m);

    ec = new ExpressiveCodeEngine({
        themes: [githubLight, githubDark],
        plugins: [
            pluginFrames(),
            pluginTextMarkers(),
            pluginCollapsibleSections(),
            pluginLineNumbers(),
            pluginLanguageBadge(),
            pluginCustomCopyButton(),
        ],
        defaultProps: EC_DEFAULT_PROPS,
        styleOverrides: EC_BASE_STYLE_OVERRIDES,
    });
    return ec;
}

export async function renderWithCache(code: string, lang: string, meta: string) {
    lang = normalizeCodeLanguage(lang) || 'text';

    const key = getCodeHash(code, lang, meta || '');

    if (cache.has(key)) {
        return cache.get(key)!;
    }

    const engine = await getEc();
    const result = await engine.render({
        code,
        language: lang,
        meta,
    });

    const html = toHtml(result.renderedGroupAst as any);

    cache.set(key, html);

    return html;
}
