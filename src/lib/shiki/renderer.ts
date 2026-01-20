import { ExpressiveCodeEngine } from '@expressive-code/core';
import { toHtml } from 'hast-util-to-html';
import { pluginCollapsibleSections } from '@expressive-code/plugin-collapsible-sections';
import { pluginLineNumbers } from '@expressive-code/plugin-line-numbers';
import { pluginFrames } from '@expressive-code/plugin-frames';
import { pluginTextMarkers } from '@expressive-code/plugin-text-markers';
// @ts-ignore
import { pluginCustomCopyButton } from '../../plugins/expressive-code/custom-copy-button.ts';
// @ts-ignore
import { pluginLanguageBadge } from '../../plugins/expressive-code/language-badge.ts';
import { getCodeHash } from './hash';
import { bundledThemes } from 'shiki';
import fs from 'node:fs';
import path from 'node:path';

const CACHE_DIR = path.join(process.cwd(), 'node_modules', '.cache');
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
        defaultProps: {
            wrap: true,
            overridesByLang: {
                shellsession: { showLineNumbers: false },
                // @ts-ignore
                bash: { frame: 'code' },
                // @ts-ignore
                shell: { frame: 'code' },
                // @ts-ignore
                sh: { frame: 'code' },
                // @ts-ignore
                zsh: { frame: 'code' },
            },
        },
        styleOverrides: {
            codeBackground: "var(--codeblock-bg)",
            borderRadius: "0.75rem",
            borderColor: "none",
        }
    });
    return ec;
}

export async function renderWithCache(code: string, lang: string, meta: string) {
    // Handle aliases
    if (lang === 'nodejs' || lang === 'node') {
        lang = 'javascript';
    }

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
