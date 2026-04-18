const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
	js: "javascript",
	cjs: "javascript",
	mjs: "javascript",
	jsx: "javascript",
	ts: "typescript",
	tsx: "typescript",
	py: "python",
	sh: "bash",
	bash: "bash",
	zsh: "bash",
	yml: "yaml",
	yaml: "yaml",
	json: "json",
};

const LANGUAGE_ALIASES: Record<string, string> = {
	node: "javascript",
	nodejs: "javascript",
	conf: "ini",
	dockerfile: "dockerfile",
	shell: "bash",
	shellscript: "bash",
};

function normalizeByExtension(lang: string) {
	const match = lang.match(/\.([a-z0-9]+)$/i);
	if (!match) {
		return undefined;
	}
	return EXTENSION_LANGUAGE_MAP[match[1].toLowerCase()];
}

export function normalizeCodeLanguage(lang?: string | null) {
	if (!lang) {
		return lang ?? undefined;
	}

	const trimmed = lang.trim();
	if (!trimmed) {
		return undefined;
	}

	const lowered = trimmed.toLowerCase();
	if (
		lowered.startsWith("#kali") ||
		trimmed.includes("┌──(") ||
		trimmed.includes("kali㉿")
	) {
		return "shellsession";
	}

	if (LANGUAGE_ALIASES[lowered]) {
		return LANGUAGE_ALIASES[lowered];
	}

	const byExtension = normalizeByExtension(trimmed);
	if (byExtension) {
		return byExtension;
	}

	return lowered;
}
