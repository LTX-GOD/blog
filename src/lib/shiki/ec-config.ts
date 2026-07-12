export const EC_DEFAULT_PROPS = {
	wrap: true,
	overridesByLang: {
		shellsession: { showLineNumbers: false },
		bash: { frame: "code" as const },
		shell: { frame: "code" as const },
		sh: { frame: "code" as const },
		zsh: { frame: "code" as const },
	},
} as const;

export const EC_BASE_STYLE_OVERRIDES = {
	codeBackground: "var(--codeblock-bg)",
	borderRadius: "0.75rem",
	borderColor: "var(--codeblock-border)",
} as const;
