<script lang="ts">
	import { onMount } from "svelte";
	import TerminalFrame from "./terminal/TerminalFrame.svelte";

	const INTRO_LINES = [
		"visitor@zsm:~$ whoami",
		"guest@zsm-blog",
		"visitor@zsm:~$ ls",
		"about.md  archive/  friends.md  posts/  projects/",
		"visitor@zsm:~$ ./boot-blog",
		"[  OK  ] Loading navigation modules...",
		"[  OK  ] Restoring theme settings...",
		"[  OK  ] Preparing post index...",
		"[  OK  ] Launching main interface...",
	];

	export let enabled = true;
	export let lineInterval = 120;
	export let finishDelay = 420;

	let lines: string[] = enabled ? [INTRO_LINES[0]] : [];
	let visible = enabled;
	let skipHintVisible = false;
	let finished = false;

	function unlockPage() {
		if (finished) return;
		finished = true;
		document.documentElement.classList.remove("terminal-intro-active");
		document.documentElement.classList.add("terminal-intro-complete");
		setTimeout(() => {
			visible = false;
		}, 260);
	}

	async function playIntro() {
		for (const line of INTRO_LINES.slice(lines.length)) {
			lines = [...lines, line];
			await new Promise((resolve) => setTimeout(resolve, lineInterval));
			if (finished) {
				return;
			}
		}

		await new Promise((resolve) => setTimeout(resolve, finishDelay));
		unlockPage();
	}

	function skipIntro() {
		unlockPage();
	}

	onMount(() => {
		if (!enabled || !document.documentElement.classList.contains("terminal-intro-active")) {
			visible = false;
			return;
		}

		skipHintVisible = true;

		const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
		if (reducedMotion.matches) {
			lines = INTRO_LINES;
			setTimeout(unlockPage, 120);
			return;
		}

		void playIntro();

		const handleKeydown = (event: KeyboardEvent) => {
			if (event.key === "Enter" || event.key === "Escape" || event.key === " ") {
				event.preventDefault();
				skipIntro();
			}
		};

		window.addEventListener("keydown", handleKeydown);

		return () => {
			window.removeEventListener("keydown", handleKeydown);
		};
	});
</script>

{#if visible}
	<div
		class="terminal-intro-overlay"
		role="dialog"
		aria-label="Terminal Intro"
		aria-modal="true"
		on:click={skipIntro}
	>
		<div class="terminal-intro-shell" on:click|stopPropagation>
			<TerminalFrame
				lines={lines}
				fullScreen={true}
				interactive={false}
				titleLabel="visitor@zsm: ~"
				panelClass="terminal-intro-panel"
				contentClass="terminal-intro-content"
			>
				<div class="mt-4 flex items-center justify-between gap-4 text-xs text-white/55">
					<span class="tracking-[0.18em] uppercase">Initializing zsm-blog</span>
					{#if skipHintVisible}
						<button
							type="button"
							class="terminal-intro-skip"
							aria-label="Skip terminal intro"
							on:click={skipIntro}
						>
							Skip
						</button>
					{/if}
				</div>
			</TerminalFrame>
		</div>
	</div>
{/if}

<style>
	.terminal-intro-overlay {
		opacity: 0;
		pointer-events: none;
		transition: opacity 0.25s ease;
	}

	:global(html.terminal-intro-active) .terminal-intro-overlay {
		opacity: 1;
		pointer-events: auto;
	}

	.terminal-intro-shell {
		width: 100%;
	}

	.terminal-intro-skip {
		border: 1px solid rgba(255, 255, 255, 0.14);
		border-radius: 999px;
		padding: 0.35rem 0.75rem;
		color: rgba(255, 255, 255, 0.82);
		background: rgba(255, 255, 255, 0.04);
		transition:
			background-color 0.2s ease,
			border-color 0.2s ease,
			color 0.2s ease;
	}

	.terminal-intro-skip:hover {
		background: rgba(255, 255, 255, 0.08);
		border-color: rgba(255, 255, 255, 0.28);
		color: white;
	}
</style>
