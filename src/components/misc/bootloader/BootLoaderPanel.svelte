<script lang="ts">
	import BootLoaderLine from "./BootLoaderLine.svelte";

	export let lines: string[] = [];
	export let showSkip = false;
	export let onSkip: () => void = () => {};
</script>

<div class="boot-loader-overlay" role="dialog" aria-label="Boot Loader" aria-modal="true">
	<div class="boot-loader-panel">
		<div class="boot-loader-header">
			<div class="boot-loader-title">boot@zsm-blog: system-init</div>
			{#if showSkip}
				<button
					type="button"
					class="boot-loader-skip"
					aria-label="Skip boot loader"
					on:click={onSkip}
				>
					Skip
				</button>
			{/if}
		</div>

		<div class="boot-loader-body">
			<div class="boot-loader-leading-line">Booting ZSM OS v1.0...</div>
			{#each lines as line}
				<BootLoaderLine line={line} />
			{/each}
			<div class="boot-loader-cursor">_</div>
		</div>
	</div>
</div>

<style>
	.boot-loader-overlay {
		position: fixed;
		inset: 0;
		z-index: 160;
		background:
			radial-gradient(circle at top right, rgba(34, 197, 94, 0.12), transparent 24%),
			linear-gradient(180deg, rgba(2, 6, 23, 0.985), rgba(0, 0, 0, 1));
	}

	.boot-loader-panel {
		width: 100%;
		height: 100%;
		display: flex;
		flex-direction: column;
		background:
			linear-gradient(180deg, rgba(15, 23, 42, 0.18), rgba(15, 23, 42, 0)),
			transparent;
	}

	.boot-loader-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		padding: 1rem 1.5rem 0;
	}

	.boot-loader-title {
		font-size: 0.78rem;
		letter-spacing: 0.16em;
		text-transform: uppercase;
		color: rgba(148, 163, 184, 0.7);
	}

	.boot-loader-skip {
		border: 1px solid rgba(148, 163, 184, 0.18);
		border-radius: 999px;
		padding: 0.35rem 0.75rem;
		font-size: 0.75rem;
		color: rgba(226, 232, 240, 0.9);
		background: rgba(255, 255, 255, 0.04);
		transition:
			background-color 0.2s ease,
			border-color 0.2s ease;
	}

	.boot-loader-skip:hover {
		background: rgba(255, 255, 255, 0.08);
		border-color: rgba(226, 232, 240, 0.34);
	}

	.boot-loader-body {
		flex: 1;
		padding: 1rem 1.5rem 2rem;
		overflow-y: auto;
		font-family: "JetBrains Mono", "Fira Code", "SFMono-Regular", monospace;
		scrollbar-width: none;
	}

	.boot-loader-body::-webkit-scrollbar {
		display: none;
	}

	.boot-loader-leading-line {
		margin-bottom: 1rem;
		font-size: 0.92rem;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: rgba(148, 163, 184, 0.76);
	}

	.boot-loader-cursor {
		display: inline-block;
		margin-top: 0.25rem;
		color: #e2e8f0;
		animation: boot-loader-blink 1s step-end infinite;
	}

	@keyframes boot-loader-blink {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0;
		}
	}

	@media (max-width: 768px) {
		.boot-loader-header {
			padding: 0.85rem 1rem 0;
		}

		.boot-loader-title {
			font-size: 0.65rem;
			letter-spacing: 0.12em;
		}

		.boot-loader-body {
			padding: 0.85rem 1rem 1.5rem;
		}

		.boot-loader-leading-line {
			font-size: 0.75rem;
		}
	}
</style>
