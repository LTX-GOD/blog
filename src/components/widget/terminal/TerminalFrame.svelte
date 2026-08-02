<script lang="ts">
	import { onMount } from "svelte";

	export let lines: string[] = [];
	export let titleLabel = "visitor@zsm: ~";
	export let promptLabel = "visitor@zsm:~$";
	export let value = "";
	export let interactive = true;
	export let autoFocus = false;
	export let fullScreen = false;
	export let inputAriaLabel = "Terminal Input";
	export let onKeydown: (event: KeyboardEvent) => void = () => {};
	export let onReady: (api: { scrollToBottom: () => void; focus: () => void }) => void = () => {};
	export let panelClass = "";
	export let contentClass = "";

	let inputElement: HTMLInputElement | undefined;
	let contentElement: HTMLDivElement | undefined;

	$: frameClass = [
		"terminal-frame",
		"font-mono",
		"text-sm",
		"transition-colors",
		"duration-300",
		fullScreen
			? "terminal-frame-overlay"
			: "terminal-frame-inline hidden md:block w-full max-w-[var(--page-width)] mx-auto mb-8",
		panelClass,
	]
		.filter(Boolean)
		.join(" ");

	$: contentClassName = [
		"terminal-content",
		"p-4",
		"overflow-y-auto",
		"text-black/80",
		"dark:text-[#908caa]",
		"scrollbar-hide",
		fullScreen ? "h-[min(70vh,42rem)] sm:h-[min(72vh,44rem)]" : "h-64",
		contentClass,
	]
		.filter(Boolean)
		.join(" ");

	export function focusInput() {
		inputElement?.focus();
	}

	export function scrollToBottom() {
		if (contentElement) {
			contentElement.scrollTop = contentElement.scrollHeight;
		}
	}

	onMount(() => {
		onReady({
			scrollToBottom,
			focus: focusInput,
		});

		if (autoFocus && interactive) {
			inputElement?.focus();
		}
	});
</script>

<div class={frameClass} on:click={focusInput}>
	<div class="terminal-window rounded-xl overflow-hidden border border-black/5 dark:border-white/10 shadow-sm dark:shadow-2xl bg-white/50 dark:bg-[#191724]/90 backdrop-blur-md">
		<div class="flex items-center justify-between px-4 py-2 bg-black/5 dark:bg-[#1f1d2e]/90 border-b border-black/5 dark:border-white/10 transition-colors duration-300">
			<div class="flex gap-2">
				<div class="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
				<div class="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
				<div class="w-3 h-3 rounded-full bg-[#27c93f]"></div>
			</div>
			<div class="text-black/50 dark:text-[#908caa] text-xs">{titleLabel}</div>
			<div class="w-10"></div>
		</div>

		<div bind:this={contentElement} class={contentClassName}>
				{#each lines as line}
					<div class="whitespace-pre-wrap mb-1">{line}</div>
				{/each}

			{#if interactive}
				<div class="flex items-center">
					<span class="text-[var(--primary)] dark:text-[#c4a7e7] mr-2">
						{promptLabel}
					</span>
					<input
						bind:this={inputElement}
						bind:value
						on:keydown={onKeydown}
						type="text"
						aria-label={inputAriaLabel}
						class="bg-transparent border-none outline-none flex-grow text-black dark:text-[#e0def4] caret-[var(--primary)] dark:caret-[#c4a7e7]"
						autocomplete="off"
						spellcheck="false"
					/>
				</div>
				{/if}

				<slot />
		</div>
	</div>
</div>

<style>
	.terminal-frame-inline {
		cursor: text;
	}

	.terminal-frame-overlay {
		position: fixed;
		inset: 0;
		z-index: 120;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background:
			radial-gradient(circle at top, rgba(59, 130, 246, 0.2), transparent 35%),
			linear-gradient(180deg, rgba(2, 6, 23, 0.96), rgba(2, 6, 23, 0.99));
	}

	.terminal-frame-overlay .terminal-window {
		width: min(100%, 72rem);
	}

	.scrollbar-hide::-webkit-scrollbar {
		display: none;
	}

	.scrollbar-hide {
		-ms-overflow-style: none;
		scrollbar-width: none;
	}
</style>
