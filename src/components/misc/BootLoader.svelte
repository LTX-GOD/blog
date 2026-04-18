<script lang="ts">
	import { onMount } from "svelte";
	import BootLoaderPanel from "./bootloader/BootLoaderPanel.svelte";
	import {
		BOOT_MESSAGES,
		ensureBootLoaderCompletedState,
		hasCompletedBootLoaderInSession,
		markBootLoaderComplete,
	} from "./bootloader/bootloader-state";

	export let enabled = true;
	export let lineInterval = 88;
	export let finishDelay = 520;

	let visible = enabled;
	let logs: string[] = enabled ? [BOOT_MESSAGES[0]] : [];
	let showSkip = false;
	let finished = false;

	function unlockPage() {
		if (finished) return;
		finished = true;
		markBootLoaderComplete();
		setTimeout(() => {
			visible = false;
		}, 220);
	}

	async function runBootSequence() {
		for (const message of BOOT_MESSAGES.slice(logs.length)) {
			logs = [...logs, message];
			await new Promise((resolve) => setTimeout(resolve, lineInterval));
			if (finished) {
				return;
			}
		}

		await new Promise((resolve) => setTimeout(resolve, finishDelay));
		unlockPage();
	}

	function skipBootSequence() {
		unlockPage();
	}

	onMount(() => {
		if (!enabled) {
			visible = false;
			return;
		}

		if (hasCompletedBootLoaderInSession()) {
			ensureBootLoaderCompletedState();
			visible = false;
			return;
		}

		if (!document.documentElement.classList.contains("boot-loader-active")) {
			visible = false;
			return;
		}

		showSkip = true;

		const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
		if (reducedMotion.matches) {
			logs = BOOT_MESSAGES;
			setTimeout(unlockPage, 120);
			return;
		}

		void runBootSequence();

		const handleKeydown = (event: KeyboardEvent) => {
			if (event.key === "Enter" || event.key === "Escape" || event.key === " ") {
				event.preventDefault();
				skipBootSequence();
			}
		};

		window.addEventListener("keydown", handleKeydown);

		return () => {
			window.removeEventListener("keydown", handleKeydown);
		};
	});
</script>

{#if visible}
	<BootLoaderPanel lines={logs} showSkip={showSkip} onSkip={skipBootSequence} />
{/if}
