<script lang="ts">
export type ClientIconName =
	| "search"
	| "search-off"
	| "close"
	| "list"
	| "pin"
	| "sun"
	| "moon"
	| "subdirectory-arrow-left"
	| "arrow-rotate-left"
	| "article";

export let name: ClientIconName;
export let className = "";
export let ariaLabel: string | undefined = undefined;
</script>

<svg
	xmlns="http://www.w3.org/2000/svg"
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-label={ariaLabel}
	aria-hidden={ariaLabel ? undefined : "true"}
>
	{#if name === "search"}
		<circle cx="11" cy="11" r="7" />
		<path d="m20 20-3.5-3.5" />
	{:else if name === "search-off"}
		<circle cx="11" cy="11" r="7" />
		<path d="m20 20-3.5-3.5" />
		<path d="M4 4l16 16" />
	{:else if name === "close"}
		<path d="M6 6l12 12" />
		<path d="M18 6L6 18" />
	{:else if name === "list"}
		<path d="M9 6h11" />
		<path d="M9 12h11" />
		<path d="M9 18h11" />
		<path d="M4 6h.01" />
		<path d="M4 12h.01" />
		<path d="M4 18h.01" />
	{:else if name === "pin"}
		<path d="m14 4 6 6-4 1-3 7-2-2 2-5-3-3z" />
		<path d="M8 14l-4 6" />
	{:else if name === "sun"}
		<circle cx="12" cy="12" r="4" />
		<path d="M12 2v2.5" />
		<path d="M12 19.5V22" />
		<path d="m4.93 4.93 1.77 1.77" />
		<path d="m17.3 17.3 1.77 1.77" />
		<path d="M2 12h2.5" />
		<path d="M19.5 12H22" />
		<path d="m4.93 19.07 1.77-1.77" />
		<path d="m17.3 6.7 1.77-1.77" />
	{:else if name === "moon"}
		<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8" />
	{:else if name === "subdirectory-arrow-left"}
		<path d="M21 5v6a2 2 0 0 1-2 2H9" />
		<path d="m9 16-4-4 4-4" />
	{:else if name === "arrow-rotate-left"}
		<path d="M3 12a9 9 0 1 0 3-6.7" />
		<path d="M3 4v4h4" />
	{:else if name === "article"}
		<path d="M7 4h10l2 2v14H5V4z" />
		<path d="M15 4v4h4" />
		<path d="M8 12h8" />
		<path d="M8 16h6" />
	{/if}
</svg>
