<script lang="ts">
	export let line = "";
</script>

<div class="boot-loader-line">
	{#if line.startsWith("[  OK  ]")}
		<span class="boot-loader-ok">[  OK  ]</span>
		{line.substring(9)}
	{:else}
		{line}
	{/if}
</div>

<style>
	.boot-loader-line {
		margin-bottom: 0.25rem;
		white-space: pre-wrap;
		font-size: 0.95rem;
		line-height: 1.6;
		color: rgba(255, 255, 255, 0.9);
	}

	.boot-loader-ok {
		margin-right: 0.35rem;
		color: #4ade80;
		font-weight: 700;
	}

	@media (max-width: 768px) {
		.boot-loader-line {
			font-size: 0.8rem;
		}
	}
</style>
