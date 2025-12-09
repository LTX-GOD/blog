<script lang="ts">
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import Icon from "@iconify/svelte";
import { url } from "@utils/url-utils.ts";
import { onMount } from "svelte";
import type { SearchResult } from "@/global";
import { navigateToPage } from "@utils/navigation-utils";

let keyword = "";
let result: SearchResult[] = [];
let isSearching = false;
let pagefindLoaded = false;
let initialized = false;
let searchInput: HTMLInputElement;
let isOpen = false;

const fakeResult: SearchResult[] = [
	{
		url: url("/"),
		meta: {
			title: "This Is a Fake Search Result",
		},
		excerpt:
			"Because the search cannot work in the <mark>dev</mark> environment.",
	},
	{
		url: url("/"),
		meta: {
			title: "If You Want to Test the Search",
		},
		excerpt: "Try running <mark>npm build && npm preview</mark> instead.",
	},
];

const openSearch = () => {
	isOpen = true;
	setTimeout(() => {
		searchInput?.focus();
	}, 100);
	document.body.style.overflow = "hidden";
};

const closeSearch = () => {
	isOpen = false;
	keyword = "";
	result = [];
	document.body.style.overflow = "";
};

const handleKeydown = (e: KeyboardEvent) => {
	if ((e.metaKey || e.ctrlKey) && e.key === "k") {
		e.preventDefault();
		if (isOpen) {
			closeSearch();
		} else {
			openSearch();
		}
	}
	if (e.key === "Escape" && isOpen) {
		closeSearch();
	}
};

const handleResultClick = (event: Event, url: string): void => {
	event.preventDefault();
	closeSearch();
	navigateToPage(url);
};

const search = async (kw: string): Promise<void> => {
	if (!kw) {
		result = [];
		return;
	}

	if (!initialized) {
		return;
	}

	isSearching = true;

	try {
		let searchResults: SearchResult[] = [];

		if (import.meta.env.PROD && pagefindLoaded && window.pagefind) {
			const response = await window.pagefind.search(kw);
			searchResults = await Promise.all(
				response.results.map((item) => item.data()),
			);
		} else if (import.meta.env.DEV) {
			searchResults = fakeResult;
		} else {
			searchResults = [];
			console.error("Pagefind is not available in production environment.");
		}

		result = searchResults;
	} catch (error) {
		console.error("Search error:", error);
		result = [];
	} finally {
		isSearching = false;
	}
};

onMount(() => {
	const initializeSearch = () => {
		initialized = true;
		pagefindLoaded =
			typeof window !== "undefined" &&
			!!window.pagefind &&
			typeof window.pagefind.search === "function";
		console.log("Pagefind status on init:", pagefindLoaded);
	};

	if (import.meta.env.DEV) {
		console.log(
			"Pagefind is not available in development mode. Using mock data.",
		);
		initializeSearch();
	} else {
		document.addEventListener("pagefindready", () => {
			console.log("Pagefind ready event received.");
			initializeSearch();
		});
		document.addEventListener("pagefindloaderror", () => {
			console.warn(
				"Pagefind load error event received. Search functionality will be limited.",
			);
			initializeSearch();
		});

		setTimeout(() => {
			if (!initialized) {
				console.log("Fallback: Initializing search after timeout.");
				initializeSearch();
			}
		}, 2000);
	}

	window.addEventListener("keydown", handleKeydown);
	return () => {
		window.removeEventListener("keydown", handleKeydown);
	};
});

$: if (initialized && keyword) {
	(async () => {
		await search(keyword);
	})();
}
</script>

<!-- Search Trigger Button (Desktop) -->
<button on:click={openSearch} class="hidden lg:flex items-center h-10 mr-2 rounded-[var(--radius-large)]
      bg-black/[0.04] hover:bg-black/[0.06]
      dark:bg-white/5 dark:hover:bg-white/10
      px-3 gap-2 transition-colors group
">
    <span class="text-sm font-mono text-[var(--primary)] group-hover:text-[var(--link-hover)] transition-colors">>_</span>
    <span class="text-sm font-mono text-black/50 dark:text-white/50 group-hover:text-[var(--primary)] transition-colors">Search...</span>
    <span class="text-[10px] font-mono border border-black/10 dark:border-white/10 rounded px-1.5 py-0.5 text-black/30 dark:text-white/30 ml-2">⌘K</span>
</button>

<!-- Search Trigger Button (Mobile) -->
<button on:click={openSearch} aria-label="Search Panel"
        class="btn-plain scale-animation lg:!hidden rounded-[var(--radius-large)] w-10 h-10 active:scale-90">
    <Icon icon="material-symbols:search" class="text-[1.25rem]"></Icon>
</button>

<!-- Telescope Modal -->
{#if isOpen}
<div class="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh] px-4">
    <!-- Backdrop -->
    <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" on:click={closeSearch}></div>

    <!-- Modal Window -->
    <div class="relative w-full max-w-2xl bg-[var(--float-panel-bg)] rounded-[var(--radius-large)] shadow-2xl overflow-hidden border border-[var(--primary)]/30 flex flex-col max-h-[70vh]">
        
        <!-- Prompt Bar -->
        <div class="flex items-center px-4 py-3 border-b border-[var(--primary)]/20 bg-[var(--card-bg)]">
            <Icon icon="material-symbols:search" class="text-[var(--primary)] text-xl mr-3" />
            <span class="text-[var(--primary)] mr-2 font-bold">Telescope</span>
            <span class="text-[var(--content-meta)] mr-2">></span>
            <input 
                bind:this={searchInput}
                bind:value={keyword}
                placeholder="Find files..." 
                aria-label="Search"
                class="flex-1 bg-transparent border-none outline-none text-[var(--deep-text)] placeholder-[var(--content-meta)] font-mono text-base h-full"
                autocomplete="off"
            />
            <button on:click={closeSearch} class="text-[var(--content-meta)] hover:text-[var(--deep-text)] transition-colors">
                <span class="text-xs">ESC</span>
            </button>
        </div>

        <!-- Results List -->
        <div class="overflow-y-auto flex-1 p-2 scrollbar-hide">
            {#if result.length > 0}
                {#each result as item}
                    <a href={item.url}
                       on:click={(e) => handleResultClick(e, item.url)}
                       class="group flex flex-col px-3 py-2 rounded-[4px] hover:bg-[var(--btn-plain-bg-hover)] transition-colors mb-1">
                        <div class="flex items-center justify-between">
                            <span class="text-[var(--primary)] font-mono text-sm group-hover:text-[var(--link-hover)] transition-colors">
                                {item.meta.title}
                            </span>
                            <Icon icon="material-symbols:subdirectory-arrow-left" class="text-[var(--content-meta)] opacity-0 group-hover:opacity-100 transition-opacity text-xs" />
                        </div>
                        <div class="text-[var(--content-meta)] text-xs mt-1 font-mono truncate pl-4 border-l-2 border-[var(--content-meta)]/30 group-hover:border-[var(--primary)]/50 transition-colors">
                            {@html item.excerpt}
                        </div>
                    </a>
                {/each}
            {:else if keyword}
                <div class="flex flex-col items-center justify-center py-12 text-[var(--content-meta)]">
                    <Icon icon="material-symbols:search-off" class="text-4xl mb-2 opacity-50" />
                    <span class="font-mono text-sm">No results found for "{keyword}"</span>
                </div>
            {:else}
                <div class="flex flex-col items-center justify-center py-12 text-[var(--content-meta)]">
                    <div class="flex gap-4 mb-4">
                        <div class="flex flex-col items-center gap-1">
                            <span class="px-2 py-1 rounded bg-[var(--btn-regular-bg)] text-xs font-mono border border-[var(--line-divider)]">Type</span>
                            <span class="text-[10px]">to search</span>
                        </div>
                        <div class="flex flex-col items-center gap-1">
                            <span class="px-2 py-1 rounded bg-[var(--btn-regular-bg)] text-xs font-mono border border-[var(--line-divider)]">↑↓</span>
                            <span class="text-[10px]">to navigate</span>
                        </div>
                        <div class="flex flex-col items-center gap-1">
                            <span class="px-2 py-1 rounded bg-[var(--btn-regular-bg)] text-xs font-mono border border-[var(--line-divider)]">ESC</span>
                            <span class="text-[10px]">to close</span>
                        </div>
                    </div>
                </div>
            {/if}
        </div>
        
        <!-- Status Line -->
        <div class="px-4 py-1 bg-[var(--card-bg)] border-t border-[var(--primary)]/20 flex justify-between items-center text-[10px] text-[var(--content-meta)] font-mono">
            <span>{result.length} results</span>
            <span>{keyword ? 'searching...' : 'ready'}</span>
        </div>
    </div>
</div>
{/if}

<style>
    .scrollbar-hide::-webkit-scrollbar {
        display: none;
    }
    .scrollbar-hide {
        -ms-overflow-style: none;
        scrollbar-width: none;
    }
</style>
