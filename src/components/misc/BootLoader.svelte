<script lang="ts">
    import { onMount } from 'svelte';
    import { fade } from 'svelte/transition';

    let visible = false;
    let logs: string[] = [];
    let logContainer: HTMLElement;

    const bootMessages = [
        "[  OK  ] Started Show Plymouth Boot Screen.",
        "[  OK  ] Reached target Paths.",
        "[  OK  ] Reached target Basic System.",
        "[  OK  ] Found device /dev/zsm-blog.",
        "[  OK  ] Mounted /boot/efi.",
        "[  OK  ] Started File System Check on /dev/disk/by-uuid/ASTR-0001.",
        "[  OK  ] Started Journal Service.",
        "[  OK  ] Started Network Name Resolution.",
        "[  OK  ] Reached target Network.",
        "[  OK  ] Reached target System Initialization.",
        "[  OK  ] Started Daily Cleanup of Temporary Directories.",
        "[  OK  ] Started CUPS Scheduler.",
        "[  OK  ] Listening on D-Bus System Message Bus Socket.",
        "[  OK  ] Reached target Sockets.",
        "[  OK  ] Reached target Timers.",
        "[  OK  ] Started Astro Content Layer Service.",
        "[  OK  ] Loaded 1024MB of Creativity...",
        "[  OK  ] Started React Frontend Service...",
        "[  OK  ] Started Tailwind CSS Engine...",
        "[  OK  ] Reached target Graphical Interface.",
        "Welcome to ZSM OS v1.0!"
    ];

    onMount(() => {
        const hasVisited = sessionStorage.getItem('zsm-boot-sequence');
        if (!hasVisited) {
            visible = true;
            runBootSequence();
        }
    });

    async function runBootSequence() {
        for (const msg of bootMessages) {
            await new Promise(r => setTimeout(r, Math.random() * 100 + 50));
            logs = [...logs, msg];
            if (logContainer) {
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        }
        
        await new Promise(r => setTimeout(r, 800));
        visible = false;
        sessionStorage.setItem('zsm-boot-sequence', 'true');
    }
</script>

{#if visible}
    <div class="boot-loader" out:fade={{ duration: 500 }}>
        <div class="log-container" bind:this={logContainer}>
            {#each logs as log}
                <div class="log-line">
                    {#if log.startsWith('[  OK  ]')}
                        <span class="text-green-500 font-bold">[  OK  ]</span> {log.substring(9)}
                    {:else}
                        {log}
                    {/if}
                </div>
            {/each}
            <div class="cursor-blink">_</div>
        </div>
    </div>
{/if}

<style>
    .boot-loader {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background-color: #000;
        z-index: 9999;
        padding: 2rem;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        color: #fff;
        overflow: hidden;
        pointer-events: none; /* Allow clicks to pass through if it gets stuck */
    }

    .log-container {
        height: 100%;
        overflow-y: auto;
        scrollbar-width: none; /* Firefox */
    }
    
    .log-container::-webkit-scrollbar {
        display: none; /* Chrome/Safari */
    }

    .log-line {
        margin-bottom: 0.25rem;
        white-space: pre-wrap;
        font-size: 14px;
        line-height: 1.5;
    }

    .cursor-blink {
        display: inline-block;
        animation: blink 1s step-end infinite;
        color: #fff;
    }

    @keyframes blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0; }
    }
    
    /* Mobile optimization */
    @media (max-width: 768px) {
        .boot-loader {
            padding: 1rem;
        }
        .log-line {
            font-size: 12px;
        }
    }
</style>
