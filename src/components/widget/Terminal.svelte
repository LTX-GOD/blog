<script lang="ts">
    import { onMount, tick } from 'svelte';

    let inputElement: HTMLInputElement;
    let mounted = false;
    let history: string[] = [
        "Welcome to Zsm's Blog Terminal v1.0.0",
        "Type 'help' to see available commands.",
    ];
    let inputValue = "";
    let commandHistory: string[] = [];
    let historyIndex = -1;

    const commands: Record<string, (args: string[]) => string | void> = {
        help: () => `Available commands:
  ls        List pages
  cat       View page content (e.g., cat about.md)
  whoami    Display visitor info
  date      Show current date
  clear     Clear terminal
  uname     System info
  rm        Exit browser (Dangerous!)`,
        ls: () => `about.md
friends.md
archive/
posts/
projects/`,
        cat: (args) => {
            const file = args[0];
            if (!file) return "Usage: cat [filename]";
            switch (file) {
                case 'about.md':
                    window.location.href = '/about/';
                    return "Navigating to /about/...";
                case 'friends.md':
                    window.location.href = '/friends/';
                    return "Navigating to /friends/...";
                case 'archive/':
                    window.location.href = '/archive/';
                    return "Navigating to /archive/...";
                case 'posts/':
                    window.location.href = '/archive/'; // Assuming posts list is in archive
                    return "Navigating to /archive/...";
                case 'projects/':
                    window.location.href = '/projects/';
                    return "Navigating to /projects/...";
                default:
                    return `cat: ${file}: No such file or directory`;
            }
        },
        whoami: () => `visitor@${navigator.userAgent}`,
        date: () => new Date().toString(),
        clear: () => {
            history = [];
            return "";
        },
        uname: () => "Linux zsm-blog 5.15.0-generic #1 SMP x86_64 GNU/Linux",
        rm: (args) => {
            // Try to close the window
            window.close();
            
            // Fallback: Redirect to about:blank or show a crash message
            // Since window.close() is often blocked, we simulate a crash/exit
            document.body.innerHTML = ""; // Clear the page content
            document.body.style.backgroundColor = "black"; // Set background to black
            
            // Optional: Redirect to blank page after a short delay if close fails
            setTimeout(() => {
                window.location.href = "about:blank";
            }, 500);
            
            return "System halting...";
        },
    };

    function handleKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter') {
            const commandLine = inputValue.trim();
            if (commandLine) {
                history = [...history, `visitor@zsm:~$ ${commandLine}`];
                commandHistory.push(commandLine);
                historyIndex = commandHistory.length;
                
                const [cmd, ...args] = commandLine.split(' ');
                if (commands[cmd]) {
                    const output = commands[cmd](args);
                    if (output) {
                        history = [...history, output];
                    }
                } else {
                    history = [...history, `bash: ${cmd}: command not found`];
                }
            } else {
                history = [...history, `visitor@zsm:~$ `];
            }
            inputValue = "";
            tick().then(() => {
                const terminalContent = document.getElementById('terminal-content');
                if (terminalContent) terminalContent.scrollTop = terminalContent.scrollHeight;
            });
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                inputValue = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                inputValue = commandHistory[historyIndex];
            } else {
                historyIndex = commandHistory.length;
                inputValue = "";
            }
        }
    }

    onMount(() => {
        mounted = true;
        tick().then(() => {
            if (inputElement) inputElement.focus();
        });
    });
</script>

<div class="hidden md:block w-full max-w-[var(--page-width)] mx-auto mb-8 rounded-xl overflow-hidden bg-white/50 dark:bg-[#1a1b26]/90 backdrop-blur-md border border-black/5 dark:border-white/10 shadow-sm dark:shadow-2xl font-mono text-sm transition-colors duration-300" on:click={() => mounted && inputElement?.focus()}>
    <div class="flex items-center justify-between px-4 py-2 bg-black/5 dark:bg-[#1f2335]/90 border-b border-black/5 dark:border-white/10 transition-colors duration-300">
        <div class="flex gap-2">
            <div class="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
            <div class="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
            <div class="w-3 h-3 rounded-full bg-[#27c93f]"></div>
        </div>
        <div class="text-black/50 dark:text-[#a9b1d6] text-xs">visitor@zsm: ~</div>
        <div class="w-10"></div> <!-- Spacer for centering -->
    </div>
    <div id="terminal-content" class="p-4 h-64 overflow-y-auto text-black/80 dark:text-[#a9b1d6] scrollbar-hide">
        {#each history as line}
            <div class="whitespace-pre-wrap mb-1">{line}</div>
        {/each}
        <div class="flex items-center">
            <span class="text-[var(--primary)] dark:text-[#7aa2f7] mr-2">visitor@zsm:~$</span>
            <input
                bind:this={inputElement}
                bind:value={inputValue}
                on:keydown={handleKeydown}
                type="text"
                aria-label="Terminal Input"
                class="bg-transparent border-none outline-none flex-grow text-black dark:text-[#c0caf5] caret-[var(--primary)] dark:caret-[#7aa2f7]"
                autocomplete="off"
                spellcheck="false"
            />
        </div>
    </div>
</div>

<style>
    .scrollbar-hide::-webkit-scrollbar {
        display: none;
    }
    .scrollbar-hide {
        -ms-overflow-style: none;
        scrollbar-width: none;
    }
</style>
