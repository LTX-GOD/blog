<script lang="ts">
    import { tick } from 'svelte';
    import TerminalFrame from "./terminal/TerminalFrame.svelte";
    import { createTerminalCommands } from "./terminal/terminal-commands";

    let history: string[] = [
        "Welcome to Zsm's Blog Terminal v1.0.0",
        "Type 'help' to see available commands.",
    ];
    let inputValue = "";
    let commandHistory: string[] = [];
    let historyIndex = -1;
    let terminalApi: { scrollToBottom: () => void; focus: () => void } | null = null;

    const commands = createTerminalCommands();

    function handleKeydown(e: KeyboardEvent) {
        if (e.key === 'Enter') {
            const commandLine = inputValue.trim();
            if (commandLine) {
                history = [...history, `visitor@zsm:~$ ${commandLine}`];
                commandHistory.push(commandLine);
                historyIndex = commandHistory.length;
                
                const [cmd, ...args] = commandLine.split(' ');
                if (commands[cmd]) {
                    if (cmd === "clear") {
                        history = [];
                    }
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
                terminalApi?.scrollToBottom();
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

</script>

<TerminalFrame
    lines={history}
    bind:value={inputValue}
    interactive={true}
    autoFocus={true}
    onKeydown={handleKeydown}
    onReady={(api) => {
        terminalApi = api;
    }}
/>
