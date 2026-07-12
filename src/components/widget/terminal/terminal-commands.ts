import { navigateToPage } from "@utils/navigation-utils";

export type TerminalCommandHandler = (args: string[]) => string | void;

export function createTerminalCommands(): Record<string, TerminalCommandHandler> {
	return {
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
				case "about.md":
					navigateToPage("/about/");
					return "Navigating to /about/...";
				case "friends.md":
					navigateToPage("/friends/");
					return "Navigating to /friends/...";
				case "archive/":
					navigateToPage("/archive/");
					return "Navigating to /archive/...";
				case "posts/":
					navigateToPage("/archive/");
					return "Navigating to /archive/...";
				case "projects/":
					navigateToPage("/projects/");
					return "Navigating to /projects/...";
				default:
					return `cat: ${file}: No such file or directory`;
			}
		},
		whoami: () => "visitor",
		date: () => new Date().toString(),
		clear: () => "",
		uname: () => "Linux zsm-blog 5.15.0-generic #1 SMP x86_64 GNU/Linux",
		rm: () => {
			// 用全屏遮罩模拟"系统关机"，不破坏 SWUP DOM 状态
			const overlay = document.createElement("div");
			overlay.style.cssText =
				"position:fixed;inset:0;background:#000;z-index:99999;transition:opacity 0.5s";
			overlay.style.opacity = "0";
			document.body.appendChild(overlay);
			requestAnimationFrame(() => { overlay.style.opacity = "1"; });
			setTimeout(() => { window.location.href = "about:blank"; }, 600);
			return "System halting...";
		},
	};
}
