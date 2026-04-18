export const BOOT_LOADER_SESSION_KEY = "zsm-boot-loader-complete";

export const BOOT_MESSAGES = [
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
	"[  OK  ] Started Frontend Runtime Service...",
	"[  OK  ] Started Theme Restore Engine...",
	"[  OK  ] Reached target Graphical Interface.",
	"Welcome to ZSM OS v1.0!",
];

export function markBootLoaderComplete() {
	sessionStorage.setItem(BOOT_LOADER_SESSION_KEY, "true");
	document.documentElement.classList.remove("boot-loader-active");
	document.documentElement.classList.add("boot-loader-complete");
}

export function hasCompletedBootLoaderInSession() {
	return sessionStorage.getItem(BOOT_LOADER_SESSION_KEY) === "true";
}

export function ensureBootLoaderCompletedState() {
	document.documentElement.classList.remove("boot-loader-active");
	document.documentElement.classList.add("boot-loader-complete");
}
