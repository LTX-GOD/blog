const BOOT_LOADER_SESSION_KEY = "zsm-boot-loader-complete";

export function ensureBootLoaderUnlocked() {
	const html = document.documentElement;
	if (sessionStorage.getItem(BOOT_LOADER_SESSION_KEY) === "true") {
		html.classList.remove("boot-loader-active");
		html.classList.add("boot-loader-complete");
	}
}

export function setupBootLoaderRuntime() {
	ensureBootLoaderUnlocked();
	window.addEventListener("pageshow", ensureBootLoaderUnlocked);
}
