function setClickOutsideToClose(panelId: string, ignoreIds: string[]) {
	document.addEventListener("click", (event) => {
		const panel = document.getElementById(panelId);
		const target = event.target;
		if (!(target instanceof Node) || !panel) {
			return;
		}

		for (const ignoreId of ignoreIds) {
			const ignoreElement = document.getElementById(ignoreId);
			if (ignoreElement === target || ignoreElement?.contains(target)) {
				return;
			}
		}

		panel.classList.add("float-panel-closed");
	});
}

export function setupFloatPanelRuntime() {
	setClickOutsideToClose("display-setting", [
		"display-setting",
		"display-settings-switch",
	]);
	setClickOutsideToClose("nav-menu-panel", [
		"nav-menu-panel",
		"nav-menu-switch",
	]);
	setClickOutsideToClose("search-panel", [
		"search-panel",
		"search-bar",
		"search-switch",
	]);
}

export function initCustomScrollbar() {
	const katexElements = document.querySelectorAll(
		".katex-display:not([data-scrollbar-initialized])",
	) as NodeListOf<HTMLElement>;

	katexElements.forEach((element) => {
		if (!element.parentNode) {
			return;
		}

		const container = document.createElement("div");
		container.className = "katex-display-container";
		element.parentNode.insertBefore(container, element);
		container.appendChild(element);
		container.style.cssText = `
			overflow-x: auto;
			scrollbar-width: thin;
			scrollbar-color: rgba(0,0,0,0.3) transparent;
		`;

		if (!document.head.querySelector("style[data-katex-scrollbar]")) {
			const style = document.createElement("style");
			style.setAttribute("data-katex-scrollbar", "true");
			style.textContent = `
				.katex-display-container::-webkit-scrollbar {
					height: 6px;
				}
				.katex-display-container::-webkit-scrollbar-track {
					background: transparent;
				}
				.katex-display-container::-webkit-scrollbar-thumb {
					background: rgba(0,0,0,0.3);
					border-radius: 3px;
				}
				.katex-display-container::-webkit-scrollbar-thumb:hover {
					background: rgba(0,0,0,0.5);
				}
			`;
			document.head.appendChild(style);
		}

		element.setAttribute("data-scrollbar-initialized", "true");
	});
}

export function reinitializeArticleRuntime() {
	const tocWrapper = document.getElementById("toc-wrapper");
	const isArticlePage = tocWrapper !== null;

	if (isArticlePage) {
		const tocElement = document.querySelector("table-of-contents") as
			| { init?: () => void }
			| null;
		if (typeof tocElement?.init === "function") {
			window.setTimeout(() => {
				tocElement.init?.();
			}, 100);
		}

		const mobileTOCInit = (window as any).mobileTOCInit;
		if (typeof mobileTOCInit === "function") {
			window.setTimeout(() => {
				mobileTOCInit();
			}, 100);
		}
	}

	const navbar = document.getElementById("navbar");
	if (navbar?.getAttribute("data-transparent-mode") === "semifull") {
		const initSemifullScrollDetection = (window as any)
			.initSemifullScrollDetection;
		if (typeof initSemifullScrollDetection === "function") {
			initSemifullScrollDetection();
		}
	}
}

export function dispatchPageLoadedForComments() {
	window.setTimeout(() => {
		if (!document.getElementById("tcomment")) {
			return;
		}

		document.dispatchEvent(
			new CustomEvent("mizuki:page:loaded", {
				detail: {
					path: window.location.pathname,
					timestamp: Date.now(),
				},
			}),
		);
	}, 300);
}

export function setupLayoutDomRuntime() {
	setupFloatPanelRuntime();
	initCustomScrollbar();
	reinitializeArticleRuntime();
}
