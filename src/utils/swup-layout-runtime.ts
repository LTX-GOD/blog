import { BANNER_HEIGHT } from "../constants/constants";
import { ensureBootLoaderUnlocked } from "./boot-loader-runtime";
import { isBannerEnabled, syncPageChromeForVisit } from "./banner-runtime";
import {
	dispatchPageLoadedForComments,
	initCustomScrollbar,
	reinitializeArticleRuntime,
} from "./layout-dom-runtime";

type Visit = {
	to: {
		url: string;
	};
};

function handleLinkClick() {
	document.documentElement.style.setProperty("--content-delay", "0ms");

	if (!isBannerEnabled()) {
		return;
	}

	const navbar = document.getElementById("navbar-wrapper");
	if (!navbar || !document.body.classList.contains("lg:is-home")) {
		return;
	}

	const threshold = window.innerHeight * (BANNER_HEIGHT / 100) - 88;
	if (document.documentElement.scrollTop >= threshold) {
		navbar.classList.add("navbar-hidden");
	}
}

function handleContentReplace() {
	initCustomScrollbar();
	reinitializeArticleRuntime();
}

function handleVisitStart(visit: Visit) {
	syncPageChromeForVisit(visit.to.url);

	const heightExtend = document.getElementById("page-height-extend");
	if (heightExtend) {
		heightExtend.classList.remove("hidden");
	}

	const toc = document.getElementById("toc-wrapper");
	if (toc) {
		toc.classList.add("toc-not-ready");
	}
}

function handlePageView() {
	ensureBootLoaderUnlocked();

	const heightExtend = document.getElementById("page-height-extend");
	if (heightExtend) {
		heightExtend.classList.remove("hidden");
	}

	window.scrollTo(0, 0);

	const storedTheme = localStorage.getItem("theme") || "LIGHT_MODE";
	const expectedTheme =
		storedTheme === "DARK_MODE" ? "github-dark" : "github-light";
	if (document.documentElement.getAttribute("data-theme") !== expectedTheme) {
		document.documentElement.setAttribute("data-theme", expectedTheme);
		window.setTimeout(() => {
			window.dispatchEvent(new CustomEvent("theme-change"));
		}, 50);
	}

	dispatchPageLoadedForComments();
}

function handleVisitEnd() {
	ensureBootLoaderUnlocked();

	window.setTimeout(() => {
		const heightExtend = document.getElementById("page-height-extend");
		if (heightExtend) {
			heightExtend.classList.add("hidden");
		}

		const toc = document.getElementById("toc-wrapper");
		if (toc) {
			toc.classList.remove("toc-not-ready");
		}
	}, 200);
}

export function setupSwupLayoutRuntime() {
	const registerHooks = () => {
		const swup = (window as any).swup;
		if (!swup?.hooks) {
			return;
		}

		swup.hooks.on("link:click", handleLinkClick);
		swup.hooks.on("content:replace", handleContentReplace);
		swup.hooks.on("visit:start", handleVisitStart);
		swup.hooks.on("page:view", handlePageView);
		swup.hooks.on("visit:end", handleVisitEnd);
	};

	if ((window as any).swup?.hooks) {
		registerHooks();
		return;
	}

	document.addEventListener("swup:enable", registerHooks, { once: true });
}
