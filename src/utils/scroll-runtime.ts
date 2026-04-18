import {
	BANNER_HEIGHT,
	BANNER_HEIGHT_EXTEND,
	BANNER_HEIGHT_HOME,
} from "../constants/constants";
import { isBannerEnabled } from "./banner-runtime";

function throttle<T extends (...args: never[]) => void>(func: T, limit: number) {
	let inThrottle = false;
	return function throttled(this: unknown, ...args: Parameters<T>) {
		if (inThrottle) {
			return;
		}

		func.apply(this, args);
		inThrottle = true;
		window.setTimeout(() => {
			inThrottle = false;
		}, limit);
	};
}

function updateBannerHeightExtend() {
	let offset = Math.floor(window.innerHeight * (BANNER_HEIGHT_EXTEND / 100));
	offset -= offset % 4;
	document.documentElement.style.setProperty(
		"--banner-height-extend",
		`${offset}px`,
	);
}

function handleScroll() {
	const scrollTop = document.documentElement.scrollTop;
	const bannerHeight = window.innerHeight * (BANNER_HEIGHT / 100);
	const backToTopBtn = document.getElementById("back-to-top-btn");
	const toc = document.getElementById("toc-wrapper");
	const navbar = document.getElementById("navbar-wrapper");
	const bannerEnabled = isBannerEnabled();

	requestAnimationFrame(() => {
		if (backToTopBtn) {
			backToTopBtn.classList.toggle("hide", scrollTop <= bannerHeight);
		}

		if (bannerEnabled && toc) {
			toc.classList.toggle("toc-hide", scrollTop <= bannerHeight);
		}

		if (bannerEnabled && navbar) {
			const isHome =
				document.body.classList.contains("lg:is-home") &&
				window.innerWidth >= 1024;
			const currentBannerHeight = isHome ? BANNER_HEIGHT_HOME : BANNER_HEIGHT;
			const threshold = window.innerHeight * (currentBannerHeight / 100) - 88;
			navbar.classList.toggle("navbar-hidden", scrollTop >= threshold);
		}
	});
}

export function setupScrollRuntime() {
	const throttledScrollHandler = throttle(handleScroll, 16);
	window.addEventListener("scroll", throttledScrollHandler, { passive: true });
	window.addEventListener("resize", updateBannerHeightExtend);
	updateBannerHeightExtend();
}
