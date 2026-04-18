import { siteConfig } from "../config";
import { pathsEqual, url } from "./url-utils";

const MOBILE_BANNER_SELECTOR =
	'.block.lg\\:hidden[alt="Mobile banner image of the blog"]';

function getCarouselItems() {
	return Array.from(document.querySelectorAll(".carousel-item"));
}

function getValidCarouselItems(items: Element[]) {
	const isMobile = window.innerWidth < 1024;
	return items.filter((item) =>
		isMobile
			? item.querySelector(".block.lg\\:hidden")
			: item.querySelector(".hidden.lg\\:block"),
	);
}

function showSingleBanner() {
	const banner = document.getElementById("banner");
	if (banner) {
		banner.classList.remove("opacity-0", "scale-105");
	}

	const mobileBanner = document.querySelector(MOBILE_BANNER_SELECTOR);
	if (mobileBanner && !document.getElementById("banner-carousel")) {
		mobileBanner.classList.remove("opacity-0", "scale-105");
		mobileBanner.classList.add("opacity-100");
	}
}

function updateCarouselVisibility(items: Element[], activeIndex: number) {
	items.forEach((item, index) => {
		const isActive = index === activeIndex;
		item.classList.toggle("opacity-100", isActive);
		item.classList.toggle("scale-100", isActive);
		item.classList.toggle("opacity-0", !isActive);
		item.classList.toggle("scale-110", !isActive);
	});
}

function initCarousel() {
	const carousel = document.getElementById("banner-carousel");
	if (!carousel || carousel.dataset.initialized === "true") {
		return;
	}

	const carouselItems = getCarouselItems();
	const validItems = getValidCarouselItems(carouselItems);
	if (validItems.length === 0) {
		return;
	}

	carousel.dataset.initialized = "true";

	if (validItems.length > 1 && !siteConfig.banner.carousel?.enable) {
		const randomIndex = Math.floor(Math.random() * validItems.length);
		updateCarouselVisibility(validItems, randomIndex);
		return;
	}

	if (!(validItems.length > 1 && siteConfig.banner.carousel?.enable)) {
		updateCarouselVisibility(validItems, 0);
		return;
	}

	let currentIndex = 0;
	const interval = siteConfig.banner.carousel?.interval || 6;
	let carouselInterval: number | undefined;
	let isPaused = false;
	let startX = 0;
	let startY = 0;
	let isSwiping = false;

	const switchToSlide = (index: number) => {
		currentIndex = index;
		updateCarouselVisibility(validItems, currentIndex);
	};

	const startCarousel = () => {
		if (carouselInterval) {
			window.clearInterval(carouselInterval);
		}
		carouselInterval = window.setInterval(() => {
			if (!isPaused) {
				switchToSlide((currentIndex + 1) % validItems.length);
			}
		}, interval * 1000);
	};

	updateCarouselVisibility(validItems, 0);

	if ("ontouchstart" in window) {
		carousel.addEventListener(
			"touchstart",
			(e) => {
				startX = e.touches[0].clientX;
				startY = e.touches[0].clientY;
				isSwiping = false;
				isPaused = true;
				if (carouselInterval) {
					window.clearInterval(carouselInterval);
				}
			},
			{ passive: true },
		);

		carousel.addEventListener(
			"touchmove",
			(e) => {
				if (!startX || !startY) {
					return;
				}

				const diffX = Math.abs(e.touches[0].clientX - startX);
				const diffY = Math.abs(e.touches[0].clientY - startY);
				if (diffX > diffY && diffX > 30) {
					isSwiping = true;
					e.preventDefault();
				}
			},
			{ passive: false },
		);

		carousel.addEventListener(
			"touchend",
			(e) => {
				if (!startX || !startY || !isSwiping) {
					isPaused = false;
					startCarousel();
					return;
				}

				const diffX = startX - e.changedTouches[0].clientX;
				if (Math.abs(diffX) > 50) {
					switchToSlide(
						diffX > 0
							? (currentIndex + 1) % validItems.length
							: (currentIndex - 1 + validItems.length) % validItems.length,
					);
				}

				startX = 0;
				startY = 0;
				isSwiping = false;
				isPaused = false;
				startCarousel();
			},
			{ passive: true },
		);
	}

	carousel.addEventListener("mouseenter", () => {
		isPaused = true;
		if (carouselInterval) {
			window.clearInterval(carouselInterval);
		}
	});

	carousel.addEventListener("mouseleave", () => {
		isPaused = false;
		startCarousel();
	});

	startCarousel();
}

export function isBannerEnabled() {
	return !!document.getElementById("banner-wrapper");
}

export function showBanner() {
	requestAnimationFrame(() => {
		showSingleBanner();
		if (document.getElementById("banner-carousel")) {
			initCarousel();
		}
	});
}

export function setupBannerRuntime() {
	showBanner();
}

export function syncPageChromeForVisit(targetUrl: string) {
	const isHomePage = pathsEqual(targetUrl, url("/"));
	const bodyElement = document.body;

	if (isHomePage) {
		bodyElement.classList.add("lg:is-home");
	} else {
		bodyElement.classList.remove("lg:is-home");
	}

	const bannerTextOverlay = document.querySelector(".banner-text-overlay");
	if (bannerTextOverlay) {
		bannerTextOverlay.classList.toggle("hidden", !isHomePage);
	}

	const navbar = document.getElementById("navbar");
	if (navbar) {
		navbar.setAttribute("data-is-home", String(isHomePage));
		if (navbar.getAttribute("data-transparent-mode") === "semifull") {
			const initSemifullScrollDetection = (window as any)
				.initSemifullScrollDetection;
			if (typeof initSemifullScrollDetection === "function") {
				initSemifullScrollDetection();
			}
		}
	}

	const bannerWrapper = document.getElementById("banner-wrapper");
	const mainContentWrapper = document.querySelector(".absolute.w-full.z-30");
	if (!(bannerWrapper && mainContentWrapper instanceof HTMLElement)) {
		return;
	}

	if (isHomePage) {
		window.setTimeout(() => {
			bannerWrapper.classList.remove("mobile-hide-banner");
		}, 100);
		window.setTimeout(() => {
			mainContentWrapper.classList.remove("mobile-main-no-banner");
		}, 150);
		return;
	}

	bannerWrapper.classList.add("mobile-hide-banner");
	window.setTimeout(() => {
		mainContentWrapper.classList.add("mobile-main-no-banner");
	}, 100);
}
