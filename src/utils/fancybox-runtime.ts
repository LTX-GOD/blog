let fancyboxInstances: any[] = [];
let fancyboxModulePromise: Promise<any> | undefined;

async function getFancybox() {
	if (!fancyboxModulePromise) {
		fancyboxModulePromise = Promise.all([
			import("@fancyapps/ui"),
			import("@fancyapps/ui/dist/fancybox/fancybox.css"),
			import("../scripts/code-collapse.js"),
		]).then(([mod]) => mod.Fancybox);
	}

	return fancyboxModulePromise;
}

export async function initFancybox() {
	if (fancyboxInstances.length > 0) {
		return;
	}

	const Fancybox = await getFancybox();
	const commonConfig = {
		Thumbs: {
			autoStart: true,
			showOnStart: "yes",
		},
		Toolbar: {
			display: {
				left: ["infobar"],
				middle: [
					"zoomIn",
					"zoomOut",
					"toggle1to1",
					"rotateCCW",
					"rotateCW",
					"flipX",
					"flipY",
				],
				right: ["slideshow", "thumbs", "close"],
			},
		},
		animated: true,
		dragToClose: true,
		keyboard: {
			Escape: "close",
			Delete: "close",
			Backspace: "close",
			PageUp: "next",
			PageDown: "prev",
			ArrowUp: "next",
			ArrowDown: "prev",
			ArrowRight: "next",
			ArrowLeft: "prev",
		},
		fitToView: true,
		preload: 3,
		infinite: true,
		Panzoom: {
			maxScale: 3,
			minScale: 1,
		},
		caption: false,
	};

	fancyboxInstances.push(
		Fancybox.bind(".custom-md img, #post-cover img, .moment-images img", {
			...commonConfig,
			groupAll: true,
			Carousel: {
				transition: "slide",
				preload: 2,
			},
		} as any),
	);

	fancyboxInstances.push(
		Fancybox.bind(".moment-images a[data-fancybox]", {
			...commonConfig,
			source: (el) => {
				return el.getAttribute("data-src") || el.getAttribute("href");
			},
		} as any),
	);

	fancyboxInstances.push(
		Fancybox.bind("[data-fancybox]:not(.moment-images a)", commonConfig as any),
	);
}

export function cleanupFancybox() {
	fancyboxInstances.forEach((instance) => {
		if (instance && typeof instance.destroy === "function") {
			instance.destroy();
		}
	});
	fancyboxInstances = [];
}

export function setupFancyboxRuntime() {
	const setup = () => {
		void initFancybox();

		window.swup.hooks.on("page:view", () => {
			cleanupFancybox();
			requestAnimationFrame(() => {
				void initFancybox();
			});
		});
	};

	if (window.swup) {
		setup();
	} else {
		document.addEventListener("swup:enable", setup, { once: true });

		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", () => {
				void initFancybox();
			});
		} else {
			void initFancybox();
		}
	}
}
