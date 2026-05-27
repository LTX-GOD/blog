class CodeBlockCollapser {
	constructor() {
		this.processedBlocks = new WeakSet();
		this.batchSize = 16;
		this.setupScheduled = false;
		this.pendingRoot = document;
		this.idleHandle = null;
		this.init();
	}

	init() {
		const bootstrap = () => this.scheduleSetup(document);
		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", bootstrap, { once: true });
		} else {
			bootstrap();
		}

		// 允许其它模块在动态注入内容后手动触发一次增量初始化
		document.addEventListener("mizuki:content:updated", (event) => {
			const root = event?.detail?.root;
			this.scheduleSetup(root instanceof Element ? root : document);
		});
	}

	scheduleSetup(root = document) {
		this.pendingRoot =
			root instanceof Document || root instanceof Element ? root : document;

		if (this.setupScheduled) {
			return;
		}

		this.setupScheduled = true;

		const run = () => {
			this.setupScheduled = false;
			this.idleHandle = null;
			this.setupCodeBlocks(this.pendingRoot);
		};

		if (typeof window.requestIdleCallback === "function") {
			this.idleHandle = window.requestIdleCallback(run, { timeout: 300 });
			return;
		}

		window.requestAnimationFrame(run);
	}

	setupCodeBlocks(root = document) {
		const scope =
			root instanceof Document || root instanceof Element ? root : document;
		const codeBlocks = scope.querySelectorAll(".expressive-code");

		if (!codeBlocks.length) {
			return;
		}

		const pendingBlocks = [];
		codeBlocks.forEach((codeBlock) => {
			if (!this.processedBlocks.has(codeBlock)) {
				pendingBlocks.push(codeBlock);
			}
		});

		if (!pendingBlocks.length) {
			return;
		}

		let index = 0;
		const processChunk = () => {
			const end = Math.min(index + this.batchSize, pendingBlocks.length);
			for (; index < end; index += 1) {
				const codeBlock = pendingBlocks[index];
				this.enhanceCodeBlock(codeBlock);
				this.processedBlocks.add(codeBlock);
			}

			if (index < pendingBlocks.length) {
				window.requestAnimationFrame(processChunk);
			}
		};

		processChunk();
	}

	enhanceCodeBlock(codeBlock) {
		const frame = codeBlock.querySelector(".frame");
		if (!frame) return;

		if (frame.classList.contains("has-title")) {
			return;
		}

		if (frame.querySelector(".collapse-toggle-btn")) {
			return;
		}

		codeBlock.classList.add("collapsible", "expanded");

		const toggleBtn = this.createToggleButton();
		frame.appendChild(toggleBtn);

		this.bindToggleEvents(codeBlock, toggleBtn);
	}

	createToggleButton() {
		const button = document.createElement("button");
		button.className = "collapse-toggle-btn";
		button.type = "button";
		button.setAttribute("aria-label", "折叠/展开代码块");

		button.innerHTML = `
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <g fill="none">
          <path d="M24 0v24H0V0zM12.593 23.258l-.011.002l-.071.035l-.02.004l-.014-.004l-.071-.035q-.016-.005-.024.005l-.004.01l-.017.428l.005.02l.01.013l.104.074l.015.004l.012-.004l.104-.074l.012-.016l.004-.017l-.017-.427q-.004-.016-.017-.018m.265-.113l-.013.002l-.185.093l-.01.01l-.003.011l.018.43l.005.012l.008.007l.201.093q.019.005.029-.008l.004-.014l-.034-.614q-.005-.019-.02-.022m-.715.002a.02.02 0 0 0-.027.006l-.006.014l-.034.614q.001.018.017.024l.015-.002l.201-.093l.01-.008l.004-.011l.017-.43l-.003-.012l-.01-.01z"></path>
          <path fill="currentColor" d="m12 16.172l-4.95-4.95a1 1 0 1 0-1.414 1.414l5.657 5.657a1 1 0 0 0 1.414 0l5.657-5.657a1 1 0 0 0-1.414-1.414z"></path>
        </g>
      </svg>
    `;

		return button;
	}

	bindToggleEvents(codeBlock, button) {
		button.addEventListener("click", (e) => {
			e.preventDefault();
			e.stopPropagation();
			this.toggleCollapse(codeBlock);
		});

		button.addEventListener("keydown", (e) => {
			if (e.key === "Enter" || e.key === " ") {
				e.preventDefault();
				this.toggleCollapse(codeBlock);
			}
		});
	}

	toggleCollapse(codeBlock) {
		const isCollapsed = codeBlock.classList.contains("collapsed");
		this.setCollapsedState(codeBlock, !isCollapsed);

		const event = new CustomEvent("codeBlockToggle", {
			detail: { collapsed: !isCollapsed, element: codeBlock },
		});
		document.dispatchEvent(event);
	}

	setCollapsedState(codeBlock, collapsed) {
		if (collapsed) {
			codeBlock.classList.remove("expanded");
			codeBlock.classList.add("collapsed");
			return;
		}

		codeBlock.classList.remove("collapsed");
		codeBlock.classList.add("expanded");
	}

	destroy() {
		if (
			typeof window.cancelIdleCallback === "function" &&
			this.idleHandle !== null
		) {
			window.cancelIdleCallback(this.idleHandle);
		}

		this.idleHandle = null;
		this.setupScheduled = false;
		this.processedBlocks = new WeakSet();
	}

	// 公共API方法
	collapseAll() {
		const allBlocks = document.querySelectorAll(".expressive-code.expanded");
		allBlocks.forEach((block) => {
			this.setCollapsedState(block, true);
		});
	}

	expandAll() {
		const allBlocks = document.querySelectorAll(".expressive-code.collapsed");
		allBlocks.forEach((block) => {
			this.setCollapsedState(block, false);
		});
	}
}

const codeBlockCollapser = new CodeBlockCollapser();

window.CodeBlockCollapser = CodeBlockCollapser;
window.codeBlockCollapser = codeBlockCollapser;

if (window.swup) {
	window.swup.hooks.on("page:view", () => {
		const container = document.getElementById("swup-container") || document;
		codeBlockCollapser.scheduleSetup(container);
	});
} else {
	document.addEventListener("swup:enable", () => {
		const container = document.getElementById("swup-container") || document;
		codeBlockCollapser.scheduleSetup(container);
	});
}

export {};
