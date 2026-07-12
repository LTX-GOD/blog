import { getImage } from "astro:assets";
import type { ImageMetadata } from "astro";
import type { HTMLElement as NhpElement } from "node-html-parser";

export const feedImagesGlob = import.meta.glob<{ default: ImageMetadata }>(
	"/src/content/**/*.{jpeg,jpg,png,gif,webp,avif}",
);

export async function resolvePostImages(
	images: NhpElement[],
	postId: string,
	siteUrl: URL,
): Promise<void> {
	const postDir = postId.includes("/") ? postId.split("/")[0] : "";

	for (const img of images) {
		const src = img.getAttribute("src");
		if (!src) continue;

		if (
			src.startsWith("./") ||
			src.startsWith("../") ||
			(!src.startsWith("http") && !src.startsWith("/"))
		) {
			let importPath: string;

			if (src.startsWith("./")) {
				const rel = src.slice(2);
				importPath = postDir
					? `/src/content/posts/${postDir}/${rel}`
					: `/src/content/posts/${rel}`;
			} else if (src.startsWith("../")) {
				importPath = `/src/content/${src.replace(/^\.\.\//, "")}`;
			} else {
				importPath = postDir
					? `/src/content/posts/${postDir}/${src}`
					: `/src/content/posts/${src}`;
			}

			const imageMod = await feedImagesGlob[importPath]?.()?.then(
				(res) => res.default,
			);
			if (imageMod) {
				const optimizedImg = await getImage({ src: imageMod });
				img.setAttribute("src", new URL(optimizedImg.src, siteUrl).href);
			} else {
				console.warn(
					`Failed to load image: ${importPath} for post: ${postId}`,
				);
			}
		} else if (src.startsWith("/")) {
			img.setAttribute("src", new URL(src, siteUrl).href);
		}
	}
}
