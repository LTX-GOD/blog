import type { RSSFeedItem } from "@astrojs/rss";
import rss from "@astrojs/rss";
import type { APIContext } from "astro";
import MarkdownIt from "markdown-it";
import { parse as htmlParser } from "node-html-parser";
import sanitizeHtml from "sanitize-html";
import { siteConfig } from "@/config";
import { getSortedPosts } from "@/utils/content-utils";
import { resolvePostImages } from "@/utils/feed-utils";

const markdownParser = new MarkdownIt();

export async function GET(context: APIContext) {
	if (!context.site) {
		throw Error("site not set");
	}

	const posts = (await getSortedPosts()).filter((post) => !post.data.encrypted);
	const feed: RSSFeedItem[] = [];

	for (const post of posts) {
		const body = markdownParser.render(post.body);
		const html = htmlParser.parse(body);
		await resolvePostImages(html.querySelectorAll("img"), post.id, context.site);

		feed.push({
			title: post.data.title,
			description: post.data.description,
			pubDate: post.data.published,
			link: `/posts/${post.slug}/`,
			content: sanitizeHtml(html.toString(), {
				allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
			}),
		});
	}

	return rss({
		title: siteConfig.title,
		description: siteConfig.subtitle || "No description",
		site: context.site,
		items: feed,
		customData: `<language>${siteConfig.lang}</language>`,
	});
}
