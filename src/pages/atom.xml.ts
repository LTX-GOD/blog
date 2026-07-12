import type { APIContext } from "astro";
import MarkdownIt from "markdown-it";
import { parse as htmlParser } from "node-html-parser";
import sanitizeHtml from "sanitize-html";
import { siteConfig, profileConfig } from "@/config";
import { getSortedPosts } from "@/utils/content-utils";
import { resolvePostImages } from "@/utils/feed-utils";

const markdownParser = new MarkdownIt();

function escapeXml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

export async function GET(context: APIContext) {
	if (!context.site) {
		throw Error("site not set");
	}

	const posts = (await getSortedPosts()).filter((post) => !post.data.encrypted);

	let atomFeed = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>${siteConfig.title}</title>
  <subtitle>${siteConfig.subtitle || "No description"}</subtitle>
  <link href="${context.site}" rel="alternate" type="text/html"/>
  <link href="${new URL("atom.xml", context.site)}" rel="self" type="application/atom+xml"/>
  <id>${context.site}</id>
  <updated>${new Date().toISOString()}</updated>
  <language>${siteConfig.lang}</language>`;

	for (const post of posts) {
		const body = markdownParser.render(post.body);
		const html = htmlParser.parse(body);
		await resolvePostImages(html.querySelectorAll("img"), post.id, context.site);

		const postUrl = new URL(`posts/${post.slug}/`, context.site).href;
		const content = sanitizeHtml(html.toString(), {
			allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
		});

		atomFeed += `
  <entry>
    <title>${escapeXml(post.data.title)}</title>
    <link href="${postUrl}" rel="alternate" type="text/html"/>
    <id>${postUrl}</id>
    <published>${post.data.published.toISOString()}</published>
    <updated>${post.data.updated?.toISOString() || post.data.published.toISOString()}</updated>
    <summary>${escapeXml(post.data.description || "")}</summary>
    <content type="html"><![CDATA[${content}]]></content>
    <author>
      <name>${escapeXml(profileConfig.name)}</name>
    </author>${post.data.category ? `
    <category term="${escapeXml(post.data.category)}"></category>` : ""}
  </entry>`;
	}

	atomFeed += `
</feed>`;

	return new Response(atomFeed, {
		headers: { "Content-Type": "application/atom+xml; charset=utf-8" },
	});
}
