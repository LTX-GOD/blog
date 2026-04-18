import { visit } from "unist-util-visit";
import { normalizeCodeLanguage } from "../utils/code-language.ts";

export function remarkNormalizeCodeLang() {
	return (tree) => {
		visit(tree, "code", (node) => {
			node.lang = normalizeCodeLanguage(node.lang) || node.lang;
		});
	};
}
