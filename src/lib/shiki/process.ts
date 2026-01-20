export async function processCodeBlocks(
    content: string, 
    renderer: (code: string, lang: string, meta: string) => Promise<string>
): Promise<string> {
    const regex = /^(```+)(\w*)\s*(.*)\n([\s\S]*?)\n\1/gm;
    
    const matches = Array.from(content.matchAll(regex));
    if (matches.length === 0) return content;

    // Process from last to first to avoid index shifting
    matches.reverse();

    let newContent = content;

    for (const match of matches) {
        const [fullMatch, fence, lang, meta, code] = match;
        const index = match.index!;
        
        try {
            const rendered = await renderer(code, lang, meta.trim());
            newContent = newContent.substring(0, index) + rendered + newContent.substring(index + fullMatch.length);
        } catch (e) {
            console.error(`Failed to render code block: ${lang}`, e);
            // Keep original if failed
        }
    }
    
    return newContent;
}
