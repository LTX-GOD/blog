// 代码块折叠功能脚本

class CodeBlockCollapser {
  constructor() {
    this.init();
  }

  init() {
    // 等待DOM加载完成
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setupCodeBlocks());
    } else {
      this.setupCodeBlocks();
    }

    // 监听页面变化（用于SPA路由）
    this.observePageChanges();
  }

  setupCodeBlocks() {
    // 查找所有代码块
    const codeBlocks = document.querySelectorAll('.expressive-code');
    
    codeBlocks.forEach((codeBlock, index) => {
      this.wrapCodeBlock(codeBlock, index);
    });
  }

  wrapCodeBlock(codeBlock, index) {
    // 避免重复包装
    if (codeBlock.closest('.code-block-wrapper')) {
      return;
    }

    // 获取代码块语言
    const language = this.getCodeLanguage(codeBlock);
    
    // 创建包装容器
    const wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';
    wrapper.setAttribute('data-code-block-id', index);

    // 创建折叠头部
    const header = this.createCollapseHeader(language, index);
    
    // 创建内容容器
    const content = document.createElement('div');
    content.className = 'code-content expanded';
    content.setAttribute('data-content-id', index);

    // 包装代码块
    codeBlock.parentNode.insertBefore(wrapper, codeBlock);
    wrapper.appendChild(header);
    wrapper.appendChild(content);
    content.appendChild(codeBlock);

    // 绑定事件
    this.bindCollapseEvents(wrapper, index);
  }

  createCollapseHeader(language, index) {
    const header = document.createElement('div');
    header.className = 'code-collapse-header';
    header.setAttribute('data-header-id', index);

    header.innerHTML = `
      <div class="code-block-title">
        <span class="code-block-language">${language}</span>
        <span class="code-collapse-indicator">点击折叠/展开代码</span>
      </div>
      <button class="code-collapse-button" type="button" aria-label="折叠/展开代码块">
        <span class="collapse-text">折叠</span>
        <svg class="code-collapse-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M6 9L12 15L18 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    `;

    return header;
  }

  bindCollapseEvents(wrapper, index) {
    const header = wrapper.querySelector('.code-collapse-header');
    const content = wrapper.querySelector('.code-content');
    const button = wrapper.querySelector('.code-collapse-button');
    const icon = wrapper.querySelector('.code-collapse-icon');
    const text = wrapper.querySelector('.collapse-text');
    const indicator = wrapper.querySelector('.code-collapse-indicator');

    // 点击事件
    header.addEventListener('click', () => {
      this.toggleCollapse(content, icon, text, indicator);
    });

    // 键盘事件
    header.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.toggleCollapse(content, icon, text, indicator);
      }
    });

    // 设置可访问性属性
    header.setAttribute('tabindex', '0');
    header.setAttribute('role', 'button');
    header.setAttribute('aria-expanded', 'true');
    header.setAttribute('aria-controls', `code-content-${index}`);
    content.setAttribute('id', `code-content-${index}`);
  }

  toggleCollapse(content, icon, text, indicator) {
    const isCollapsed = content.classList.contains('collapsed');
    
    if (isCollapsed) {
      // 展开
      content.classList.remove('collapsed');
      content.classList.add('expanded');
      icon.classList.remove('collapsed');
      text.textContent = '折叠';
      indicator.textContent = '点击折叠代码';
      content.parentElement.querySelector('.code-collapse-header').setAttribute('aria-expanded', 'true');
    } else {
      // 折叠
      content.classList.remove('expanded');
      content.classList.add('collapsed');
      icon.classList.add('collapsed');
      text.textContent = '展开';
      indicator.textContent = '点击展开代码';
      content.parentElement.querySelector('.code-collapse-header').setAttribute('aria-expanded', 'false');
    }

    // 触发自定义事件
    const event = new CustomEvent('codeBlockToggle', {
      detail: {
        collapsed: !isCollapsed,
        element: content.parentElement
      }
    });
    document.dispatchEvent(event);
  }

  getCodeLanguage(codeBlock) {
    // 尝试从多个位置获取语言信息
    const langSources = [
      () => codeBlock.getAttribute('data-language'),
      () => codeBlock.querySelector('[data-language]')?.getAttribute('data-language'),
      () => codeBlock.className.match(/language-(\w+)/)?.[1],
      () => codeBlock.querySelector('code')?.className.match(/language-(\w+)/)?.[1],
      () => codeBlock.querySelector('.frame')?.getAttribute('data-language'),
    ];

    for (const getLanguage of langSources) {
      const language = getLanguage();
      if (language) {
        return this.formatLanguageName(language);
      }
    }

    return 'Code';
  }

  formatLanguageName(language) {
    const languageMap = {
      'js': 'JavaScript',
      'ts': 'TypeScript',
      'py': 'Python',
      'cpp': 'C++',
      'c': 'C',
      'java': 'Java',
      'html': 'HTML',
      'css': 'CSS',
      'scss': 'SCSS',
      'sass': 'Sass',
      'json': 'JSON',
      'xml': 'XML',
      'yaml': 'YAML',
      'yml': 'YAML',
      'md': 'Markdown',
      'sh': 'Shell',
      'bash': 'Bash',
      'zsh': 'Zsh',
      'fish': 'Fish',
      'powershell': 'PowerShell',
      'sql': 'SQL',
      'php': 'PHP',
      'rb': 'Ruby',
      'go': 'Go',
      'rust': 'Rust',
      'swift': 'Swift',
      'kotlin': 'Kotlin',
      'dart': 'Dart',
      'vue': 'Vue',
      'svelte': 'Svelte',
      'astro': 'Astro'
    };

    return languageMap[language.toLowerCase()] || language.toUpperCase();
  }

  observePageChanges() {
    // 使用MutationObserver监听DOM变化
    const observer = new MutationObserver((mutations) => {
      let shouldReinit = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.querySelector && node.querySelector('.expressive-code')) {
                shouldReinit = true;
              }
            }
          });
        }
      });

      if (shouldReinit) {
        // 延迟执行，确保DOM完全更新
        setTimeout(() => this.setupCodeBlocks(), 100);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // 公共API方法
  collapseAll() {
    const allContent = document.querySelectorAll('.code-content.expanded');
    allContent.forEach(content => {
      const wrapper = content.closest('.code-block-wrapper');
      const icon = wrapper.querySelector('.code-collapse-icon');
      const text = wrapper.querySelector('.collapse-text');
      const indicator = wrapper.querySelector('.code-collapse-indicator');
      this.toggleCollapse(content, icon, text, indicator);
    });
  }

  expandAll() {
    const allContent = document.querySelectorAll('.code-content.collapsed');
    allContent.forEach(content => {
      const wrapper = content.closest('.code-block-wrapper');
      const icon = wrapper.querySelector('.code-collapse-icon');
      const text = wrapper.querySelector('.collapse-text');
      const indicator = wrapper.querySelector('.code-collapse-indicator');
      this.toggleCollapse(content, icon, text, indicator);
    });
  }
}

// 初始化代码块折叠器
const codeBlockCollapser = new CodeBlockCollapser();

// 导出到全局作用域（可选）
window.CodeBlockCollapser = CodeBlockCollapser;
window.codeBlockCollapser = codeBlockCollapser;