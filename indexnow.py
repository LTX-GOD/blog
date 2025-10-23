import re
import xml.etree.ElementTree as ET

import requests


def extract_urls_from_sitemap(sitemap_content):
    """
    从 sitemap 内容中提取所有有效的 URL
    使用多种方法确保即使 XML 格式有问题也能提取
    """
    urls = []
    
    # 方法1: 使用正则表达式提取（最可靠）
    url_pattern = r'<loc>\s*(https?://[^<]+)\s*</loc>'
    urls = re.findall(url_pattern, sitemap_content)
    
    # 方法2: 尝试 XML 解析（作为备用）
    if not urls:
        try:
            root = ET.fromstring(sitemap_content)
            for url_elem in root.findall('.//loc'):
                if url_elem.text and url_elem.text.strip():
                    urls.append(url_elem.text.strip())
        except ET.ParseError:
            print("XML 解析失败，使用正则表达式提取的 URL")
    
    # 去重和过滤空值
    urls = list(set(urls))
    urls = [url for url in urls if url and url.startswith('http')]
    
    return urls

def submit_to_indexnow(urls, key, key_location, batch_size=100):
    """
    提交 URL 到 IndexNow
    """
    if not urls:
        print("没有找到有效的 URL")
        return
    
    domain = "www.zhuangsanmeng.xyz"
    successful_batches = 0
    
    # 分批提交
    for i in range(0, len(urls), batch_size):
        batch_urls = urls[i:i + batch_size]
        
        payload = {
            "host": domain,
            "key": key,
            "keyLocation": key_location,
            "urlList": batch_urls
        }
        
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Host": "api.indexnow.org"
        }
        
        try:
            response = requests.post(
                "https://api.indexnow.org/IndexNow",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                successful_batches += 1
                print(f"✅ 成功提交第 {i//batch_size + 1} 批 URL ({len(batch_urls)} 个)")
            else:
                print(f"❌ 第 {i//batch_size + 1} 批提交失败: HTTP {response.status_code}")
                print(f"响应: {response.text[:200]}...")
                
        except Exception as e:
            print(f"❌ 第 {i//batch_size + 1} 批请求出错: {e}")
    
    return successful_batches

def main():
    # 配置参数
    SITEMAP_URL = "https://www.zhuangsanmeng.xyz/sitemap-0.xml"
    KEY = "9f50633778924dc1a069421e946ea90e"
    KEY_LOCATION = "https://www.zhuangsanmeng.xyz/9f50633778924dc1a069421e946ea90e.txt"
    
    print("开始处理 sitemap...")
    
    try:
        # 获取 sitemap 内容
        response = requests.get(SITEMAP_URL, timeout=30)
        response.raise_for_status()
        sitemap_content = response.text
        
        # 提取 URL
        urls = extract_urls_from_sitemap(sitemap_content)
        
        print(f"从 sitemap 中提取了 {len(urls)} 个有效的 URL")
        
        if urls:
            # 显示前几个 URL 作为示例
            print("\n前5个URL示例:")
            for url in urls[:5]:
                print(f"  - {url}")
            
            if len(urls) > 5:
                print(f"  - ... 还有 {len(urls) - 5} 个 URL")
            
            # 确认是否继续
            confirm = input("\n是否继续提交到 IndexNow? (y/n): ")
            if confirm.lower() == 'y':
                successful_batches = submit_to_indexnow(urls, KEY, KEY_LOCATION)
                print(f"\n🎉 完成！成功提交了 {successful_batches} 批 URL")
            else:
                print("操作已取消")
        else:
            print("没有找到有效的 URL，请检查 sitemap 格式")
            
    except Exception as e:
        print(f"❌ 处理过程中出错: {e}")

if __name__ == "__main__":
    main()
