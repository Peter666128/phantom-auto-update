#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
幻影核心 - 自动发现安全渠道脚本
功能：自动搜索GitHub上的Android安全仓库，自动筛选有价值的，自动添加到config.json
"""

import json
import re
import time
import logging
from typing import List, Dict, Set
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

# ============== 配置 ==============
GITHUB_API = "https://api.github.com/search/repositories"
GITHUB_RAW = "https://raw.githubusercontent.com"
CONFIG_FILE = "config.json"

# 搜索关键词列表
SEARCH_KEYWORDS = [
    "android root detection",
    "android emulator detection",
    "frida detection android",
    "xposed detection android",
    "android rasp security",
    "android anti tamper",
    "android malware detection",
    "magisk detection",
    "android security library",
    "android hook detection",
    "android rootbeer",
    "android anti debug",
    "android device integrity",
    "android risk detection",
    "android security detection",
]

# 有价值的关键词（用于筛选仓库）
VALUE_KEYWORDS = [
    "root", "magisk", "supersu", "kernelsu", "emulator", "genymotion",
    "bluestacks", "nox", "ldplayer", "frida", "xposed", "lsposed",
    "rasp", "anti-tamper", "anti-debug", "malware", "security",
    "detection", "detector", "checkroot", "rootbeer", "integrity",
    "play integrity", "safetynet", "hook", "tamper", "risk",
]

# 包名正则
PACKAGE_PATTERN = r'"((?:com|org|cn|io|net|me|de|eu)\.[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)"'

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("auto_discover.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ============== 网络请求 ==============
def safe_request(url: str, timeout: int = 15, headers: Dict = None) -> str:
    """安全的网络请求，带重试"""
    if headers is None:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/vnd.github.v3+json'
        }
    for attempt in range(3):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=timeout) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        except HTTPError as e:
            if e.code == 403 and 'rate limit' in str(e).lower():
                logging.warning(f"GitHub API速率限制，等待60秒...")
                time.sleep(60)
                continue
            logging.warning(f"HTTP错误 {e.code}: {url}")
            return None
        except URLError as e:
            logging.warning(f"URL错误: {url} - {e}")
            if attempt < 2:
                time.sleep(2)
        except Exception as e:
            logging.warning(f"请求失败: {url} - {e}")
            if attempt < 2:
                time.sleep(2)
    return None

# ============== GitHub搜索 ==============
def search_github(keyword: str, per_page: int = 30) -> List[Dict]:
    """搜索GitHub仓库"""
    logging.info(f"搜索关键词: {keyword}")
    url = f"{GITHUB_API}?q={quote(keyword)}&sort=stars&order=desc&per_page={per_page}"
    content = safe_request(url)
    if not content:
        return []
    try:
        data = json.loads(content)
        return data.get("items", [])
    except Exception as e:
        logging.warning(f"解析搜索结果失败: {e}")
        return []

# ============== 仓库筛选 ==============
def score_repository(repo: Dict) -> tuple:
    """给仓库评分，返回(分数, 原因)"""
    score = 0
    reasons = []
    
    # Star数评分
    stars = repo.get("stargazers_count", 0)
    if stars >= 1000:
        score += 30
        reasons.append(f"star={stars}")
    elif stars >= 500:
        score += 20
        reasons.append(f"star={stars}")
    elif stars >= 100:
        score += 10
        reasons.append(f"star={stars}")
    elif stars >= 20:
        score += 5
        reasons.append(f"star={stars}")
    
    # 更新时间评分
    updated = repo.get("updated_at", "")
    if updated:
        try:
            from datetime import datetime
            update_time = datetime.strptime(updated, "%Y-%m-%dT%H:%M:%SZ")
            days_ago = (datetime.now() - update_time).days
            if days_ago <= 30:
                score += 20
                reasons.append(f"最近更新({days_ago}天前)")
            elif days_ago <= 90:
                score += 10
                reasons.append(f"近期更新({days_ago}天前)")
            elif days_ago <= 365:
                score += 5
                reasons.append(f"年内更新({days_ago}天前)")
        except:
            pass
    
    # 描述/名称关键词评分
    name = repo.get("name", "").lower()
    description = (repo.get("description") or "").lower()
    text = name + " " + description
    
    keyword_hits = 0
    for kw in VALUE_KEYWORDS:
        if kw in text:
            keyword_hits += 1
    
    if keyword_hits >= 3:
        score += 25
        reasons.append(f"关键词命中{keyword_hits}个")
    elif keyword_hits >= 2:
        score += 15
        reasons.append(f"关键词命中{keyword_hits}个")
    elif keyword_hits >= 1:
        score += 8
        reasons.append(f"关键词命中{keyword_hits}个")
    
    # 语言评分
    language = (repo.get("language") or "").lower()
    if language in ["kotlin", "java", "rust", "c++", "c", "typescript", "javascript"]:
        score += 5
        reasons.append(f"语言={language}")
    
    return score, reasons

# ============== 验证仓库可访问性 ==============
def verify_repo_access(repo: Dict) -> tuple:
    """验证仓库的raw地址是否可访问，返回(可访问, raw_url, 包名数量)"""
    full_name = repo.get("full_name", "")
    default_branch = repo.get("default_branch", "master")
    
    if not full_name:
        return False, None, 0
    
    # 尝试常见的文件路径
    candidate_files = [
        "README.md",
        "readme.md",
        "README.MD",
    ]
    
    # 如果是Android项目，尝试常见的代码文件
    language = (repo.get("language") or "").lower()
    if language in ["kotlin", "java"]:
        candidate_files.extend([
            "app/src/main/java/com/example/demo/MainActivity.java",
            "library/src/main/java/com/framgia/android/emulator/EmulatorDetector.java",
        ])
    
    for file_path in candidate_files:
        raw_url = f"{GITHUB_RAW}/{full_name}/{default_branch}/{file_path}"
        content = safe_request(raw_url, timeout=10)
        if content:
            # 提取包名数量
            packages = re.findall(PACKAGE_PATTERN, content)
            # 过滤example/test
            valid_packages = [p for p in packages if not any(kw in p.lower() for kw in ['example', 'test', 'demo', 'sample'])]
            return True, raw_url, len(set(valid_packages))
    
    return False, None, 0

# ============== 主流程 ==============
def main():
    logging.info("=" * 60)
    logging.info("幻影核心 - 自动发现安全渠道脚本启动")
    logging.info("=" * 60)
    
    # 1. 读取现有配置
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        existing_repos = set(config.get("sources", {}).get("github_safety_repos", []))
        logging.info(f"现有渠道数量: {len(existing_repos)}")
    except Exception as e:
        logging.warning(f"读取配置失败: {e}，使用空配置")
        config = {"sources": {"github_safety_repos": []}}
        existing_repos = set()
    
    # 2. 搜索所有关键词
    all_repos = {}
    for keyword in SEARCH_KEYWORDS:
        repos = search_github(keyword, per_page=20)
        for repo in repos:
            full_name = repo.get("full_name", "")
            if full_name and full_name not in all_repos:
                all_repos[full_name] = repo
        logging.info(f"当前累计仓库数: {len(all_repos)}")
        time.sleep(2)  # 避免速率限制
    
    logging.info(f"搜索完成，共找到 {len(all_repos)} 个不同仓库")
    
    # 3. 评分筛选
    logging.info("开始评分筛选...")
    scored_repos = []
    for full_name, repo in all_repos.items():
        score, reasons = score_repository(repo)
        if score >= 15:  # 只保留评分>=15的
            scored_repos.append((score, repo, reasons))
    
    # 按分数排序
    scored_repos.sort(key=lambda x: x[0], reverse=True)
    logging.info(f"筛选后剩余 {len(scored_repos)} 个有价值仓库")
    
    # 4. 验证可访问性并提取包名
    logging.info("开始验证可访问性...")
    valid_repos = []
    for i, (score, repo, reasons) in enumerate(scored_repos[:50]):  # 只验证前50个
        full_name = repo.get("full_name", "")
        logging.info(f"验证 [{i+1}/50]: {full_name} (分数={score})")
        
        accessible, raw_url, pkg_count = verify_repo_access(repo)
        
        if accessible and raw_url:
            # 检查是否已存在
            if raw_url not in existing_repos:
                valid_repos.append({
                    "full_name": full_name,
                    "raw_url": raw_url,
                    "score": score,
                    "pkg_count": pkg_count,
                    "stars": repo.get("stargazers_count", 0),
                    "reasons": reasons
                })
                logging.info(f"  ✅ 有效！包名数量={pkg_count}, 分数={score}")
            else:
                logging.info(f"  ⏭️ 已存在，跳过")
        else:
            logging.info(f"  ❌ 无法访问，跳过")
        
        time.sleep(1)
    
    # 5. 按包名数量+分数排序
    valid_repos.sort(key=lambda x: (x["pkg_count"] * 2 + x["score"]), reverse=True)
    
    # 6. 显示结果
    logging.info("=" * 60)
    logging.info(f"发现 {len(valid_repos)} 个新的有效渠道！")
    logging.info("=" * 60)
    
    for i, repo in enumerate(valid_repos[:20]):
        logging.info(f"{i+1}. {repo['full_name']}")
        logging.info(f"   分数={repo['score']}, 包名={repo['pkg_count']}, stars={repo['stars']}")
        logging.info(f"   原因: {', '.join(repo['reasons'])}")
        logging.info(f"   URL: {repo['raw_url']}")
    
    # 7. 询问是否添加
    if valid_repos:
        print("\n" + "=" * 60)
        print(f"发现 {len(valid_repos)} 个新的有效渠道！")
        print("=" * 60)
        print("\n前20个渠道：")
        for i, repo in enumerate(valid_repos[:20]):
            print(f"{i+1}. {repo['full_name']} (分数={repo['score']}, 包名={repo['pkg_count']})")
        
        choice = input("\n是否添加到config.json？(y=添加全部, n=取消, 输入数字=添加前N个): ").strip().lower()
        
        add_count = 0
        if choice == 'y':
            add_count = len(valid_repos)
        elif choice == 'n' or choice == '':
            logging.info("用户取消添加")
            return
        elif choice.isdigit():
            add_count = min(int(choice), len(valid_repos))
        
        # 8. 添加到配置
        new_urls = [repo["raw_url"] for repo in valid_repos[:add_count]]
        existing_list = config.get("sources", {}).get("github_safety_repos", [])
        existing_list.extend(new_urls)
        # 去重
        existing_list = list(dict.fromkeys(existing_list))
        config["sources"]["github_safety_repos"] = existing_list
        
        # 9. 保存配置
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        logging.info(f"成功添加 {add_count} 个新渠道！")
        logging.info(f"当前总渠道数: {len(existing_list)}")
        
        # 10. 保存发现报告
        report = {
            "discover_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_searched": len(all_repos),
            "total_scored": len(scored_repos),
            "total_valid": len(valid_repos),
            "added": add_count,
            "new_repos": valid_repos
        }
        with open("discover_report.json", 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logging.info("发现报告已保存到 discover_report.json")
    else:
        logging.info("没有发现新的有效渠道")
    
    logging.info("=" * 60)
    logging.info("自动发现渠道完成！")
    logging.info("=" * 60)

if __name__ == "__main__":
    main()
