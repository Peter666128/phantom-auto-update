#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
幻影核心 - 特征库自动更新工具
功能：从多渠道拉取最新风控特征，自动对比去重，推送到Gitee仓库
作者：幻影核心 PHANTOM CORE
版本：v1.0.0
"""

import json
import os
import sys
import time
import logging
import requests
from datetime import datetime
from typing import Dict, List, Set, Any

# ============== 配置加载 ==============
def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """加载配置文件，支持从环境变量读取Gitee配置（避免特殊字符问题）"""
    if not os.path.exists(config_path):
        print(f"[错误] 配置文件不存在: {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    
    # 从环境变量读取Gitee配置（优先级高于配置文件）
    gitee_owner = os.environ.get("GITEE_OWNER", "").strip()
    gitee_repo = os.environ.get("GITEE_REPO", "").strip()
    gitee_token = os.environ.get("GITEE_TOKEN", "").strip()
    
    if gitee_owner:
        config["gitee"]["owner"] = gitee_owner
    if gitee_repo:
        config["gitee"]["repo"] = gitee_repo
    if gitee_token:
        config["gitee"]["access_token"] = gitee_token
    
    # 验证Gitee配置
    if not config.get("gitee", {}).get("owner"):
        print("[错误] 未配置Gitee所有者（GITEE_OWNER）")
        sys.exit(1)
    if not config.get("gitee", {}).get("repo"):
        print("[错误] 未配置Gitee仓库（GITEE_REPO）")
        sys.exit(1)
    if not config.get("gitee", {}).get("access_token"):
        print("[错误] 未配置Gitee访问令牌（GITEE_TOKEN）")
        sys.exit(1)
    
    print(f"[信息] Gitee配置: {config['gitee']['owner']}/{config['gitee']['repo']}")
    return config

# ============== 日志配置 ==============
def setup_logging(log_file: str):
    """配置日志"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

# ============== 工具函数 ==============
def safe_request(url: str, timeout: int = 15, retries: int = 3) -> str:
    """安全的HTTP请求，带重试"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            logging.warning(f"请求失败 ({i+1}/{retries}): {url} - {e}")
            time.sleep(2)
    return ""

def version_bump(version: str) -> str:
    """版本号+0.1"""
    try:
        num = float(version.replace("v", "").replace("V", ""))
        return f"v{num + 0.1:.1f}"
    except:
        return version

import re

# ============== 特征拉取 ==============
def extract_packages_from_code(content: str) -> List[str]:
    """从代码文件中提取包名"""
    packages = set()
    # 匹配 com.xxx.xxx 格式的包名（至少两段）
    pattern = r'"(com\.[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)"'
    matches = re.findall(pattern, content)
    for m in matches:
        # 过滤掉明显不是包名的
        if any(kw in m.lower() for kw in ['example', 'test', 'demo', 'sample', 'template', 'placeholder']):
            continue
        if len(m) < 10:
            continue
        packages.add(m)
    # 匹配 Kotlin/Java 代码中的包名数组
    pattern2 = r'"((?:com|org|cn|io|net)\.[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+)"'
    matches2 = re.findall(pattern2, content)
    for m in matches2:
        if any(kw in m.lower() for kw in ['example', 'test', 'demo', 'sample']):
            continue
        if len(m) >= 10:
            packages.add(m)
    return list(packages)

def fetch_from_github_repos(repos: List[str]) -> Dict[str, List[str]]:
    """从GitHub安全仓库拉取特征（支持JSON和代码文件）"""
    result = {"packages": [], "permissions": [], "signatures": []}
    for url in repos:
        logging.info(f"正在拉取: {url}")
        content = safe_request(url)
        if not content:
            logging.warning(f"拉取失败，跳过: {url}")
            continue
        # 判断是JSON还是代码文件
        if url.endswith('.json'):
            try:
                data = json.loads(content)
                # 尝试提取包名
                if "riskPackages" in data:
                    result["packages"].extend(data["riskPackages"])
                if "packages" in data:
                    result["packages"].extend(data["packages"])
                if "riskSDKs" in data:
                    for sdk in data["riskSDKs"]:
                        if "package" in sdk:
                            result["packages"].append(sdk["package"])
                        if "signatures" in sdk:
                            result["signatures"].extend(sdk["signatures"])
                # 尝试提取权限
                if "dangerousPermissions" in data:
                    result["permissions"].extend(data["dangerousPermissions"])
                if "permissions" in data:
                    result["permissions"].extend(data["permissions"])
                logging.info(f"JSON拉取成功: {url}")
            except Exception as e:
                logging.warning(f"JSON解析失败: {url} - {e}")
        else:
            # 代码文件，提取包名
            try:
                pkgs = extract_packages_from_code(content)
                result["packages"].extend(pkgs)
                logging.info(f"代码文件拉取成功，提取到{len(pkgs)}个包名: {url}")
            except Exception as e:
                logging.warning(f"代码文件解析失败: {url} - {e}")
    # 去重
    result["packages"] = list(set(result["packages"]))
    result["permissions"] = list(set(result["permissions"]))
    result["signatures"] = list(set(result["signatures"]))
    return result

def merge_custom_features(config: Dict) -> Dict[str, List[str]]:
    """合并用户自定义特征"""
    sources = config.get("sources", {})
    return {
        "packages": sources.get("custom_packages", []),
        "permissions": sources.get("custom_permissions", []),
        "signatures": []
    }

def extract_pkg_set(packages: List) -> Set[str]:
    """从风险包名列表（可能是字符串数组或字典数组）提取字符串集合"""
    result = set()
    for item in packages:
        if isinstance(item, str):
            result.add(item)
        elif isinstance(item, dict):
            # 从字典里提取包名
            if "package" in item:
                result.add(item["package"])
            if "name" in item and "." in str(item["name"]):
                result.add(item["name"])
            if "signatures" in item:
                for sig in item["signatures"]:
                    if isinstance(sig, str) and "." in sig:
                        result.add(sig)
    return result

def convert_pkgs_to_original_format(new_pkgs: Set[str], original_format: type) -> List:
    """把新包名转换成原库的格式（字符串数组或字典数组）"""
    if original_format == str:
        return list(new_pkgs)
    else:
        # 字典格式
        return [{"name": pkg.split(".")[-1] if "." in pkg else pkg, 
                 "package": pkg, 
                 "signatures": [pkg],
                 "description": f"自动采集自情报源 - {datetime.now().strftime('%Y-%m-%d')}"} 
                for pkg in new_pkgs]

# ============== 特征对比合并 ==============
def merge_features(old_rules: Dict, new_features: Dict) -> tuple:
    """合并新特征到旧规则库，返回(新规则库, 新增数量)"""
    added_count = 0
    
    # 合并危险权限
    old_perms = set(old_rules.get("dangerousPermissions", []))
    new_perms = set(new_features.get("permissions", []))
    added_perms = new_perms - old_perms
    if added_perms:
        old_rules["dangerousPermissions"] = list(old_perms | new_perms)
        added_count += len(added_perms)
        logging.info(f"新增危险权限: {len(added_perms)}个 - {list(added_perms)[:5]}...")
    
    # 合并风险包名（兼容字符串数组和字典数组）
    old_pkgs_list = old_rules.get("riskPackages", [])
    original_pkg_format = str if (not old_pkgs_list or isinstance(old_pkgs_list[0], str)) else dict
    old_pkgs = extract_pkg_set(old_pkgs_list)
    new_pkgs = set(new_features.get("packages", []))
    added_pkgs = new_pkgs - old_pkgs
    
    if added_pkgs:
        all_pkgs = old_pkgs | new_pkgs
        old_rules["riskPackages"] = convert_pkgs_to_original_format(all_pkgs, original_pkg_format)
        added_count += len(added_pkgs)
        logging.info(f"新增风险包名: {len(added_pkgs)}个 - {list(added_pkgs)[:5]}...")
    
    # 合并风控SDK特征
    old_sdks = old_rules.get("riskSDKs", [])
    old_sdk_names = {sdk.get("name", "") for sdk in old_sdks}
    # 新包名如果不在现有SDK里，自动添加为新SDK
    for pkg in added_pkgs:
        # 简单判断：包名包含常见SDK关键词才自动加
        if any(kw in pkg.lower() for kw in ["sdk", "risk", "security", "shield", "guard", "verify"]):
            sdk_name = pkg.split(".")[-1] if "." in pkg else pkg
            if sdk_name not in old_sdk_names:
                new_sdk = {
                    "name": sdk_name,
                    "signatures": [pkg],
                    "description": f"自动采集自情报源 - {datetime.now().strftime('%Y-%m-%d')}"
                }
                old_sdks.append(new_sdk)
                old_sdk_names.add(sdk_name)
                added_count += 1
                logging.info(f"新增风控SDK: {sdk_name}")
    
    old_rules["riskSDKs"] = old_sdks
    return old_rules, added_count

# ============== Gitee操作 ==============
def get_gitee_file(config: Dict) -> Dict:
    """从Gitee获取当前文件内容（带浏览器请求头绕过WAF）"""
    gitee = config["gitee"]
    url = f"https://gitee.com/api/v5/repos/{gitee['owner']}/{gitee['repo']}/contents/{gitee['file_path']}"
    params = {"ref": gitee["branch"], "access_token": gitee["access_token"]}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": "https://gitee.com/",
        "Connection": "keep-alive"
    }
    # 重试3次
    for i in range(3):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                import base64
                data = resp.json()
                content = base64.b64decode(data["content"]).decode("utf-8")
                return json.loads(content), data.get("sha", "")
            else:
                logging.warning(f"获取Gitee文件失败 ({i+1}/3): {resp.status_code} - {resp.text[:200]}")
                time.sleep(2)
        except Exception as e:
            logging.warning(f"获取Gitee文件异常 ({i+1}/3): {e}")
            time.sleep(2)
    logging.error("获取Gitee文件失败，已重试3次")
    return None, ""

def push_to_gitee(config: Dict, content: str, sha: str = "") -> bool:
    """推送文件到Gitee（带浏览器请求头绕过WAF）"""
    gitee = config["gitee"]
    url = f"https://gitee.com/api/v5/repos/{gitee['owner']}/{gitee['repo']}/contents/{gitee['file_path']}"
    
    import base64
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
    
    data = {
        "access_token": gitee["access_token"],
        "content": content_b64,
        "message": f"自动更新特征库 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "branch": gitee["branch"]
    }
    if sha:
        data["sha"] = sha
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Referer": "https://gitee.com/",
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "keep-alive"
    }
    
    # 重试3次
    for i in range(3):
        try:
            if sha:
                resp = requests.put(url, json=data, headers=headers, timeout=30)
            else:
                resp = requests.post(url, json=data, headers=headers, timeout=30)
            if resp.status_code in [200, 201]:
                logging.info("推送到Gitee成功！")
                return True
            else:
                logging.warning(f"推送到Gitee失败 ({i+1}/3): {resp.status_code} - {resp.text[:200]}")
                time.sleep(2)
        except Exception as e:
            logging.warning(f"推送到Gitee异常 ({i+1}/3): {e}")
            time.sleep(2)
    logging.error("推送到Gitee失败，已重试3次")
    return False

# ============== 主流程 ==============
def main():
    print("=" * 60)
    print("  幻影核心 - 特征库自动更新工具 v1.0.0")
    print("=" * 60)
    
    # 加载配置
    config = load_config()
    logger = setup_logging(config.get("settings", {}).get("log_file", "auto_update.log"))
    
    # 检查Gitee配置
    gitee = config.get("gitee", {})
    if "你的Gitee私人令牌" in gitee.get("access_token", ""):
        logger.error("请先在config.json中配置你的Gitee私人令牌！")
        logger.error("获取方法：Gitee -> 设置 -> 私人令牌 -> 生成新令牌")
        sys.exit(1)
    
    logger.info("开始自动更新流程...")
    
    # 1. 从Gitee获取当前特征库
    logger.info("正在从Gitee获取当前特征库...")
    old_rules, sha = get_gitee_file(config)
    if not old_rules:
        logger.error("获取当前特征库失败，终止更新")
        sys.exit(1)
    logger.info(f"当前特征库版本: {old_rules.get('version', 'unknown')}")
    logger.info(f"当前风控SDK数量: {len(old_rules.get('riskSDKs', []))}")
    logger.info(f"当前危险权限数量: {len(old_rules.get('dangerousPermissions', []))}")
    
    # 2. 备份当前特征库
    if config.get("settings", {}).get("backup_before_update", True):
        backup_file = f"backup_risk_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(old_rules, f, ensure_ascii=False, indent=2)
        logger.info(f"已备份当前特征库到: {backup_file}")
    
    # 3. 从多渠道拉取新特征
    logger.info("正在从多渠道拉取新特征...")
    github_features = fetch_from_github_repos(config.get("sources", {}).get("github_safety_repos", []))
    custom_features = merge_custom_features(config)
    
    # 合并所有新特征
    all_new_features = {
        "packages": list(set(github_features["packages"] + custom_features["packages"])),
        "permissions": list(set(github_features["permissions"] + custom_features["permissions"])),
        "signatures": list(set(github_features["signatures"] + custom_features.get("signatures", [])))
    }
    logger.info(f"拉取到候选特征: 包名{len(all_new_features['packages'])}个, 权限{len(all_new_features['permissions'])}个")
    
    # 4. 半自动模式：显示待确认列表
    if not config.get("settings", {}).get("auto_mode", False):
        logger.info("当前为半自动模式，显示待确认特征...")
        print("\n" + "=" * 60)
        print("  待确认新特征列表")
        print("=" * 60)
        
        old_perms = set(old_rules.get("dangerousPermissions", []))
        old_pkgs = set(old_rules.get("riskPackages", []))
        
        new_perms = set(all_new_features["permissions"]) - old_perms
        new_pkgs = set(all_new_features["packages"]) - old_pkgs
        
        if new_perms:
            print(f"\n【新增危险权限】({len(new_perms)}个)")
            for p in list(new_perms)[:10]:
                print(f"  - {p}")
            if len(new_perms) > 10:
                print(f"  ... 还有{len(new_perms)-10}个")
        
        if new_pkgs:
            print(f"\n【新增风险包名】({len(new_pkgs)}个)")
            for p in list(new_pkgs)[:10]:
                print(f"  - {p}")
            if len(new_pkgs) > 10:
                print(f"  ... 还有{len(new_pkgs)-10}个")
        
        if not new_perms and not new_pkgs:
            print("\n✅ 没有发现新特征，特征库已是最新！")
            logger.info("没有新特征，无需更新")
            return
        
        print("\n" + "=" * 60)
        confirm = input("是否确认添加以上特征并推送到Gitee？(y/n): ").strip().lower()
        if confirm != "y":
            logger.info("用户取消更新")
            print("已取消更新")
            return
    
    # 5. 合并特征
    logger.info("正在合并新特征...")
    new_rules, added_count = merge_features(old_rules, all_new_features)
    
    if added_count == 0:
        logger.info("没有新特征需要添加")
        print("✅ 特征库已是最新，无需更新！")
        return
    
    logger.info(f"共新增 {added_count} 个特征")
    
    # 6. 更新版本号和时间
    if config.get("settings", {}).get("version_bump", True):
        new_rules["version"] = version_bump(new_rules.get("version", "v9.9.0"))
    new_rules["updateTime"] = datetime.now().strftime("%Y-%m-%d")
    new_rules["lastAutoUpdate"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    logger.info(f"新版本号: {new_rules['version']}")
    
    # 7. 推送到Gitee
    logger.info("正在推送到Gitee...")
    content = json.dumps(new_rules, ensure_ascii=False, indent=2)
    success = push_to_gitee(config, content, sha)
    
    if success:
        print("\n" + "=" * 60)
        print(f"  ✅ 自动更新成功！")
        print(f"  新版本号: {new_rules['version']}")
        print(f"  新增特征: {added_count}个")
        print(f"  更新时间: {new_rules['lastAutoUpdate']}")
        print("=" * 60)
        logger.info("自动更新流程完成！")
    else:
        print("\n❌ 推送到Gitee失败，请检查配置和网络")
        logger.error("自动更新失败")
        sys.exit(1)

if __name__ == "__main__":
    main()
