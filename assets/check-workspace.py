#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLMS/COSEM 课程工作区 · 校验脚本  (assets/check-workspace.py)
=============================================================

每次改完 HTML 跑一次。检查四件事：
  1. HTML 标签是否闭合（用 html.parser 的栈式检查）
  2. .html 里引用的内部资源（href/src，相对路径）是否存在
  3. #锚点链接指向的 id / name 是否真的存在
  4. data-quiz / data-frame-splitter / data-sc-decoder 组件的必要子节点是否齐全

用法：
    python assets/check-workspace.py            # 从工作区根目录跑
    python assets/check-workspace.py <root>     # 或指定根

退出码 0 = 全部通过；1 = 发现问题。
"""

import os
import re
import sys
from html.parser import HTMLParser

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# HTML 里允许不闭合的空元素
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"}
# 这些标签在 html.parser 下可能隐式闭合，宽松处理
OPTIONAL = {"li", "p", "td", "th", "tr", "option", "dt", "dd"}


class Checker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []
        self.ids = set()
        self.links = set()          # (href, line)
        self.imgs = set()           # (src, line)
        self.quiz_count = 0
        self.splitter_count = 0
        self.decoder_count = 0
        self._line = 1

    def _ln(self):
        return self.getpos()[0]

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d:
            self.ids.add(d["id"])
        if "name" in d and tag == "a":
            self.ids.add(d["name"])
        if "href" in d:
            self.links.add((d["href"], self._ln()))
        if "src" in d:
            self.imgs.add((d["src"], self._ln()))
        if "data-quiz" in d:
            self.quiz_count += 1
        if "data-frame-splitter" in d:
            self.splitter_count += 1
        if "data-sc-decoder" in d:
            self.decoder_count += 1
        if tag in VOID:
            return
        self.stack.append((tag, self._ln()))

    def handle_startendtag(self, tag, attrs):
        d = dict(attrs)
        if "id" in d:
            self.ids.add(d["id"])
        if "href" in d:
            self.links.add((d["href"], self._ln()))
        if "src" in d:
            self.imgs.add((d["src"], self._ln()))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        # 从栈顶往下找该 tag
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                # 中间若有非 OPTIONAL 的未闭合标签 → 报错
                for t, ln in self.stack[i + 1:]:
                    if t not in OPTIONAL:
                        self.errors.append(f"第 {self._ln()} 行 </{tag}> 闭合时发现未闭合的 <{t}>（起于第 {ln} 行）")
                del self.stack[i:]
                return
        self.errors.append(f"第 {self._ln()} 行出现多余的 </{tag}>（栈中没有对应开标签）")


def find_html(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for f in filenames:
            if f.lower().endswith((".html", ".htm")):
                out.append(os.path.join(dirpath, f))
    return sorted(out)


def check_html_file(path, root):
    problems = []
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    c = Checker()
    c.feed(text)
    c.close()
    problems += c.errors
    for tag, ln in c.stack:
        if tag not in OPTIONAL:
            problems.append(f"第 {ln} 行 <{tag}> 未闭合")

    base = os.path.dirname(path)

    # 内部链接
    for href, ln in c.links:
        if href.startswith(("http://", "https://", "mailto:", "javascript:")):
            continue
        if href.startswith("#"):
            if href[1:] and href[1:] not in c.ids:
                problems.append(f"第 {ln} 行锚点 #{href[1:]} 在本文件里不存在")
            continue
        target = href.split("#")[0]
        if not target:
            continue
        if target.lower().endswith((".md", ".py", ".js", ".css")) or True:
            tpath = os.path.normpath(os.path.join(base, target))
            if not os.path.exists(tpath):
                problems.append(f'第 {ln} 行链接文件不存在：{href}')
            elif "#" in href:
                frag = href.split("#", 1)[1]
                if frag:
                    try:
                        with open(tpath, "r", encoding="utf-8") as fh:
                            if not re.search(r'(id|name)\s*=\s*["\']' + re.escape(frag) + r'["\']', fh.read()):
                                problems.append(f"第 {ln} 行跨文件锚点不存在：{href}")
                    except Exception:
                        pass

    # 脚本/样式引用
    for src, ln in c.imgs:
        if src.startswith(("http://", "https://", "data:")):
            continue
        tpath = os.path.normpath(os.path.join(base, src))
        if not os.path.exists(tpath):
            problems.append(f"第 {ln} 行引用的资源不存在：{src}")

    # 组件检查
    if c.quiz_count:
        if 'data-quiz' in text:
            n_opts = len(re.findall(r'<ul class="opts"', text))
            n_ans = len(re.findall(r'data-correct="true"', text))
            if n_opts != c.quiz_count:
                problems.append(f"data-quiz 有 {c.quiz_count} 个，但 <ul class=\"opts\"> 只有 {n_opts} 个")
            if n_ans != c.quiz_count:
                problems.append(f"data-quiz 有 {c.quiz_count} 个，但 data-correct=\"true\" 只有 {n_ans} 个")
        if 'quiz.js' not in text:
            problems.append("有 data-quiz 但没引用 assets/quiz.js")
    if c.splitter_count and 'frame-splitter.js' not in text:
        problems.append("有 data-frame-splitter 但没引用 assets/frame-splitter.js")
    if c.decoder_count and 'sc-decoder.js' not in text:
        problems.append("有 data-sc-decoder 但没引用 assets/sc-decoder.js")

    return problems


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    root = os.path.abspath(root)
    files = find_html(root)
    print(f"校验根目录：{root}")
    print(f"发现 {len(files)} 个 HTML 文件\n")

    total = 0
    for p in files:
        rel = os.path.relpath(p, root)
        probs = check_html_file(p, root)
        if probs:
            total += len(probs)
            print(f"✗ {rel}")
            for x in probs:
                print(f"    - {x}")
        else:
            print(f"✓ {rel}")

    print()
    if total:
        print(f"结论：发现 {total} 个问题 ✗")
        return 1
    print("结论：全部通过 ✓（标签闭合 / 内部链接 / 锚点 / 组件引用）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
