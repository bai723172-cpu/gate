name: 更新 VPN Gate 住宅节点

# ---------------------------------------------------------------------------
# 说明:
#   1. state/ 用 Actions 缓存持久化 → 检测结果缓存 + 数据源记忆 + 住宅留存库
#      有缓存时重复运行几乎不产生真实检测请求（避免 Cloudflare 风控的关键）
#   2. 并发 8 / 超时 25s / 单次上限 300 → 大幅降低 Worker 压力
#   3. Pages 部署「总是执行」（只有内容变化时才说明有更新，但页面必须保证存在）
#   4. 不需要 contents: write
# ---------------------------------------------------------------------------

on:
  schedule:
    - cron: '0 */2 * * *'        # 每 2 小时（想改成每天一次: '0 0 * * *'）
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: gate-update
  cancel-in-progress: false

jobs:
  update:
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps:
      - name: 检出仓库
        uses: actions/checkout@v4

      - name: 安装 Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: 安装依赖
        run: pip install -r requirements.txt

      - name: 恢复状态缓存（state/）
        uses: actions/cache/restore@v4
        with:
          path: state
          key: vpngate-state-${{ github.run_id }}
          restore-keys: |
            vpngate-state-

      - name: 运行抓取与检测
        env:
          CHECK_WORKER: ${{ secrets.DOMAIN }}
          KEEP_RESIDENTIAL_ONLY: '1'
          CHECK_CONCURRENCY: '8'
          MAX_CHECK_NODES: '300'
          CHECK_TIMEOUT: '25'
          CHECK_CACHE_TTL: '21600'
          RESIDENTIAL_KEEP_DAYS: '7'
          MAX_VPNGATE_SOURCES: '3'
          MAX_EDGE_ENDPOINTS: '30'
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NODES_URL: https://${{ github.repository_owner }}.github.io/${{ github.event.repository.name }}/nodes.txt
        run: |
          python vpngate.py 2>&1 | tee run.log
          echo "================ 关键结果 ================"
          grep -E 'OUTPUT_CHANGED|可用节点|住宅留存|候选数据源|验证通过|提交检测' run.log || true

      - name: 读取变化标记
        id: chk
        run: |
          if grep -q 'OUTPUT_CHANGED=1' run.log; then
            echo "changed=1" >> "$GITHUB_OUTPUT"
          else
            echo "changed=0" >> "$GITHUB_OUTPUT"
          fi

      - name: 保存状态缓存（state/）
        if: always()
        uses: actions/cache/save@v4
        with:
          path: state
          key: vpngate-state-${{ github.run_id }}

      - name: 检查 Pages 是否已启用
        id: pages
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          code=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            "https://api.github.com/repos/$GITHUB_REPOSITORY/pages")
          echo "Pages API status: $code"
          if [ "$code" = "200" ]; then
            echo "ok=1" >> "$GITHUB_OUTPUT"
          else
            echo "ok=0" >> "$GITHUB_OUTPUT"
          fi

      - name: 首次启用 Pages
        if: steps.pages.outputs.ok == '0'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -sS -X PUT \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            -H "Content-Type: application/json" \
            -d '{"build_type":"workflow"}' \
            "https://api.github.com/repos/$GITHUB_REPOSITORY/pages" || true
          sleep 10

      - name: 配置 Pages
        uses: actions/configure-pages@v5

      - name: 上传 Pages 产物
        uses: actions/upload-pages-artifact@v3
        with:
          path: public

      - name: 部署到 GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4

      - name: 结果汇总
        if: always()
        run: |
          echo "内容是否变化 : ${{ steps.chk.outputs.changed }}"
          echo "Pages 之前状态: ${{ steps.pages.outputs.ok }} (1=已启用 0=本次启用)"
          echo "订阅地址     : https://${{ github.repository_owner }}.github.io/${{ github.event.repository.name }}/nodes.txt"
          echo "部署结果     : ${{ steps.deployment.outcome }}"
