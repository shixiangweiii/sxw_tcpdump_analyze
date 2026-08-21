# TCP 时序图"动态演示"功能实施方案

## 目标

在连接工作台的**现有梯形图**上增加单步播放的渐进式动画：点击"动态演示"进入演示模式（梯形图收起为只剩生命线），每点一次"播放"推进一个包——先播放包图标从发送端飞到接收端的动画，落笔后该行正式渲染，同时右栏"当前包信息条"更新，有 `appSpan` 的包额外触发现有的报文正文联动。控制仅三键：播放（单步）、重播、退出。core / server / api 一行不动。

## 状态机（放在 ConnectionWorkbench，单一 state 对象避免组合不一致）

```ts
interface DemoState {
  active: boolean;        // 是否处于演示模式
  playedCount: number;    // 已落笔的包数（0..N）
  flyingIndex: number | null; // 正在飞行的包下标（connection.packets 的下标）
}
```

状态迁移：

- **enter**（点击"动态演示"）：`{active:true, playedCount:0, flyingIndex:null}`，`setSelectedPacket(null)`
- **step**（点击"播放"，`flyingIndex===null && playedCount<N` 时可用）：`flyingIndex = playedCount`
- **flightEnd**（飞行元素 `onAnimationEnd`）：`playedCount = flyingIndex+1`、`flyingIndex=null`、`setSelectedPacket(packets[playedCount-1].packetIndex)` ——选中即复用现有 `selectedSpan → HttpTransactions` 自动展开+高亮链路；信息条同刻更新（"落笔时更新"）
- **replay**：回到 enter 后的状态（作废进行中的飞行）
- **exit**：`{active:false,...}`，`setSelectedPacket(null)`，梯形图恢复静态全图
- **切连接**：并入现有 `useEffect(..., [connection.id])` 清选中态的 effect，一并复位 demo

## 文件改动（共 5 个，全在 packages/web）

### 1. `src/packet-text.ts`（新建，小工具模块）

- 从 `LadderDiagram.tsx` 移出 `formatSeq`（seq/ack/len/win 那行文本），信息条与梯形图共用，避免两处各写一份
- 增加 `directionText(direction)` → `客户端 → 服务端` / `服务端 → 客户端`

### 2. `src/components/DemoInfoBar.tsx`（新建）

右栏顶部的"当前包信息条"，演示模式下每一步都显示（TLS/非 HTTP 连接它是有且仅有的讲解内容）：

- 未开播（playedCount===0）：提示"点击「播放」开始，这条连接共 N 个包"
- 播放中：`第 k / N 包 · #packetIndex · 方向 · [flags]` + `formatSeq` 那行 + 人话注解 `note`，有 `appNote`/异常注解时顺带列出
- 样式沿用项目约定（`--panel` 底、`--border` 边框、`--mono` 字段、`.chip` 风格的 flags）

### 3. `src/components/ConnectionWorkbench.tsx`

- 上述 demo 状态机与动作函数
- 头部：非演示时在 `.workbench-nav` 左侧放"▶ 动态演示"按钮（`connection.packets.length === 0` 时禁用）；演示时原位换成工具条 `[播放下一包] [↺ 重播] [退出演示]`——飞行中或播完（playedCount===N）时播放键禁用，重播/退出随时可用
- Esc：改为演示模式下先退演示、非演示才 `onClose()`（注意 effect 依赖）
- 右栏 `.pane-messages` 顶部（QualityNotes 之前）渲染 `<DemoInfoBar>`
- 向 `LadderDiagram` 传 `demo` prop（`{playedCount, flyingIndex} | null`）与 `onFlightEnd`

### 4. `src/components/LadderDiagram.tsx`

- `demo` prop 为 null 时走现有逻辑不动
- 演示模式下：
  - 只渲染 `packets.slice(0, playedCount)`，`bodyHeight = max(playedCount, 3) * rowHeight + 16`（开局保留约 3 行高度，只剩生命线也像张图；生命线随高度自然生长）
  - 已播行包进 `<g className="demo-row-in">` 触发入场淡入动画；行的点击热区不挂事件、不加 `clickable`（演示中选中只由播放驱动）
  - 飞行图标：外层 `<g transform="translate(140, y)">`（SVG 属性定位行 Y 与起点 X，`y = flyingIndex * rowHeight + rowHeight/2`），内层 `<g className="demo-fly c2s|s2c">` 用 CSS keyframes 平移 0→330px（330 = RIGHT_LANE−LEFT_LANE，s2c 用 `animation-direction: reverse`，一条 keyframes 服务两个方向），图标为小圆角矩形 + flags 文本（如 `SYN`、`PSH·ACK`），挂 `onAnimationEnd={onFlightEnd}`，处理函数里加 stale 防护（重播/退出瞬间撞上动画结束的竞态）
- 自动滚动：useEffect 监听 `demo.active` / `playedCount`，直接操作 `.ladder` 容器 `scrollTop`（进入演示滚回顶部；每步落笔把新行滚到容器视口中线附近）——不使用 scrollIntoView，避免连带滚动外层容器

### 5. `src/styles.css`

- `@keyframes demo-fly-right`（translateX 0→330px，注释标明须与 LadderDiagram 的 `RIGHT_LANE-LEFT_LANE` 同步）；`.demo-fly.c2s` / `.demo-fly.s2c`（600ms ease-in-out forwards）
- `@keyframes demo-fade-in`（opacity 0→1，250ms）+ `.demo-row-in`
- 飞行图标 `.demo-packet`（accent 系配色）、工具条 `.demo-btn`（沿用 `.nav-btn` 风格）、信息条 `.demo-info` 样式
- `@media (prefers-reduced-motion: reduce)`：动画时长压到近 0——飞行瞬时完成但 `animationend` 仍触发，功能不变

## 已定的行为细节（此前与你确认过的）

- 每步动画时长固定 600ms，不按真实时间差缩放；真实 Δ 仍显示在时间列
- 信息条在**落笔时**更新，飞行中的图标本身带 flags 即为发送时刻的反馈
- 演示模式下梯形图行不可点选；退出后恢复现有交互
- 有 `appSpan` 的包在落笔时联动右栏展开事务并高亮正文段落（完全复用现有逻辑，零新代码）

## 验证

1. `packages/web` 下 `npm run build`（tsc --noEmit + vite build）
2. `npm run dev` 起服务，浏览器实测（browser-use）：
   - `测试文件/http/packet-http.pcap`：进演示 → 逐步播过握手/请求/响应，验证飞行方向、落笔、信息条内容、右栏事务自动展开与正文高亮、自动滚动；重播复位、退出恢复全图
   - `测试文件/https/packet2.pcap`：全程无 appSpan，验证每步只有信息条也讲得通
   - 边界：飞行中连点播放（应无效）、飞行中重播/退出（应干净取消）、播放到末尾（播放键禁用）、演示中按 Esc（退演示不退页面）、演示中切换上/下一条连接（演示复位）
