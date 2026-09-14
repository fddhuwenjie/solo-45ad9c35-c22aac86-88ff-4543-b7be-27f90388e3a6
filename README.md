# 分块镜像证据核验 API

面向现场大容量磁盘分段采集（断电续传、更换目标盘、纠错重采）的证据完整性核验服务。
技术栈：**Python 3.11 · FastAPI · Pydantic v2 · SQLite（sqlite3 标准库，WAL）**。

## 解决的问题

现场只留下一个**总哈希**，无法证明各片段来自同一介质，也难以发现缺块、重叠、错序拼接。
本服务接收：

- **源介质标识与几何参数**：`media_id`、序列号/型号、扇区大小、扇区数、容量；
- **写保护器（写阻断器）校验**：只读模式、是否通过、自检固件摘要与期望值；
- **采集会话**：操作人员、工具、起止时间、中断原因（断电/换盘/纠错）；
- **采集会话**：操作人员、工具、起止时间、中断原因（断电/换盘/纠错）；
  会话按采集顺序提交**读取尝试** `read_attempts`：源扇区区间、重试轮次、
  结果（成功读取/错误/填充）、工具错误码、实际读取长度、零填充/模式填充/
  稀疏洞声明，并绑定最终分块；
- **人工例外** `recovery_exceptions`：人工接受的仍未恢复扇区区间（必须说明
  理由，只能在派生修订中登记），以及封存时冻结的未恢复容忍策略
  `freeze_policy`（绝对扇区数和/或比例，缺省为零容忍）；
- **分块文件**：块 ID、所属会话、**字节偏移**、长度、SHA-256、可选 Base64 内联内容、纠错关系；
- **存储副本**：采集件 `acquired`、复制件 `copy`、封存件 `archive` 及其父子链；
- **交接事件**：采集 / 复制 / 校验 / 封存 / 移交，每个事件的 `digest_before/after`；
- **封存后巡检**：对已封存清单的副本按**种子确定性抽样计划**实读抽样区间，
  提交实读摘要或读取错误，逐段比对封存证据包；
- **多副本联合巡检**：把同一封存镜像的工作盘/异地盘/归档盘放进一个任务，
  冻结统一种子、采样比例与完成窗口，逐区间对照所有副本，区分单盘损坏与
  多副本共同异常。

服务按偏移把字节区间换算成扇区，核清覆盖、重建块序并计算 **SHA-256 线性总摘要** 与
**Merkle 根**，再追踪副本摘要从采集→复制→封存→移交的连续链。

## 核验规则（任一 error 都拒绝封存）

| 代码 | 含义 |
|---|---|
| `GEOMETRY_INCONSISTENT` | 容量 ≠ 扇区大小 × 扇区数 |
| `MEDIA_PARAMETERS_CHANGED` | 同一介质的后续修订改变了首次登记的扇区参数（中途换源/参数漂移） |
| `WRITE_BLOCKER_MISSING / _FAILED / _SELF_TEST_MISMATCH` | 缺写保校验、校验未通过、自检摘要不符 |
| `CHUNK_MISALIGNED / _OUT_OF_RANGE / _EMPTY` | 偏移或长度不按扇区对齐、越过容量、零长 |
| `CHUNK_CONTENT_UNAVAILABLE / _FILE_UNREADABLE / _FILE_OUTSIDE_ROOT / _CONTENT_BAD_BASE64` | **硬门槛**：无内联内容也无登记路径、分块文件不可读、路径逃逸证据根、Base64 非法——每块摘要必须能从真实字节复算 |
| `CHUNK_CONTENT_LENGTH_MISMATCH / CHUNK_DIGEST_MISMATCH` | **硬门槛**：登记文件实际长度或重算 SHA-256 与清单声明冲突。**所有登记块都必须通过**，包括被 `correction_of` 取代的旧块——`correction_of` 只决定哪个块代表镜像区间，不免除旧块核验 |
| `IMAGE_HASH_NOT_RECOMPUTABLE` | **硬门槛**：任一块无法核验时，整盘线性哈希不可重建；不再降级为 warning |
| `TOTAL_HASH_MISMATCH` | 按偏移顺序拼接真实字节重算的整盘 SHA-256 与现场总哈希不一致（可抓出错序拼接） |
| `CHUNK_DUPLICATE_RANGE`（warning） | 同区间同摘要的冗余块，自动去重保留其一 |
| `CHUNK_DIGEST_CONFLICT` | 同区间摘要不同且没有合法 `correction_of` 纠错链 |
| `CHUNK_CORRECTION_APPLIED`（warning） | 纠错块替换同区间旧块，旧块仍保留在清单中只读 |
| `CHUNK_OVERLAP` | 部分重叠，返回冲突扇区区间和涉及块 ID |
| `COVERAGE_GAP` | 未覆盖扇区区间（半开区间 `[start,end)`，可直接定位缺块） |
| `INDEX_ORDER_MISMATCH / INDEX_DUPLICATE` | 声明序号顺序与按偏移重建的块序不一致 / 序号重复 |
| `REPLICA_CHAIN_EMPTY / REPLICA_NO_ACQUISITION / REPLICA_CHAIN_NO_COPY_STAGE`（硬门槛） | 零副本、缺 `acquired` 采集件锚定、或唯一的 acquired 副本没有任何 `copy/archive`——即使它自身登记了 acquired+sealed+transferred 事件，未经过实际复制阶段也不能判为 proven |
| `REPLICA_PARENT_UNKNOWN / _PARENT_MISSING / _COPY_DIGEST_MISMATCH` | 副本链断裂、复制件与母本摘要不一致 |
| `CUSTODY_CHAIN_EMPTY / CUSTODY_NO_EVENTS / CUSTODY_EVENT_MISSING / CUSTODY_TERMINAL_NOT_HANDED_OVER / REPLICA_CHAIN_UNPROVEN`（硬门槛） | 零交接事件、某副本无事件、缺 acquired/copied 必需事件、末端副本未同时 sealed+transferred、无法证明采集→复制→封存移交的连续性 |
| `ACQUIRED_DIGEST_MISMATCH / REPLICA_MERKLE_MISMATCH` | 采集件摘要/Merkle 与按真实字节重建的结果不一致 |
| `CUSTODY_DIGEST_BREAK / _AFTER_BREAK / _EXPECTED_MISMATCH` | 交接前后摘要断链、封存/移交摘要与副本不一致（篡改或重封失败） |
| `RECOVERY_ATTESTATION_REQUIRED` | **硬门槛**：非空介质没有任何读取尝试记录；分块摘要匹配只证明字节哈希正确，不能证明字节来自源介质——工具在坏扇区后写的零填充/稀疏洞会与成功读取无法区分 |
| `ATTEMPT_OUT_OF_RANGE / _SESSION_UNKNOWN / _CHUNK_UNKNOWN / _CHUNK_RANGE_MISMATCH / _DUPLICATE` | 尝试越界、引用未知会话/分块、区间不落在所绑定分块内、尝试 ID 重复 |
| `ATTEMPT_ROUND_ORDER_REVERSED` | 同一会话内轮次在提交顺序中倒退（必须非递减） |
| `ATTEMPT_PARTIAL_NOT_SPLIT / _ACTUAL_LENGTH_MISMATCH` | 部分读取没有按实际读取扇区拆段（声称区间宽于 `actual_read_length`），或错误/填充尝试上报了非零读取长度 |
| `ATTEMPT_CONTENT_DIGEST_MISMATCH / _CONTENT_UNVERIFIABLE / _SUCCESS_CONFLICT / _PROVENANCE_MISSING` | 成功读取的摘要不能从所绑定分块字节复算、区间无内容可核验、同区间多次成功读取的工具摘要冲突、分块扇区完全没有尝试记录 |
| `FILL_CONTENT_MISMATCH / FILL_HOLE_UNVERIFIABLE` | 声明的零/模式填充与分块实际字节不符、声明稀疏洞但字节存在、或稀疏洞检测对该内容源不可用 |
| `UNRECOVERED_OVER_FREEZE_POLICY` | 无人工例外接受的未恢复扇区超过冻结策略；返回区间、会话和分块并拒绝封存。**显式声明的填充带有溯源，不占未恢复预算；人工接受的扇区只豁免冻结策略，永不计为已恢复** |
| `RECOVERY_EXCEPTION_ON_INITIAL / _NOT_UNRECOVERED / _DUPLICATE / _OUT_OF_RANGE` | 例外登记在初始修订、接受了已成功读取/已填充的区间（只能接受仍未恢复区）、例外区间重叠或越界。例外必须在派生修订中说明理由 |

### 坏扇区重试与填充溯源

采集会话**按顺序提交读取尝试**。后端把相互交叠的尝试区间切分成原子扇区
切片，再按"最高重试轮次、同轮按提交顺序"合并多轮结果：后续成功读取可以
取代早期失败（反之亦然），但**失败记录始终保留**。每个最终扇区段都标明：

- `read`：字节确实来自源介质，并从所绑定分块的真实字节复算工具摘要；
- `fill`：声明的零填充 / 模式填充（字节必须与声明一致）或**真实文件系统
  稀疏洞**（通过 `SEEK_DATA`/`SEEK_HOLE` 判定，平台/文件系统不支持时判为
  不可核验而非默认通过）；
- `unrecovered`：从未读到；只有被带理由的人工例外表接受才能封存，
  且只豁免冻结策略，**不**计入 `recovered_sectors`；
- `unattested`：完全没有读取尝试溯源——摘要匹配不能代替源读取证明。

`recovery_rate = read_sectors / total_sectors` 是**实际源读取率**；
`fill_rate`、`unrecovered_rate`、`accepted_sectors` 分别报告填充、未接受
未恢复和人工接受扇区。预检、`GET /recovery`、版本差异、证据包与
`/evidence/recompute` 使用同一版尝试记录、例外决定和恢复率：证据包内嵌
整版恢复状态，复算时逐字段重算比对，篡改任何一段都会使包失效。

所有 finding 都携带 `media_id`，并尽量带 `chunk_ids / session_id / replica_ids /
event_id` 与扇区区间，便于直接定位介质、区间和事件。

## 封存后完整性巡检（只追加）

封存件移交后，副本介质可能**静默损坏**；只重算整盘哈希的巡检在读取中断时
既无法定位受损扇区，也无法证明抽样范围不是事后临时挑选。本服务对 **sealed**
清单提供抽样巡检：

1. `GET /manifests/{id}/inspection-plan?seed=&sample_ratio=` 预览**确定性抽样
   计划**：必含首/尾扇区与每条块接缝两侧扇区，再按种子随机补足抽样比例；
   同一（种子, 比例, 几何, 块边界）永远生成同一计划，计划绑定证据包摘要。
2. 巡检工具对副本实读这些区间，记录每区间的实读摘要（或读取错误）、
   **读取时刻**与**设备标识**。
3. `POST /manifests/{id}/inspections` 提交巡检：记录冻结**副本、随机种子、
   抽样比例、块边界、读取时刻、设备标识**；服务按种子重新生成抽样集，
   从封存时冻结的基准逐段复算期望摘要并比对。期望摘要只来自冻结基准：
   内联字节封存时已固化；文件型分块必须先整体重读并与封存清单登记的
   长度/SHA-256 完全一致，逐段期望才可复算。登记路径在封存后被改写、
   截断或删除时基准不可还原，相关区间只能判 `inconclusive`
   （`INSPECTION_EXPECTED_UNRECOMPUTABLE`），**绝不**拿路径当前内容当
   期望去冲突一份未变化副本的正确摘要。

判定：

- `failed`：抽样区间实读摘要与封存证据**冲突**（`INSPECTION_DIGEST_CONFLICT`），
  或**副本链断裂**（副本不在封存清单中 `INSPECTION_REPLICA_UNKNOWN`、副本登记
  摘要与封存镜像摘要不符 `INSPECTION_REPLICA_DIGEST_MISMATCH`）——副本已被证明改变；
- `inconclusive`：无实证差异但无法完整核验——区间漏检
  （`INSPECTION_INTERVAL_MISSING`）、重复提交（`INSPECTION_READING_DUPLICATE`）、
  越界/超出冻结计划（`INSPECTION_READING_OUT_OF_BOUNDS`）、实读失败
  （`INSPECTION_READ_FAILED`）或封存字节已不可复算
  （`INSPECTION_EXPECTED_UNRECOMPUTABLE`）；
- `passed`：计划区间全部实读且摘要一致。

所有 finding 都携带 `replica_ids` 与扇区区间，直接定位副本和受损扇区。
**巡检记录只追加**：`inspection_id` 全局唯一，重复提交返回 409，重测必须换新
ID，永不覆盖失败结果。`GET /manifests/{id}/inspection-report` 汇总全部巡检：
累计覆盖率（只合并**真实成功读取、落在计划内且未重复**的区间；漏检、读取
失败、重复提交、越界区间一律不计，跨次巡检按扇区并集去重）、历次结果计数、
所有曾出现的差异区间及其**首次变化时间**（后续重测通过也不抹除），并绑定
证据包摘要、整盘摘要与 Merkle 根。

## 多副本联合巡检（只追加）

一份封存镜像常同时留在工作盘、异地盘和归档盘。逐副本各自巡检的报告覆盖
扇区不同，某处摘要变化后很难判断是**单盘损坏**还是**多个副本共同异常**。
联合巡检把多个副本放进同一个任务里对照：

1. `POST /manifests/{id}/joint-inspections` 创建联合任务，冻结 **sealed
   清单、证据包摘要、参与 replica、统一种子、采样比例和完成窗口**，并派生
   唯一一组种子确定性计划区间（与单副本巡检同一算法）。任务只追加：
   `joint_id` 重复返回 409；参与副本未登记在封存清单中返回 422。
2. 每个副本用**同一组种子/比例**提交普通的单副本巡检
   （`POST /manifests/{id}/inspections`），即对同一组计划区间提交实读摘要
   或读取错误。
3. `POST /manifests/{id}/joint-inspections/{joint_id}/submissions` 把该巡检
   记录**绑定**到联合任务（副本身份取自巡检记录本身；绑定同样只追加，
   补测绑定新记录，旧记录永不改写）。

服务逐区间对照封存基准与各副本，判定：

- `all-match`：所有副本与封存基准一致；
- `single-replica-deviation`：恰好一个副本偏离（单盘损坏）；
- `multi-replica-deviation`：两个以上副本共同偏离基准，
  `shared_deviation` 进一步区分它们是否返回**同一错误摘要**
  （同一错误摘要指向共同的上游损坏，不同错误摘要指向各自独立劣化）；
- `missing-read`：副本缺席、漏读、读取失败或读取越出完成窗口；
- `baseline-unrecomputable`：封存基准不可复算——此时**副本间一致也不能
  改判为通过**，基准已失，一致无所依凭。

任务保持 `inconclusive` 的情形：参与副本缺席（`JOINT_REPLICA_ABSENT`）、
读取越窗（`JOINT_READING_OUT_OF_WINDOW`）、计划区间不齐
（`JOINT_INTERVAL_MISSING`）、重复引用同一巡检记录
（`JOINT_INSPECTION_RECORD_REUSED`，记录保留但不采信）、绑定的巡检与任务
种子/比例/计划不符（`JOINT_PLAN_MISMATCH`）、绑定记录不属于参与副本
（`JOINT_REPLICA_NOT_PARTICIPANT`）或证据包摘要不符
（`JOINT_EVIDENCE_PACKAGE_MISMATCH`）。判定优先级：绑定记录证明副本链断裂
（`JOINT_REPLICA_CHAIN_BROKEN`）判 `failed`；证实偏离
（`JOINT_DIGEST_CONFLICT`）只有在联合巡检证据完整时才判 `failed`——与
缺席、越窗、区间不齐或重复引用任一条件并存时，任务保持 `inconclusive`，
冲突 finding 与差异历史照常保留，证据不足的组合不被摘要偏离覆盖。

`GET /manifests/{id}/joint-inspections/{joint_id}` 返回完整 JSON：逐区间
联合判定与逐副本单元格（各自绑定原 `inspection_id`）、**逐副本覆盖**
（当前绑定与跨绑定累计覆盖、全部绑定过的巡检记录 ID）、**差异首次出现
时间**（跨全部绑定聚合，后续补测通过也不抹除，`ever_failed` 同步保留）、
全部绑定记录与冻结的证据包摘要。联合评估是存储记录的纯函数：逐区间期望
摘要取自各巡检记录封存时冻结的结果，不在报告时重算，历史不会随证据库
状态漂移。

### 关键算法

- **覆盖重建**：把每块 `(offset, length)` 换算为扇区区间，扫描线合并，
  起点事件先于终点事件（相邻块不算重叠）。输出 `covered_intervals`、`gaps`、
  `overlaps`、`covered_sectors`。
- **块序重建**：按 `(offset, chunk_id)` 排序得到 `ordered_chunk_ids`，
  再与采集工具声明的 `index` 顺序比对。
- **Merkle 树**：叶子为块 SHA-256（按重建顺序），内部节点
  `sha256(left_bytes || right_bytes)`；奇数节点直接上提。空树返回 `null`。
- **线性总摘要（硬门槛）**：每块的真实字节优先取内联 `content_b64`，否则从登记的
  `stored_path` 流式读取（1 MiB 分块，可处理大文件），逐块核对长度与 SHA-256；
  全部通过后按 `ordered_chunk_ids` 顺序流式拼接重算整盘 SHA-256，并与
  `expected_total_sha256` 对比。文件缺失、越权路径、截断、单块摘要冲突或总哈希不符，
  均为 error 并拒绝封存。**所有登记块（包括 `correction_of` 取代的旧块）都必须
  通过读取、长度和摘要核验**：纠错只决定有效块（哪个块参与覆盖/Merkle/线性拼接），
  旧块不可读、截断或摘要冲突同样拒绝封存；旧块不参与整盘线性哈希。证据根目录由
  环境变量 `EVIDENCE_ROOTS`（冒号分隔，默认 `data/evidence`）限定，相对路径相对
  根目录解析；根目录之外的路径一律拒绝。

## 版本与封存（只追加，不可变）

- `POST /manifests` 创建修订；同一介质首次为 `change_kind=initial`；
  之后只能以 `resume`（续采）、`target-swap`（换目标盘）、`correction`（纠错）
  并携带 `parent_manifest_id` **派生修订**。
- 修订插入后，父版本立即变为 `superseded`（只读）。
  断电造成的残缺草稿无法封存，允许直接从草稿派生续采修订；
  已被取代的版本不能再次作为父本（谱系保持线性）。
- 封存只接受 `status=draft` 且报告无 error、覆盖完整、Merkle 存在的修订；
  失败返回 **409** 和全部阻断性 finding（介质/区间/事件），清单保留为草稿，
  纠正后只能再派生修订。**已封存清单永久只读**。

## 接口

| 方法/路径 | 说明 |
|---|---|
| `POST /manifests` | 提交清单修订（自动预检），201 返回修订信息与完整报告 |
| `GET  /manifests?media_id=` | 列出某介质全部修订 |
| `GET  /manifests/{id}` | 读取清单（含规范化提交原文与 `payload_digest`） |
| `POST /manifests/{id}/precheck` | 只核验不封存，任何状态可重跑 |
| `POST /manifests/{id}/seal` | 封存；成功 200 直接返回完整证据包 `evidence_package`；失败 409 返回阻断性 finding，且**不改变封存状态**（证据包在状态落库前构造，任何序列化失败都不会留下"半封存"） |
| `GET  /manifests/{id}/findings` | 最近一次核验/封存的全部 finding |
| `GET  /manifests/{id}/recovery` | 读取尝试日志、最终 read/fill/unrecovered 分段、例外决定与实际源读取率 |
| `GET  /manifests/{id}/evidence-package` | **可复算 JSON 证据包**（确定性序列化） |
| `POST /evidence/recompute` | 仅凭证据包原始字段复算全部摘要并逐项给 true/false |
| `GET  /manifests/{id}/inspection-plan?seed=&sample_ratio=` | 预览种子确定性抽样计划（首/尾、块接缝、随机扇区），绑定证据包 |
| `POST /manifests/{id}/inspections` | 提交封存后巡检（只追加，201 返回完整巡检报告；重复 ID 409） |
| `GET  /manifests/{id}/inspections` | 列出该清单全部巡检摘要 |
| `GET  /manifests/{id}/inspections/{inspection_id}` | 读取单条巡检记录与报告 |
| `GET  /manifests/{id}/inspection-report` | 巡检历史汇总：累计覆盖率、差异区间、首次变化时间、绑定证据包 |
| `POST /manifests/{id}/joint-inspections` | 创建多副本联合巡检任务（冻结参与副本/统一种子/比例/完成窗口，201 返回联合报告；重复 ID 409） |
| `GET  /manifests/{id}/joint-inspections` | 列出该清单全部联合巡检任务摘要 |
| `GET  /manifests/{id}/joint-inspections/{joint_id}` | 联合报告：逐区间联合判定、逐副本覆盖、差异首次出现时间、绑定原巡检记录 |
| `POST /manifests/{id}/joint-inspections/{joint_id}/submissions` | 把单副本巡检记录绑定到联合任务（只追加，201 返回最新联合报告） |
| `GET  /diffs?left=&right=` | 两个修订版本比较（参数变化、增删块/会话/副本/事件、根差异） |
| `GET  /media/{media_id}` | 介质登记（参数在首次登记时冻结） |
| `GET  /health` | 健康检查 |

交互式文档：服务启动后访问 `/docs`（Swagger）。

### 副本/交接链最低完整性（硬门槛）

预检、封存和证据包复算都要求记录能**证明**摘要连续性，否则拒绝封存、证据包 `valid=false`：

1. 至少一个 `acquired` 副本且绑定真实采集会话，其摘要必须等于按字节重建的整盘摘要；
2. 链中必须存在**实际复制阶段**：至少一个 `copy/archive` 副本；唯一的 acquired
   副本即使自身具备 acquired、sealed、transferred 事件，也不能判为 proven
   （`REPLICA_CHAIN_NO_COPY_STAGE` / `REPLICA_CHAIN_UNPROVEN`）；
3. 每个 `copy/archive` 必须声明父副本，且父子 SHA-256 完全一致；
4. 每个副本至少有一个交接事件；采集件必须有 `acquired` 事件，每个复制件必须有
   `copied` 事件；
5. 链末端（无下游副本的 leaf）必须**同时**具备 `sealed` 与 `transferred` 事件；
6. 每个事件的 `digest_before` 必须承接副本摘要或上一事件的 `digest_after`，
   `digest_after`/`expected_digest` 必须恒等于副本摘要。
7. 存在一条 acquired → 复制阶段 → 末端的完整可达路径（`provenance_path` 写入报告）。

零副本、零事件、缺必需事件、末端未封存移交、摘要断链或路径不可达，分别报
`REPLICA_CHAIN_EMPTY / CUSTODY_CHAIN_EMPTY / CUSTODY_EVENT_MISSING /
CUSTODY_TERMINAL_NOT_HANDED_OVER / CUSTODY_DIGEST_*_BREAK / REPLICA_CHAIN_UNPROVEN`。

### 可复算证据包

证据包包含：清单元信息（含 `payload_digest`）、**规范化提交原文**、
计算结果（块序、每块内容核验来源与结果、Merkle 根及其算法说明、线性总摘要、
副本链 `provenance_path`、覆盖/缺块/重叠）、全部 finding 与复算步骤说明；
最后对"去掉 `evidence_package_digest` 的自身"做规范 JSON 序列化再求 SHA-256，
得到包摘要。任意机器把 JSON 原样 POST 到 `/evidence/recompute` 即可验证：
`schema_ok`、`payload_digest_ok`、`chunk_content_ok`（逐块从内联内容或
`stored_path` 重读复算）、`merkle_root_ok`、`coverage_ok`、`total_hash_ok`、
`replica_custody_chain_ok`、`evidence_package_digest_ok`。

## 运行

```bash
pip install -r requirements.txt
# EVIDENCE_ROOTS 限定分块文件可读目录（冒号分隔，默认 data/evidence）
EVIDENCE_ROOTS=/var/evidence:/mnt/raid/acquisitions \
  uvicorn app.main:app --host 0.0.0.0 --port 8000
# 数据库默认在 data/evidence.db（SQLite WAL），首次启动自动建表
```

测试：

```bash
pytest -q          # 104 个用例：覆盖、重叠、错序、纠错、换盘、交接断链、
                   # 文件型分块读取/缺件/截断/错序拼接、零副本零事件、证据包复算、
                   # 坏扇区重试合并/填充溯源/稀疏洞/人工例外/冻结策略/封存原子性、
                   # 封存后巡检抽样计划/漏检/重复/越界/摘要冲突/读取失败/
                   # 副本链断裂/只追加历史与首次变化时间、
                   # 多副本联合巡检（全部一致/单副本偏离/多副本共同偏离/缺读/
                   # 基准不可复算不改判通过/缺席/越窗/区间不齐/重复引用/
                   # 补测只追加且首次差异时间保留）
```

### 请求示例（片段）

```json
{
  "change_kind": "resume",
  "parent_manifest_id": "MF-D6013C078E53",
  "media": {"media_id": "CASE-2026-042", "interface": "SATA",
    "geometry": {"sector_size": 512, "total_sectors": 64,
                 "capacity_bytes": 32768, "media_sn": "WD-XYZ12345"}},
  "write_blocker": {"blocker_id": "WB-01", "mode": "read-only",
    "checked_by": "zhao.lei", "checked_at": "2026-09-10T09:00:00+00:00",
    "passed": true},
  "sessions": [{"session_id": "S1", "started_at": "2026-09-10T09:00:00+00:00",
    "operator": "zhao.lei", "interruption": "power-loss"}],
  "chunks": [{"chunk_id": "C01", "session_id": "S1", "index": 0,
    "offset": 0, "length": 8192, "sha256": "<64 hex>",
    "content_b64": "<可选：用于现场后复算总哈希>"}],
  "replicas": [{"replica_id": "R-ACQ", "role": "acquired", "session_id": "S1",
    "sha256": "<整盘摘要>", "created_at": "2026-09-10T12:00:00+00:00"}],
  "custody_events": [{"event_id": "E1", "event_type": "sealed",
    "replica_id": "R-ACQ", "at": "2026-09-10T12:20:00+00:00",
    "actor": "qian.wu", "digest_before": "<摘要>", "digest_after": "<摘要>"}],
  "expected_total_sha256": "<现场唯一总哈希，可选>"
}
```

巡检提交示例（`POST /manifests/{id}/inspections`，区间来自
`GET .../inspection-plan?seed=daily-2026-10-01&sample_ratio=0.25`）：

```json
{
  "inspection_id": "INSP-2026-10-01-01",
  "replica_id": "R-ARC",
  "seed": "daily-2026-10-01",
  "sample_ratio": 0.25,
  "device": {"device_id": "READER-03", "model": "Tableau TD3",
             "serial": "TD3-7788", "interface": "SATA"},
  "readings": [
    {"start_sector": 0, "end_sector": 1,
     "read_at": "2026-10-01T08:00:00+00:00", "sha256": "<64 hex>"},
    {"start_sector": 15, "end_sector": 17,
     "read_at": "2026-10-01T08:00:04+00:00", "error": "medium-error: UNC"}
  ]
}
```

## 目录结构

```
app/
  schemas.py    Pydantic 输入/输出模型与 finding、报告结构
  hashing.py    规范 JSON、SHA-256、线性摘要、Merkle 树
  content.py    分块内容解析：内联 Base64 或证据根内 stored_path 流式读取
  chains.py     副本/交接链最低完整性（引擎与证据包复算共用的纯函数）
  recovery.py   读取尝试拆段合并、重试取代、填充/稀疏洞溯源、例外与冻结策略
  verifier.py   核验引擎（全部规则，可独立单测）
  evidence.py   证据包构造、修订比较
  inspection.py 封存后巡检：种子确定性抽样计划、逐段比对、只追加历史聚合
  joint.py      多副本联合巡检：冻结任务上下文、逐区间跨副本判定、只追加绑定聚合
  db.py         SQLite 建表、事务化修订写入、封存/预检/巡检/联合巡检持久化
  main.py       FastAPI 路由
tests/          104 个端到端与单元测试（合成 32KiB 介质、两段断电采集、文件型分块、
                  坏扇区重试/填充溯源/稀疏洞/人工例外/冻结策略/封存原子性、封存后抽样巡检、
                  多副本联合巡检；封存后登记文件改写/截断不误报、累计覆盖只算真实成功
                  读取区间）
```
