# 分块镜像证据核验 API

面向现场大容量磁盘分段采集（断电续传、更换目标盘、纠错重采）的证据完整性核验服务。
技术栈：**Python 3.11 · FastAPI · Pydantic v2 · SQLite（sqlite3 标准库，WAL）**。

## 解决的问题

现场只留下一个**总哈希**，无法证明各片段来自同一介质，也难以发现缺块、重叠、错序拼接。
本服务接收：

- **源介质标识与几何参数**：`media_id`、序列号/型号、扇区大小、扇区数、容量；
- **写保护器（写阻断器）校验**：只读模式、是否通过、自检固件摘要与期望值；
- **采集会话**：操作人员、工具、起止时间、中断原因（断电/换盘/纠错）；
- **分块文件**：块 ID、所属会话、**字节偏移**、长度、SHA-256、可选 Base64 内联内容、纠错关系；
- **存储副本**：采集件 `acquired`、复制件 `copy`、封存件 `archive` 及其父子链；
- **交接事件**：采集 / 复制 / 校验 / 封存 / 移交，每个事件的 `digest_before/after`。

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
| `CHUNK_CONTENT_LENGTH_MISMATCH / CHUNK_DIGEST_MISMATCH` | **硬门槛**：登记文件实际长度或重算 SHA-256 与清单声明冲突（warning 仅用于已被纠错取代的块） |
| `IMAGE_HASH_NOT_RECOMPUTABLE` | **硬门槛**：任一块无法核验时，整盘线性哈希不可重建；不再降级为 warning |
| `TOTAL_HASH_MISMATCH` | 按偏移顺序拼接真实字节重算的整盘 SHA-256 与现场总哈希不一致（可抓出错序拼接） |
| `CHUNK_DUPLICATE_RANGE`（warning） | 同区间同摘要的冗余块，自动去重保留其一 |
| `CHUNK_DIGEST_CONFLICT` | 同区间摘要不同且没有合法 `correction_of` 纠错链 |
| `CHUNK_CORRECTION_APPLIED`（warning） | 纠错块替换同区间旧块，旧块仍保留在清单中只读 |
| `CHUNK_OVERLAP` | 部分重叠，返回冲突扇区区间和涉及块 ID |
| `COVERAGE_GAP` | 未覆盖扇区区间（半开区间 `[start,end)`，可直接定位缺块） |
| `INDEX_ORDER_MISMATCH / INDEX_DUPLICATE` | 声明序号顺序与按偏移重建的块序不一致 / 序号重复 |
| `TOTAL_HASH_MISMATCH` | 线性重算的整盘 SHA-256 与现场总哈希不一致 |
| `REPLICA_CHAIN_EMPTY / REPLICA_NO_ACQUISITION`（硬门槛） | 零副本，或缺 `acquired` 采集件锚定整条链 |
| `REPLICA_PARENT_UNKNOWN / _PARENT_MISSING / _COPY_DIGEST_MISMATCH` | 副本链断裂、复制件与母本摘要不一致 |
| `CUSTODY_CHAIN_EMPTY / CUSTODY_NO_EVENTS / CUSTODY_EVENT_MISSING / CUSTODY_TERMINAL_NOT_HANDED_OVER / REPLICA_CHAIN_UNPROVEN`（硬门槛） | 零交接事件、某副本无事件、缺 acquired/copied 必需事件、末端副本未同时 sealed+transferred、无法证明采集→复制→封存移交的连续性 |
| `ACQUIRED_DIGEST_MISMATCH / REPLICA_MERKLE_MISMATCH` | 采集件摘要/Merkle 与按真实字节重建的结果不一致 |
| `CUSTODY_DIGEST_BREAK / _AFTER_BREAK / _EXPECTED_MISMATCH` | 交接前后摘要断链、封存/移交摘要与副本不一致（篡改或重封失败） |

所有 finding 都携带 `media_id`，并尽量带 `chunk_ids / session_id / replica_ids /
event_id` 与扇区区间，便于直接定位介质、区间和事件。

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
  均为 error 并拒绝封存（已被纠错取代的旧块不可读只记 warning）。证据根目录由
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
| `POST /manifests/{id}/seal` | 封存；失败 409 返回阻断性 finding |
| `GET  /manifests/{id}/findings` | 最近一次核验/封存的全部 finding |
| `GET  /manifests/{id}/evidence-package` | **可复算 JSON 证据包**（确定性序列化） |
| `POST /evidence/recompute` | 仅凭证据包原始字段复算全部摘要并逐项给 true/false |
| `GET  /diffs?left=&right=` | 两个修订版本比较（参数变化、增删块/会话/副本/事件、根差异） |
| `GET  /media/{media_id}` | 介质登记（参数在首次登记时冻结） |
| `GET  /health` | 健康检查 |

交互式文档：服务启动后访问 `/docs`（Swagger）。

### 副本/交接链最低完整性（硬门槛）

预检、封存和证据包复算都要求记录能**证明**摘要连续性，否则拒绝封存、证据包 `valid=false`：

1. 至少一个 `acquired` 副本且绑定真实采集会话，其摘要必须等于按字节重建的整盘摘要；
2. 每个 `copy/archive` 必须声明父副本，且父子 SHA-256 完全一致；
3. 每个副本至少有一个交接事件；采集件必须有 `acquired` 事件，每个复制件必须有
   `copied` 事件；
4. 链末端（无下游副本的 leaf）必须**同时**具备 `sealed` 与 `transferred` 事件；
5. 每个事件的 `digest_before` 必须承接副本摘要或上一事件的 `digest_after`，
   `digest_after`/`expected_digest` 必须恒等于副本摘要。
6. 存在一条 acquired → … → 末端的完整可达路径（`provenance_path` 写入报告）。

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
pytest -q          # 43 个用例：覆盖、重叠、错序、纠错、换盘、交接断链、
                   # 文件型分块读取/缺件/截断/错序拼接、零副本零事件、证据包复算等
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

## 目录结构

```
app/
  schemas.py    Pydantic 输入/输出模型与 finding、报告结构
  hashing.py    规范 JSON、SHA-256、线性摘要、Merkle 树
  content.py    分块内容解析：内联 Base64 或证据根内 stored_path 流式读取
  chains.py     副本/交接链最低完整性（引擎与证据包复算共用的纯函数）
  verifier.py   核验引擎（全部规则，可独立单测）
  evidence.py   证据包构造、修订比较
  db.py         SQLite 建表、事务化修订写入、封存/预检持久化
  main.py       FastAPI 路由
tests/          43 个端到端与单元测试（合成 32KiB 介质、两段断电采集、文件型分块）
```
