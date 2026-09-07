# 制品与 Google Tink 版本的兼容关系

本文件记录 `tink-gm-crypto` 与 `com.google.crypto.tink:tink` 各版本之间的兼容关系，是版本适配验证的唯一登记处。每次对某个 Tink 版本完成验证后，请在本文件的矩阵中补充/更新一行。

## 版本约定

- pom.xml 中 `tink.version` 属性声明所依赖的 Tink 版本，当前默认 **1.23.0**。
- 制品版本号前缀标识其基于的 Tink 版本：例如 `1.23.0.0` 表示基于 `tink:1.23.0` 开发（历史版本 `1.17.0.0` 基于 `tink:1.17.0`）。
- 代码对 Tink 的最低要求见下方“重要分界”。

## 验证方法

对指定版本做全量验证（不改动 pom）：

```shell
./mvnw test -Dtink.version=<版本号>
# 或
./scripts/verify-tink-version.sh <版本号>   # 省略版本号 = 使用 pom 默认值
```

结果判据：主代码与测试全部编译通过，且全部单元测试通过（当前套件 108 个用例）。

## 兼容矩阵

| Tink 版本 | 制品版本 | 构建与测试 | 最近验证 | 说明 |
| --- | --- | --- | --- | --- |
| 1.23.0 | 1.23.0.0 | ✅ 编译通过，108/108 | 2026-09-07 | 默认目标版本（`tink.version`=1.23.0）；使用公开序列化 API |
| 1.22.0 | 1.23.0.0 | ✅ 编译通过，108/108 | 2026-09-07 | 当前源码的支持下限 |
| 1.21.0 | — | ❌ 主代码编译失败 | 2026-09-07 | 分界点：仍为 `internal.*` 序列化 API，与当前源码不兼容 |
| 1.18.0 ~ 1.20.0 | — | ❌ 预期不兼容（同 1.21.0） | 未逐一实测 | 使用旧 `internal` 序列化 API |
| 1.17.0 | 1.17.0.0 | ✅（历史状态） | 2026-09-07 | 适配前的仓库基线（commit `6ac4e72`）下 92/92 通过，pom `tink.version`=1.17.0 |

> 说明：“验证”指以本仓库当前工作区代码执行上述命令得到的结果；“1.17.0.0”行记录的是适配改造**之前**的历史仓库状态，不代表当前源码仍可在 1.17.0 上构建。

## 重要分界：Tink 1.22.0 的序列化 API 重构

Tink 在 1.22.0 对序列化 API 做了重构（旧 API 存在于 1.21.0 及更早，1.22.0 起移除）：

- `com.google.crypto.tink.internal.ProtoKeySerialization` / `ProtoParametersSerialization`
  → 移入公开顶层包 `com.google.crypto.tink`（并内置 `KeyMaterialType`、`OutputPrefixType`）；
- `ParametersParser` / `KeyParser` 改为非泛型、以字符串 `typeUrl` 标识，
  `ParametersSerializer` / `KeySerializer` 泛型参数由 2 个减为 1 个；
- `MutableKeyCreationRegistry.KeyCreator` → 独立类 `com.google.crypto.tink.internal.KeyCreator`。

因此：

- **Tink ≥ 1.22.0**：由当前主代码支持（已实测 1.22.0、1.23.0）。
- **Tink ≤ 1.21.0**：需要基于旧 `internal` API 的历史版本代码（即 `1.17.0.x` 时代的仓库状态），当前主代码无法编译（1.21.0 已实测）。

## 其他适配点（与 Tink 版本相关的维护项）

- `src/test/java/com/google/crypto/tink/` 下随仓库维护的 Tink 测试支持类
  （`Asserts`、`KeyTester`、`FakeMonitoringClient`、`StreamingTestUtil`、`TestUtil` 等）
  目前与 tink-java **v1.23.0** 源码一致。升级/验证其他 Tink 版本时，建议从对应 tag 同步这些文件，
  以免其引用的内部 API 与新版本不兼容。
- 若某次验证失败，请把失败信息（首个编译错误或失败用例）记入本表对应行的“说明”，便于追溯。

## 登记流程（升级到新 Tink 版本时）

1. `./scripts/verify-tink-version.sh <新版本>` 运行全量验证；
2. 若通过：在矩阵中新增一行（版本、制品版本、✅、日期）；
3. 若失败：定位并适配代码/测试后重跑，直至通过；
4. 决定是否将 pom 默认 `tink.version` 与制品版本号升级到该版本，并同步更新 README 与本文件。
