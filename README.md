# NW-E405 Recovery Tools

> 🚧 **Work in progress / 開発中**
>
> **診断ログの報告はこちら:**  
> https://github.com/festice32570/NW-E405-Recovery-Tools/issues/new?template=nw-e405-recovery-report.yml
>
> Sony Network Walkman **NW-E405** がファームウェア更新失敗後に `MEMORY ERROR` となり、Windowsではリムーバブルディスクが見えるものの「ディスクを挿入してください / No Media」となる症状を調査・復旧するための実験的ツールです。

## GUI版 v0.5-dev — Forensic / Preflight

現在の推奨開発版は **`NW-E405-Recovery-Lab.exe` v0.5-dev** です。

> **重要:** v0.5-devはまだ「強制フラッシュ版」ではありません。純正Updaterを再監査した結果、`CopyFileA` が失敗して `ERROR_DISK_FULL` になった場合でも制御が `FC/04` 更新開始ブロックへ合流する実装を確認しました。Issue #1の99%タイムアウトは、壊れた/不完全な更新状態でFC/04まで進んだ可能性があります。そのためv0.4-devのFC/04再送モードは撤回・Release削除し、v0.5-devからFC/04実行コードを完全に外しています。

Windows 7でも起動できる32-bitネイティブWin32 GUIです。64-bit Windows 7ではWoW64で動作します。PowerShell・Python・.NET Frameworkの追加導入は不要です。

### v0.5-devでできること

1. **NW-E405を読み取り専用で診断**
   - USB `VID_054C&PID_01FB`
   - PnP parent mapping
   - SCSI `INQUIRY`
   - `TEST UNIT READY`
   - `REQUEST SENSE`
   - `READ CAPACITY(10)`
   - Sony `FC/03` firmware-info read
   - Sony `FC/05` GetDeviceId read (`ClassifyType=3`の純正経路)
   - Sony `FC/09` GetProductInfo形状のread-only probe (`Signature=roga`)
2. **Windows環境をログ化**
   - OS version / build
   - native architecture
   - x86/WoW64
   - administrator state
3. **完全ログを即時保存**
   - `NW-E405_diag_YYYYMMDD_HHMMSS.txt`
   - `NW-E405_trace_YYYYMMDD_HHMMSS.jsonl`
   - JSONLには送信CDB、Target ID、転送方向、要求長、Win32/SCSI status、Sense、返却データを1コマンドごとに記録し、都度flushします。
4. **Sony公式日本版FWをSHA-256で検証**
   - `NW-E40X_V2_0J.exe`
     - SHA-256 `8b68cf41d193464439e8139aa593ebcf887d2dd0a2220a6135039b3ebf7a7eb7`
   - `MSFWUPGR_NW-E40X_201J.UPG`
     - size `2,131,380 bytes`
     - SHA-256 `82977775f1333892acfd4926739458cb4054a40d204e8b5d651539d77ace4691`

一致しないファイルは復旧用ファームウェアとして扱いません。

5. **状態メタデータをバイナリ保存**
   - SCSI INQUIRY
   - FC/03 FW info
   - FC/05 DeviceId
   - FC/09 ProductInfo probe
   - `NW-E405_metadata_YYYYMMDD_HHMMSS.bin`
   - これは**NOR/NANDのFWイメージではありません**。
6. **メディアが正常にREAD CAPACITYを返す個体のみ、論理ストレージをREAD(10)で丸ごと保存**
   - 本体への書き込みなし
   - 完了前は `.img.partial` として保持
   - 成功時のみ `.img` へ確定

### v0.5-devで絶対に行わないこと

- Windowsフォーマット
- パーティション操作
- セクタ書き込み
- SCSI DATA OUT
- 標準SCSI WRITE系CDB
- UPGの本体コピー
- `FC/04` update-start
- 強制フラッシュ

### なぜv0.4-devのFC/04再送を撤回したか

純正 `FWUpdaterCom.dll` の `SendFWUpdateCommand` をバイト列まで固定して再監査しました。処理は `MSFWUPGR.UPG` を `CopyFileA` した後に `FC/04` を送りますが、**CopyFileAが失敗した場合もFC/04ブロックへ合流します**。さらに `GetLastError()==0x70 (ERROR_DISK_FULL)` を明示的に判定した後も、そのFC/04ブロックへ進みます。

つまり公式が「約3 MBの空き」を要求しているのに容量不足で実行した場合、UPGコピーが正常完了していない状態でも本体側更新開始を指示し得る実装です。Issue #1の事故原因として非常に重要な候補です。

純正GUI側では `SendFWUpdateCommand` 後に本体の再列挙を待ち、`Timer=6:00` を基準に進捗を計算して100%未満を最大99%に丸めます。`TimeOut` がない場合はTimerの1.5倍、つまり約9分でタイムアウトします。そのため「99%でタイムアウト」はPCからのファイルコピーが99%だったという意味ではありません。

この新しい証拠により、故障個体へFC/04を再送する根拠はなくなりました。**v0.4-dev Releaseとtagは削除済み**です。

### Windows 7 64-bitについて

2005年の純正Updaterの公式対象はWindows 98/Me/2000/XP世代です。Sonyの後年のWindows 7対応表にもNW-E405/E407は掲載されておらず、掲載外機種はWindows 7対応予定なしとされています。

一方、純正DLLのOS判定はWindows NT 6.xを単純拒否せず、管理者権限等に応じてSCSIバックエンドを選択します。そのためWindows 7 64-bitのWoW64上でもUpdaterが更新開始まで進めてしまうこと自体はコード上説明できます。

現時点では「Windows 7 64-bitだけが故障原因」とは判断していません。むしろ純正DLLには、`CopyFileA` が `ERROR_DISK_FULL` で失敗しても `FC/04` へ進む制御フローがあり、空き容量不足は直接的な故障トリガになり得ます。Windows 7 x64は公式サポート外であり、再列挙や旧ドライバ周辺の追加リスク要因として扱います。

### 本当の強制フラッシュに必要なもの

通常の純正更新は `MSFWUPGR.UPG` をWalkmanのドライブへコピーしてから `FC/04` を送ります。しかしIssue #1は現在 `MEDIUM NOT PRESENT` で、通常のファイルコピー経路を使えません。

したがって本当の強制フラッシュには次のどちらかを確立する必要があります。

- No Media状態でもUPG/イメージを送れるSony vendor data-transfer protocol
- `XBOOT / TXD1 / RXD1` を使うCXR704060のROM/service boot protocol

後者のXBOOTがboot-mode selection inputであることは同SoCのSony資料で確認していますが、論理レベル・電圧・タイミング・UARTプロトコルはまだ未確定です。確認できるまでは短絡手順を公開しません。

詳細な解析メモは [`docs/RESEARCH.md`](docs/RESEARCH.md) にまとめています。

## v0.3.1-devで修正した点

純正 `FWUpdaterCom.dll` を再度逆アセンブルし、v0.3-devとの差分を修正しました。

- `FC/03` の受信サイズを純正 `FWInfoSize=8` に合わせて **8 bytes** に変更
- `scsipath` 経路のSCSI Pass Throughを純正と同じ **PathId=0 / TargetId=1 / Lun=0** に変更
- Sense buffer lengthを純正と同じ **18 bytes** に変更
- SCSI timeoutを純正と同じ **5 seconds** に変更
- 純正UpdaterがWindows NT系で行う `QueryDosDeviceA("X:")` → `DeviceIoControl(0x7048C)` のドライブ文字→`scsipathN`対応確認を追加
- `scsipath` のopen数、INQUIRY成功数、機種一致数、マッピング成功数をログへ追加
- `scsipath` が一つも存在しない場合、not-found / access-denied / other の内訳を表示

この変更により、次回ログでは「旧Sony/PCD scsipath層が存在しない」「存在するがNW-E405へ到達しない」「到達するがFC/03のみ拒否される」を切り分けやすくなりました。

**引き続きSCSI DATA OUT経路と `0xFC/0x04` 更新開始コマンドは含まれていません。**

## v0.3-dev: scsipath診断

v0.2.1-devの実機ログでは、通常のDisk interface経由でSCSI INQUIRYは成功した一方、`TEST UNIT READY` / `READ CAPACITY` は `NOT READY / 3A00 (Medium Not Present)`、Sony `0xFC/0x03` は `ILLEGAL REQUEST / 2000 (Invalid Command Operation Code)` になりました。

純正 `FWUpdaterCom.dll` のWindows NT系コードを再解析した結果、当時のUpdaterは `SONYSPTI` ではなく `\\.\scsipath0` ～ `\\.\scsipath25` を列挙し、そのパスに対して `IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D014)` を使用していることを確認しました。

v0.3-devでは、正しいNW-E405 USB ID (`054C:01FB`) が存在する場合に限り、`scsipath0..25` を開いて標準SCSI INQUIRYを実行します。`SONY / NWWM MEM AAD2` が確認できたパスだけで、読み取り系Sony `0xFC/0x03` を再テストします。

**SCSI DATA OUT経路および `0xFC/0x04` 更新開始コマンドはこの版にも含まれていません。**

## 機種判定の検証

NW-E405のUSB IDは **Sony VID 054C / PID 01FB** として確認しています。

v0.2.1-devでは、Sony製だからという理由だけで独自コマンドを送らないように判定を強化しました。

1. PnP上に `USB\VID_054C&PID_01FB` が存在することを確認
2. Disk interfaceの親デバイスをPnPツリーで遡り、同じVID/PIDへ到達することを確認
3. SCSI INQUIRYが公式Updaterの `ProductInfo=NWWM MEM AAD2` と整合することを確認
4. 上記すべてを満たしたDisk interfaceに限ってSony `0xFC/0x03` を送信

`NWWM MEM AAD2` は他のSonyプレーヤーでも使われる例があるため、**この文字列単独ではNW-E405判定に使用しません**。

Disk interfaceが取得できない場合は、Explorerに残っているリムーバブルドライブ文字を読み取り専用で調べるフォールバックを行います。この経路では安全のためSony独自 `0xFC` コマンドを送信しません。

## 想定している故障状態

- ファームウェア更新前の空き容量が少なかった
- 更新途中で失敗
- 本体に `MEMORY ERROR`
- サービスモードへ入れない
- USB接続自体はPCが認識する
- Explorerでは半透明のリムーバブルディスク
- 開くと「ディスクを挿入してください」
- DiskPart等では `No Media / 0 B` になる可能性がある

## 解析で分かったこと

Sony公式NW-E405/E407 Updaterを解析すると、更新コンポーネント `FWUpdaterCom.dll` はWindowsの `DeviceIoControl` とSCSI Pass Throughを使用しています。

公式Updater内には少なくとも以下のSony独自CDB処理が確認できます。

```
0xFC / 0x03   FW/デバイス情報取得に使われる読み取り経路
0xFC / 0x04   更新開始に関係する経路
```

また、純正DLLには以下のSony独自SCSIアクセス経路も含まれています。

```
\\.\SONYSPTI
\\.\scsipath%d
```

通常のDisk interfaceからアクセスできない故障個体では、これらが次の調査対象です。

## ログで特に重要な結果

### INQUIRYは成功、READ CAPACITYは失敗

USB/SCSI command pathは生きている一方、本体が内蔵Flashを通常のメディアとして公開できていない可能性があります。

### Sony 0xFC/0x03が成功

かなり重要です。Mass Storage側が `No Media` でもSony独自コマンド処理部が生存していることになり、ソフトウェア復旧の余地があります。

### USB VID/PIDは見えるがDisk interfaceがない

次段階として純正Updaterの `SONYSPTI/scsipath` 経路を調査します。

## やらないでほしいこと

故障個体に対して以下を実行しないでください。

```
Windowsのフォーマット
ディスクの管理から初期化
diskpart clean
chkdsk /f
サードパーティ製フォーマッタ
```

追加の書き込みによって復旧調査に必要な状態が変化する可能性があります。

## Roadmap

- [x] Sony公式Updaterの構造解析
- [x] FWUpdaterCom.dllのSCSI経路確認
- [x] PowerShell READ-ONLY prototype v0.1
- [x] Windows 7対応ネイティブGUI v0.2.1-dev
- [x] Windows NT系 scsipath0..25 読み取り診断 v0.3-dev
- [x] 純正Updater互換パラメータ・scsipathマッピング診断 v0.3.1-dev
- [x] v0.4-dev FC/04再送案を解析により撤回・Release/tag削除
- [x] v0.5-dev 即時Flushログ / FW検証 / FC03・FC05・FC09 read-only preflight / metadata backup / READ(10) backup
- [x] 故障実機からv0.3.1ログ収集（FC03成功 / 3A00確認）
- [ ] SONYSPTI / scsipath経路への対応
- [x] FC03 FW info / FC05 DeviceId経路の特定
- [x] FC09 / ProductInfo read-only probeを純正GetProductInfo形状から実装
- [x] UPGヘッダ / モデルID / セクション表 / E40X-E50X差分解析
- [ ] UPG高エントロピーペイロードの暗号/圧縮/署名方式解析
- [ ] No Media状態への安全なfirmware transportの発見・検証
- [ ] XBOOT ROM/service protocolの解析
- [ ] 書込み/再フラッシュ機能（十分な検証後のみ）

## Source

GUI版のソースは `src/NW-E405-Recovery-Tool.c` にあります。

Windows 7との互換性を優先して、.NETではなくWin32 APIで実装しています。ReleaseのEXEは32-bit PEとしてビルドされています。

## Sony firmwareについて

Sony公式ファームウェア、UPGファイル、純正Updaterバイナリそのものはこのリポジトリに含めません。

このリポジトリは故障した所有機器の診断・復旧研究を目的とした独立した実験プロジェクトで、Sonyとは無関係です。

## Disclaimer

開発中の実験ツールです。現在のmain/v0.5-devは読み取り専用です。書き込み系復旧機能は、No Media状態での安全なfirmware transportまたはROM/service protocolを確認し、実機検証できるまでmainへ戻しません。

---

### English

Experimental recovery research for Sony NW-E405 units stuck at **MEMORY ERROR / No Media** after a failed firmware update.

**v0.5-dev is a read-only Windows 7 forensic/preflight build. The earlier v0.4 FC/04 resume experiment was withdrawn and its release/tag deleted after a control-flow re-audit. v0.5 performs diagnostics, persistent CDB tracing, and official-firmware hash verification only.**
