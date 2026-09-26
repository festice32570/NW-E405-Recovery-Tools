## GUI版 v0.8.3-dev — Authentic E40X FC/05+roga GetDeviceId Probe

v0.8.3-devは、v0.8.2でordinary Diagnosticsから誤って送っていたsignature-less FC/05を撤去し、Sony純正E40X `ClassifyType=3` の正規GetDeviceId queryを独立したRecovery Stage 2Dとして実装した研究版です。

- ordinary DiagnosticsはFC/05を送信しない。従来どおりFC/03とhistorical FC/09+`roga` read queryのみ
- Stage 2D exact CDB: `FC 00 05 72 6F 67 61 00 00 10 00 00`
- directionはDATA INのみ、要求長は16 bytes
- Stage 2D直前に `INQUIRY + TUR + READ CAPACITY + FC/03` をfresh revalidationし、Issue #1状態から外れていればFC/05を送信しない
- preflight通過後にも別の明示確認を出し、送信は1回だけ。retry・DATA OUT・FC/04・follow-up vendor commandは自動送信しない
- 成功条件は `IOCTL OK && SCSI GOOD && returned DataTransferLength == 16 && copied length == 16`
- 0-byte、1～15-byte、over-length、CHECK CONDITION、non-GOOD、IOCTL failureはすべて失敗扱い
- 完全16-byte GOODだけを `NW-E405_FC05_DEVICEID_PRIVATE_<session>.bin` としてPRIVATE保存し、PUBLIC_REPORTにはraw/first-6/decoded値を出さず、SCSI要約・要求/実転送長・成功時SHA-256だけを記録
- Sony API上の名称は `pbDeviceId`。E40X updaterが更新前後のcontinuity確認に使うのは先頭6 bytesだが、16 bytesをserial numberとは決めつけない
- all-zero / partially-zeroな完全16-byte responseはtransport-completeとして扱うが、device-side semantic meaningは付与しない
- Stage 2A/2B/2C、SONYICD Set/Reset禁止、format/erase禁止、standard SCSI WRITE禁止、fixed A3以外のDATA OUT禁止、FC/04 safety gateは維持

**v0.8.2履歴:** v0.8.2のsignature-less CDB `FC 00 05 00 00 00 00 00 00 10 00 00` は実機で `05/20/00`、actual length 0でした。この結果は正規FC/05+`roga`のsupport/unsupportedを示しません。v0.8.3の正規queryは別物として扱います。

公開Issueへ添付するのは `NW-E405_PUBLIC_REPORT_*.txt` **だけ**です。TXT/JSONL/metadata/IMG/UPG/FC05_DEVICEID/DvID/FB/SONYICD blobはPRIVATEです。

---

# NW-E405 Recovery Tools

> 🚧 **Work in progress / 開発中**
>
> **診断ログの報告はこちら:**  
> https://github.com/festice32570/NW-E405-Recovery-Tools/issues/new?template=nw-e405-recovery-report.yml
>
> Sony Network Walkman **NW-E405** がファームウェア更新失敗後に `MEMORY ERROR` となり、Windowsではリムーバブルディスクが見えるものの「ディスクを挿入してください / No Media」となる症状を調査・復旧するための実験的ツールです。

## GUI版 v0.7-dev — Recovery Ladder

現在の研究開発版は **`NW-E405-Recovery-Tool.exe` v0.8.3-dev** です。Windows 7 x64では32-bit Win32アプリとしてWoW64で動作し、.NET / PowerShell / Pythonは不要です。

v0.7は「診断だけ」ではなく、Issue #1の既知状態と一致した場合に**段階的な復旧アクション**へ進みます。

1. **Stage 1: No Media LBA rescue**
   - `READ(10)` LBA0 / 512 bytesだけを直接試行
   - 読めればFAT/MBRを解析してREAD(10)のみでIMG化
   - `MSFWUPGR.UPG`をFATクラスタチェーンから抽出し、Sony公式v2.0 SHA-256と比較
2. **Stage 2: Sony MP3FM A3/A4 Device-ID query**
   - Stage 1でLBA0も読めない場合だけ提示
   - NW-E405実機のSony MP3 File Manager通信キャプチャ由来の固定シーケンス
   - A3: fixed 12-byte CDB + fixed 20-byte select DATA OUT (`00 12` + zeroes)
   - A4: 18-byte DATA IN。先頭 `00 10` + 16-byte Device-ID recordを期待
   - 生DvIDはPRIVATEファイルだけに保存。公開レポートにはSHA-256しか出しません
3. **Stage 3: gated FC/04 update resume**
   - FATから正規に抽出した本体内 `MSFWUPGR.UPG` が公式v2.0とSHA-256完全一致
   - FAT空き容量から推定した更新前空きがSonyの約3 MB条件に矛盾しない
   - Sony公式 `NW-E40X_V2_0J.exe` を同セッションで検証済み
   - 現在もIssue #1の `VID/PID + SONY/NWWM + TUR 3A00 + CAP 3A00 + known FC03` 状態
   - 上記を送信直前にも再確認
   - 二重確認後に純正Updaterと同じ**no-data FC/04を1回だけ**送信
   - 以後は追加のwrite/update commandを送らず、USB切断→再認識だけを約9分監視

### 公開/非公開ログ

GitHub Issueへ添付するのは **`NW-E405_PUBLIC_REPORT_*.txt` だけ**にしてください。これはRaw DvID、音楽データ、IMGセクタ、vendor response本文を含みません。

次はPRIVATE扱いです。公開Issueへそのまま貼らないでください。

- `NW-E405_diag_*.txt`
- `NW-E405_trace_*.jsonl`
- `NW-E405_metadata_*.bin`
- `NW-E405_DvID_PRIVATE_*.bin`
- `NW-E405_LBA0_*.bin`
- `NW-E405_rescue_*.img` / `.partial`
- 抽出したUPG

### v0.7で許可している本体向けアクション

- DATA IN / no-data診断コマンド
- READ(10)
- **固定A3 select DATA OUT 1種類だけ**
- 条件をすべて満たした場合の**FC/04 update-start 1回だけ**

標準SCSI `WRITE(10/12)`、WRITE BUFFER、フォーマット、パーティション書き込み、任意DATA OUT、任意vendor writeは実装しません。

---

## 過去版: v0.6.1-dev — No Media Rescue / Forensic

v0.6.1-devはNo Media救出経路を確立した読み取り専用の過去版です。現在はv0.7-devを推奨します。

> **重要:** v0.6.1-devはまだ「強制フラッシュ版」ではありません。MSVCの例外テーブルまで含めて純正Updaterを再監査した結果、`CopyFileA` が失敗した場合は例外ハンドラで `SendFWUpdateCommand` が中止され、`FC/04` へ進まないことを確認しました。一方、純正GUIが99%待機へ入るのは `SendFWUpdateCommand` が成功した後です。Issue #1ではUPGコピーとFC/04開始までは成功し、その後の本体側更新または再起動・再列挙で失敗した可能性が高いと見ています。v0.4-devの単純なFC/04再送は、この失敗を繰り返す可能性があるため撤回したままです。

Windows 7でも起動できる32-bitネイティブWin32 GUIです。64-bit Windows 7ではWoW64で動作します。PowerShell・Python・.NET Frameworkの追加導入は不要です。

### v0.6.1-devでできること

1. **NW-E405を読み取り専用で診断**
   - USB `VID_054C&PID_01FB`
   - PnP parent mapping
   - SCSI `INQUIRY`
   - `TEST UNIT READY`
   - `REQUEST SENSE`
   - `READ CAPACITY(10)`
   - Sony `FC/03` firmware-info read
   - Sony `FC/09` GetProductInfo形状のhistorical read-only probe (`Signature=roga`)
   - 正規 `FC/05+roga` GetDeviceIdはordinary Diagnosticsでは送信せず、Recovery Stage 2Dのfresh preflight + explicit confirmation後だけ1回送信
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
   - FC/09 ProductInfo probe
   - 正規FC/05+`roga`のraw 16 bytesはmetadataではなく専用PRIVATE blobへ保存
   - `NW-E405_metadata_YYYYMMDD_HHMMSS.bin`
   - これは**NOR/NANDのFWイメージではありません**。
6. **メディアが正常にREAD CAPACITYを返す個体のみ、論理ストレージをREAD(10)で丸ごと保存**
   - 本体への書き込みなし
   - 完了前は `.img.partial` として保持
   - 成功時のみ `.img` へ確定


### v0.6.1-dev: No Media救出

Issue #1の実機ログと完全一致した場合だけ「No Media救出」ボタンを有効にします。

1. `READ CAPACITY(10)` が `3A/00 MEDIUM NOT PRESENT` でも、`READ(10)` で **LBA0を512 bytesだけ直接読み出す**。
2. 読めた場合はLBA0を保存し、FAT12/16/32のBPBまたはMBRパーティションを解析して論理容量を推定する。
3. 推定に成功した場合だけ、ユーザー確認後に `READ(10)` のみで論理ストレージのイメージを作成する。
4. イメージ完成後、FATルートの `MSFWUPGR.UPG` をクラスタチェーンから抽出する。
5. FAT管理情報が壊れていても、イメージ全体から `UPGR_FMT` / `SONY` / `00100000` を探索し、連続したUPG候補を切り出す。
6. 抽出した候補を日本版公式v2.0 UPGのSHA-256 `82977775...ace4691` と比較する。

これにより、正常な別個体がなくても「公式UPGが完全な状態で残っている」「UPG候補はあるが破損している」「論理NAND自体がREAD(10)で読めない」を切り分けられます。

すべてのデバイスアクセスはDATA INまたはno-dataの読み取り/問い合わせで、`FC/04`、SCSI DATA OUT、WRITE(10/12)、WRITE BUFFERは含みません。

### v0.6.1-devで絶対に行わないこと

- Windowsフォーマット
- パーティション操作
- セクタ書き込み
- SCSI DATA OUT
- 標準SCSI WRITE系CDB
- UPGの本体コピー
- `FC/04` update-start
- 強制フラッシュ

### なぜv0.4-devのFC/04再送を撤回したか

純正 `FWUpdaterCom.dll` の `SendFWUpdateCommand` を、MSVC C++例外処理の `FuncInfo / TryBlockMap / HandlerMap` まで含めて再監査しました。

処理は概ね次の通りです。

1. `MSFWUPGR.UPG` を `CopyFileA` でWalkmanへコピー
2. コピーが失敗した場合はエラー値を作り、内部例外ヘルパから `RaiseException`
3. `SendFWUpdateCommand` のcatch handler (`0x10005287`) が例外を受け、エラー復帰
4. コピー成功時だけ通常経路でSony `FC/04` update-startへ進む

つまり、以前の「容量不足でCopyFileが失敗してもFC/04へ進む」という解析は誤りでした。v0.5.1-devではこの誤りを訂正し、例外テーブルまでテストで固定しています。

さらに純正GUI側では、`SendFWUpdateCommand` が成功した**後**に本体の再列挙待ちへ入り、`Timer=6:00` を基準に経過時間から進捗を作ります。100%以上になる値は99%へ丸め、期待するデバイス状態を検出したときだけ100%を表示します。`TimeOut` が未指定の場合はTimerの1.5倍、つまり約9分です。

したがってIssue #1の「99%でタイムアウト」は、PC→WalkmanへのUPGコピーが99%だったという意味ではありません。**UPGコピーとFC/04開始処理が成功を返した後、本体が期待する状態で戻らなかった**ことを示します。

このため、同じ個体へ根拠なくFC/04を再送することも安全とは言えません。最初のFC/04後にNOR/管理領域が途中まで更新されている可能性があるため、v0.4-dev Release/tagは削除済みです。

### Windows 7 64-bitについて

2005年の純正Updaterの公式対象はWindows 98/Me/2000/XP世代です。Sonyの後年のWindows 7対応表にもNW-E405/E407は掲載されておらず、掲載外機種はWindows 7対応予定なしとされています。

一方、純正DLLのOS判定はWindows NT 6.xを単純拒否せず、管理者権限等に応じてSCSIバックエンドを選択します。そのためWindows 7 64-bitのWoW64上でもUpdaterが更新開始まで進めてしまうこと自体はコード上説明できます。

現時点では「Windows 7 64-bitだけが故障原因」とは判断していません。Issue #1が99%待機まで到達したことから、純正UpdaterのPC側コピー/開始処理は成功した可能性が高いです。Windows 7 x64は公式サポート外なので、更新後の再列挙や旧ドライバ周辺の追加リスク要因として扱います。

空き容量については、公式UPGが `2,131,380 bytes` である一方、Sonyは約3 MBの空きを要求しています。99%待機へ入ったならUPGコピー自体は成功した可能性が高いため、「コピーできないほど空きが無かった」よりも、**UPGは置けたがSony推奨の約3 MB未満で、本体側の展開・作業領域が不足した**可能性を仮説として重視します。ただし、これは現時点でSonyが原因として明記した事実ではありません。

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
- [x] v0.5-dev 即時Flushログ / FW検証 / FC03・historical signature-less FC05・FC09 read-only preflight / metadata backup / READ(10) backup
- [x] v0.5.1-dev MSVC例外処理まで含む純正Updater再監査 / 99%進捗ロジック固定テスト
- [x] v0.6.1-dev No Media LBA0 direct READ(10) / FAT・MBR解析 / rescue image / MSFWUPGR.UPG抽出・公式SHA比較
- [x] 故障実機からv0.3.1ログ収集（FC03成功 / 3A00確認）
- [ ] SONYSPTI / scsipath経路への対応
- [x] FC03 FW info / 正規E40X ClassifyType=3 FC05+`roga` GetDeviceId経路の特定とv0.8.3 Stage 2D化
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

開発中の実験ツールです。現在のmain/v0.6.1-devは読み取り専用です。書き込み系復旧機能は、No Media状態での安全なfirmware transportまたはROM/service protocolを確認し、実機検証できるまでmainへ戻しません。

---

### English

Experimental recovery research for Sony NW-E405 units stuck at **MEMORY ERROR / No Media** after a failed firmware update.

**v0.6.1-dev is a read-only Windows 7 No-Media rescue/forensic build. The earlier v0.4 FC/04 resume experiment was withdrawn and its release/tag deleted after a control-flow re-audit. v0.6.1 adds gated No-Media LBA0 rescue, FAT/MBR imaging, recovered-UPG comparison, and stricter MBR/BPB bounds while remaining device-side read-only.**
