# NW-E405 Recovery Tools

> 🚧 **Work in progress / 開発中**
>
> **診断ログの報告はこちら:**  
> https://github.com/festice32570/NW-E405-Recovery-Tools/issues/new?template=nw-e405-recovery-report.yml
>
> Sony Network Walkman **NW-E405** がファームウェア更新失敗後に `MEMORY ERROR` となり、Windowsではリムーバブルディスクが見えるものの「ディスクを挿入してください / No Media」となる症状を調査・復旧するための実験的ツールです。

## GUI版 v0.4-dev

現在の推奨版は **`NW-E405-Recovery-Tool.exe`** です。

Windows 7でそのまま起動できる32-bitネイティブWin32 GUIアプリです。64-bit Windows 7でも動作する構成で、PowerShell・Python・Linux・.NET Frameworkの追加導入は不要です。

### 使い方

1. 故障したNW-E405をUSBハブを使わずPCへ直接接続します。
2. Releaseから `NW-E405-Recovery-Tool.exe` をダウンロードします。
3. EXEを起動します。UACが表示されたら許可します。
4. **「NW-E405を診断する」** を押します。
5. 結果が画面に表示され、同じフォルダへ次のログが保存されます。

```
NW-E405_diag_YYYYMMDD_HHMMSS.txt
```

6. **「結果をコピー」** またはログファイルを使って結果を共有してください。

## v0.4-devで実行する処理

Stage 1は意図的に **READ-ONLY** です。

- USB/PnPでSony NW-E405のVID/PIDを確認
- WindowsのDisk interfaceを列挙
- SCSI `INQUIRY`
- `TEST UNIT READY`
- `REQUEST SENSE`
- `READ CAPACITY(10)`
- Sony独自 `0xFC / 0x03` 読み取りコマンド

他のHDD/SSDへSony独自コマンドを送らないよう、標準SCSI INQUIRY等でSony/NWWM候補と判定したデバイスだけを対象にします。

## この版では絶対に行わないこと

- Windowsフォーマット
- パーティション操作
- セクタ書き込み
- UPGファイルのコピー
- ファームウェア書き込み
- Sony更新開始コマンド `0xFC / 0x04`

そのため、v0.4-devは **診断＋Issue #1専用の実験的な更新再開版** です。





## v0.4-dev: Issue #1 専用の実験的な更新再開

実機のv0.3.1-devログで、通常のDisk interface経由からSony `0xFC/0x03` がSCSI GOODで成功し、8バイト `01 00 0D 00 20 02 00 00` を取得できました。一方で `TEST UNIT READY` と `READ CAPACITY(10)` は引き続き `NOT READY / 3A00 (Medium Not Present)` です。

純正Updaterの `SendFWUpdateCommand` を再解析すると、通常の更新シーケンスは概ね次の順序です。

1. 公式UPGをWalkmanのドライブへ `MSFWUPGR.UPG` としてコピー
2. Sony vendor CDB `0xFC / 0x04` を送信
3. 本体側で更新処理を開始

Issue #1では公式更新が99%付近まで進んでから失敗しているため、`MSFWUPGR.UPG` が内部に残っている可能性があります。ただし、現在はNo MediaのためPC側からそのファイルの存在・完全性を確認できません。**この点は推測であり、保証できません。**

v0.4-devでは「更新再開を試す」ボタンを追加しました。ボタンは次の条件をすべて満たした場合だけ有効になります。

- USB IDが `VID_054C&PID_01FB`
- Disk interfaceがそのUSBデバイス配下にある
- SCSI INQUIRYが `SONY / NWWM MEM AAD2`
- TEST UNIT READYが `NOT READY / 3A00`
- READ CAPACITY(10)が `NOT READY / 3A00`
- Sony `FC/03` がSCSI GOOD
- FC/03の8バイト応答がIssue #1で確認済みの `01 00 0D 00 20 02 00 00` と完全一致

さらに復旧ボタンを押した直後にも同じ条件を再検証します。条件が変わっていれば `FC/04` は送信しません。

実行前には警告ダイアログを表示し、既定ボタンを「いいえ」にしています。明示的に「はい」を選んだ場合だけ、純正Updaterと同じ12-byte CDB `FC 00 04 00 00 00 00 00 00 00 00 00` をデータ転送なしで1回だけ送ります。

**重要:** v0.4-devは一般的なNW-E405修復ツールではありません。現時点ではIssue #1の「Ver.1.x→2.0更新が99%付近で失敗し、MEMORY ERROR / No Mediaになった個体」を対象にした実験的な復旧再開モードです。内部に残る更新ファイルが不完全な場合、状態が悪化する可能性があります。

FC/04が成功しても追加の書き込みコマンドを自動実行しません。状態が落ち着いた後に再度「診断する」を実行し、新しいログで結果を確認します。

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
- [x] Issue #1専用のFC/04更新再開ゲート v0.4-dev
- [ ] 故障実機からGUI版ログ収集
- [ ] SONYSPTI / scsipath経路への対応
- [ ] Sony vendor command応答の詳細解析
- [ ] UPGパッケージ形式の解析
- [ ] 安全な復旧シーケンスの検証
- [ ] 書込み/再フラッシュ機能（十分な検証後のみ）

## Source

GUI版のソースは `src/NW-E405-Recovery-Tool.c` にあります。

Windows 7との互換性を優先して、.NETではなくWin32 APIで実装しています。ReleaseのEXEは32-bit PEとしてビルドされています。

## Sony firmwareについて

Sony公式ファームウェア、UPGファイル、純正Updaterバイナリそのものはこのリポジトリに含めません。

このリポジトリは故障した所有機器の診断・復旧研究を目的とした独立した実験プロジェクトで、Sonyとは無関係です。

## Disclaimer

開発中の実験ツールです。v0.2-devは読み取り専用になるよう設計していますが、利用は自己責任でお願いします。今後追加する可能性のある書き込み系復旧機能は、安全性を確認できるまでデフォルト無効とします。

---

### English

Experimental recovery research for Sony NW-E405 units stuck at **MEMORY ERROR / No Media** after a failed firmware update.

**v0.4-dev is a native Windows 7 GUI diagnostic/recovery-resume executable. Stage 1 is read-only: no formatting, sector writes, firmware writes, UPG copying, or Sony update-start command are performed.**
