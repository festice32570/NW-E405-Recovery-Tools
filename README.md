# NW-E405 Recovery Tools

> 🚧 **Work in progress / 開発中**
>
> Sony Network Walkman **NW-E405** がファームウェア更新失敗後に `MEMORY ERROR` となり、Windowsではリムーバブルディスクが見えるものの「ディスクを挿入してください / No Media」となる症状を調査・復旧するための実験的ツールです。

## GUI版 v0.2-dev

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

## v0.2-devで実行する処理

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

そのため、v0.2-devは **復旧そのものではなく、復旧可能性を判断する診断版** です。

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
- [x] Windows 7対応ネイティブGUI v0.2-dev
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

**v0.2-dev is a native Windows 7 GUI diagnostic executable. Stage 1 is read-only: no formatting, sector writes, firmware writes, UPG copying, or Sony update-start command are performed.**
