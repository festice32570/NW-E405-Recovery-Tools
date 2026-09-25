# NW-E405 Recovery Tools

> 🚧 **Work in progress / 開発中**  
> Sony Network Walkman **NW-E405** で、ファームウェア更新失敗後に `MEMORY ERROR` が表示され、Windowsではリムーバブルディスクとして見えるものの「ディスクを挿入してください」となる個体を調査・復旧するための実験的ツールです。

## 現在の状態

現在公開している **v0.1 は診断専用（READ-ONLY）** です。

- フォーマットしません
- セクタを書き換えません
- ファームウェアを書き込みません
- Sonyの更新開始コマンドは送信しません

壊れたNW-E405が、USB/SCSIレベルでどこまで応答できるかを安全側で確認するためのStage 1です。

## 想定している症状

- NW-E405のファームウェアアップデートに失敗した
- 本体に `MEMORY ERROR` が表示される
- サービスモードに入れない
- PCへのUSB接続自体は認識する
- Windows Explorerでは半透明の「リムーバブルディスク」が表示される
- 開こうとすると「リムーバブルディスクにディスクを挿入してください」と表示される
- ファーム更新前の空き容量が少なかった

## v0.1で調べること

`NW-E405-Recovery-Probe.ps1` はWindowsのSCSI Pass Throughを使用して以下を確認します。

- Sony NW-E405のUSB/PnP認識（VID 054C / PID 01FB）
- WindowsがPhysicalDriveを作成しているか
- SCSI `INQUIRY`
- `TEST UNIT READY`
- `REQUEST SENSE`
- `READ CAPACITY(10)`
- Sony独自の読み取りコマンド `0xFC / 0x03`

## 使い方（Windows 7）

1. 可能なら他のUSBメモリやカードリーダーを外します。
2. 故障したNW-E405をUSBハブを使わずPCへ直接接続します。
3. このリポジトリをZIPでダウンロードするか、Releaseの診断ツールを展開します。
4. `RUN_DIAGNOSTIC.cmd` を右クリックして **「管理者として実行」** します。
5. 診断が完了すると、同じフォルダに次のようなログが作成されます。

```
NW-E405_diag_YYYYMMDD_HHMMSS.txt
```

6. ログをGitHub Issues等へ貼ってください。

Windows 7 + PowerShell 2.0以上 + .NET Frameworkを想定しています。Python/Linux/SonicStageはStage 1では不要です。

## 絶対にやらないでほしいこと

現状の故障個体に対して、次の操作は推奨しません。

```
Windowsのフォーマット
ディスクの管理から初期化
diskpart clean
chkdsk /f
サードパーティ製フォーマッタ
```

「No Media」状態は通常のFAT破損より深い可能性があり、追加の書き込みで復旧調査に必要な状態を失う可能性があります。

## 解析で分かったこと

Sony公式のNW-E405/E407用アップデータを解析すると、更新コンポーネントには `FWUpdaterCom.dll` が含まれており、Windowsの `DeviceIoControl` とSCSI Pass Throughを使用する実装が確認できます。

また、解析上はSony独自SCSI CDBとして少なくとも以下の処理が確認されています。

```
0xFC / 0x03  読み取り系（FW/デバイス情報取得に使用される経路）
0xFC / 0x04  更新開始に関係すると思われる経路
```

**v0.1では `0xFC / 0x04` は意図的に無効です。**

公式Updaterには `\\.\SONYSPTI` / `\\.\scsipath%d` というSony独自のSCSIアクセス経路も存在しており、通常のPhysicalDrive経由でアクセスできない場合の次の調査対象です。

## ログで特に見たいもの

### INQUIRYは通るがREAD CAPACITYが失敗

USB/SCSIコマンド処理は生きているものの、内蔵フラッシュをメディアとして公開できていない可能性があります。

### Sony `0xFC/0x03` が成功

これは非常に重要です。通常のMass Storageが壊れていてもSony独自コマンド処理部が生存している可能性があり、ソフトウェア復旧の余地があります。

### PhysicalDrive自体が作成されない

v0.1ではそこで終了します。今後、Sony純正のSONYSPTI経路を利用する方法を追加する予定です。

## Roadmap

- [x] Sony公式Updaterの展開・構造調査
- [x] FWUpdaterCom.dllのSCSI経路確認
- [x] READ-ONLY診断ツール v0.1
- [ ] 実機の故障個体からログ収集
- [ ] SONYSPTI/scsipath経路への対応
- [ ] Sony vendor command応答の詳細解析
- [ ] UPGパッケージ形式の解析
- [ ] 安全な復旧シーケンスの検証
- [ ] 書き込み/再フラッシュ機能（安全性が確認できた場合のみ）

## Sonyファームウェアについて

Sony公式のファームウェア/UPGファイルそのものはこのリポジトリには含めません。

このリポジトリは、故障した所有機器の診断・復旧研究を目的とした独立した実験プロジェクトで、Sonyとは無関係です。

## 対象機種

現時点の主対象は **NW-E405** です。

同世代のNW-E403 / NW-E407 / NW-E505 / NW-E507も類似した構造を持つ可能性がありますが、v0.1はNW-E405向けとして扱ってください。

## Disclaimer

このプロジェクトは開発中です。  
Stage 1は書き込み操作を行わないよう設計していますが、使用は自己責任でお願いします。今後の実験的な復旧機能についても、十分な実機検証が終わるまではデフォルトで無効にする方針です。

---

### English

Experimental recovery research for Sony NW-E405 units that became stuck at **MEMORY ERROR** after a failed firmware update and appear as **No Media** in Windows.

**v0.1 is read-only diagnostics only. No formatting, sector writes, firmware writes, or update-start commands are performed.**
