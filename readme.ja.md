# Yuki Core

Yuki エコシステムのサーバー（「頭脳」）。デバイスを認証し、コマンドをルーティングし、デバイス間メッセージを中継し、メトリクスを収集し、`yuki-webui` のダッシュボードが接続するリアルタイムチャンネルを提供する、Python `asyncio` 製の WebSocket サーバーです。

## 必要要件

Python 3.10 以上。依存関係は `requirements.txt` で固定されています（`websockets==16.0`、`psutil==7.2.2`）。

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python core.py
```

デフォルトでは `ws://0.0.0.0:8000` で待ち受け、パスは2つあります。`/device`（`yuki-humidifier`、`yuki-device-pc`、`yuki-device-pc-linux`、`yuki-device-android` 用）と `/webui`（`yuki-webui` のブラウザ側ダッシュボード用）です。

## 設定（環境変数）

| 変数 | デフォルト | 用途 |
|---|---|---|
| `YUKI_AUTH_TOKEN` | （自動生成） | デバイス共有認証トークン。未設定の場合、初回起動時にランダムな32文字のトークンが生成され、`.token`（パーミッション600）に保存され、下記のスケジュールでローテーションされます。 |
| `YUKI_TOKEN_ROTATION_HOURS` | `24` | 自動生成トークンをローテーションする間隔。`YUKI_AUTH_TOKEN` が設定されている場合は無視されます。 |
| `YUKI_DEBUG` | 未設定 | 設定すると、予期しない接続エラー発生時に1行のログだけでなく完全なトレースバックを出力します。 |
| `YUKI_TLS_ENABLED` | 未設定 | 真値（`1`/`true`/`yes`）を設定すると、`ws://` の代わりに `wss://` で待ち受けます - `YUKI_TLS_CERT`/`YUKI_TLS_KEY` も必要です。 |
| `YUKI_TLS_CERT` / `YUKI_TLS_KEY` | 未設定 | `YUKI_TLS_ENABLED` 設定時に使用する PEM 形式の証明書/鍵のパス。 |

暗号化はエコシステム全体で**デフォルトでオフ**です。core ↔ device/webui 間のリンクで有効にするには、3つの `YUKI_TLS_*` 変数をまとめて設定してください。

## データファイル

すべて `core.py` と同じディレクトリに保存されます。`yuki_core.db`（SQLite - 既知のデバイス、認可情報、ブラックリスト、メトリクス履歴、監査ログ）、`.token`/`.token_meta`（現在の認証トークンとその作成日時、パーミッション600）、`logs/`（実行ごとに1つのログファイル）。

## デバイスの認可

有効な `auth_token` を提示したデバイスが自動的に信頼されるわけではありません - 認可済みデバイス一覧にまだ登録されていない場合、`yuki-core` は接続中の `yuki-webui` クライアントにそのデバイスの承認を求め（`device_auth_request`/`device_auth_response`）、それが済むまでハンドシェイクを完了しません。デバイスはブラックリストに登録することもでき、その場合はトークンの有効性に関わらず接続が即座に拒否されます。

## プロトコル

`libs/yuki-protocol/python/` に同梱されたコピーを通じて Yuki Protocol `yuki/1.0` を使用します - メッセージ形式そのものについては [`yuki-protocol`](../yuki-protocol) を参照してください。
