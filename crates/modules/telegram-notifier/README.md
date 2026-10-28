# Telegram Notifier

This module sends threat events to a Telegram chat or channel using a bot token.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`bot_token` (required)|string|telegram bot token|
|`chat_id` (required)|string|chat/channel id|
|`api_url`|string|telegram api base url|

Default configuration:

```ini
[telegram-notifier]
enabled=false
api_url=https://api.telegram.org
```

This module is disabled by default. You can enable it with:

```sh
pulsar config --set telegram-notifier.enabled=true
```
