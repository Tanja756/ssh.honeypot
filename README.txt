SSH Honeypot — захват credentials атакующих в изолированном окружении.


УСТАНОВКА

  pip install -r requirements.txt


ЗАПУСК

  python3 ssh_honeypot.py

  По умолчанию слушает порт 2222, эмулирует Ubuntu 22.04.
  Лог пишется в honeypot.log (JSON).


ПРИМЕРЫ

  python3 ssh_honeypot.py --profile debian-12
  python3 ssh_honeypot.py --profile centos-9 --port 2222
  sudo python3 ssh_honeypot.py --port 22 --drop-privs


ПРОФИЛИ ЭМУЛЯЦИИ

  --list-profiles — показать все доступные профили
  --profile NAME  — выбрать профиль (ubuntu-22.04, debian-12, centos-9, ...)

  Профиль задаёт: SSH-баннер, тип ключа хоста, разрядность ключа.


ПАРАМЕТРЫ КОНФИГУРАЦИИ (honeypot.yaml)

  Сеть:
    bind_host — адрес прослушивания (0.0.0.0)
    bind_port — порт (2222)
    backlog   — TCP backlog (100)

  Таймауты:
    connection_timeout — таймаут сокета, сек (60.0)
    auth_timeout       — время ожидания аутентификации, сек (30.0)

  Rate limiting (на IP):
    rate_window               — окно для лимита соединений, сек (60)
    rate_max_conn             — макс. соединений за окно (5)
    auth_rate_window          — окно для лимита попыток входа, сек (60)
    auth_rate_max_attempts    — макс. попыток аутентификации за окно (10)

  Логирование:
    log_file          — путь к логу (honeypot.log)
    log_json          — JSON-формат (true/false)
    log_max_size      — макс. размер файла до ротации (104857600 = 100 МБ)
    log_max_backups   — кол-во сжатых архивов (2)
    log_max_field_len — обрезка логина/пароля до N символов (256)

  Безопасность (требует root):
    drop_privileges — сброс привилегий после bind (false)
    run_as_user     — пользователь (nobody)
    run_as_group    — группа (nogroup)
    chroot_dir      — chroot-каталог (/var/empty)

  Ключ хоста:
    host_key_path — путь к ключу (ssh_host_key, авто-генерация)


АНАЛИЗАТОР ЛОГОВ

  python3 honeypot_stats.py honeypot.log

  Выводит: топ IP, топ паролей, топ пар логин:пароль, статистику по дням.


СОБЫТИЯ ЛОГА

  auth_attempt           — попытка аутентификации
  auth_rate_limited      — отклонена из-за лимита попыток
  connection_dropped     — соединение отклонено (rate limit)
  connection_timeout     — таймаут соединения
  channel_request        — запрос открытия канала
  exec_request           — запрос выполнения команды (отклонён)
  server_start/stop      — жизненный цикл сервера
  shutdown               — получен сигнал
  host_key_* / config_*  — события ключа и конфига
  privilege_*            — операции с привилегиями


SYSTEMD

  cp ssh-honeypot.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now ssh-honeypot


DOCKER

  docker build -t ssh-honeypot .
  docker run -d -p 2222:2222 --name honeypot ssh-honeypot

  С сохранением логов:
  docker run -d -p 2222:2222 -v $(pwd)/logs:/opt/ssh-honeypot ...


БЕЗОПАСНОСТЬ

  - Доступ к shell никогда не предоставляется
  - Все попытки аутентификации отклоняются (AUTH_FAILED)
  - Rate limiting соединений и попыток аутентификации по IP
  - Chroot + сброс привилегий + capability bounding
  - Ограничения ресурсов (FD, процессы, память, файлы)
  - Никакие системные команды не выполняются
