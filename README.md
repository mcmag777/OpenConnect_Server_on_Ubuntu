# Установка и настройка сервера OpenConnect на Ubuntu 24.04/22.04

В данной статье хочу поделиться своим опытом по установке сервера OpenConnect и подключению к нему роутера Keentetic, но чтобы при этом используя только выборочную адресацию при помощи Bird4Static и BGP.
В последние года много экспериментировал с различными сервисами с разной степени удобства и на данный момент для себя остановился на OpenConnect, так как с некоторых пор роутеры Keenetic из коробки поддерживают данный протокол.
Опять же OpenConnect — это open source реализация всем известного Cisco AnyConnect. Что позволяет использовать OpenConnect на любых устройствах используя Cisco AnyConnect, либо Clavister OneConnect (лично мне он кажется удобнее, так как позволяет сохранить пароль для подключения), для десктопов дополнительно есть ПО OpenConnect на сайте разработчика.

И так что нам понадобится:

VPS – облачный сервер, я для себя выбрал justhost, не самый дешевый, но удобный

Личный домен – можно купить свой за 180 рублей, либо сделать субдомен на уже имеющемся, можно получить бесплатный субдомен, например на **duckdns.org**

Клиент – для ПК это OpenConnect, либо Cisco AnyConnect; для смартфонов это Cisco AnyConnect, либо более удобный Clavister OneConnect (для Android из России недоступен, но можно скачать и установить через ApkPure)

## 1.	Подготовка сервера и установка OpenConnect

Берем любой VPS сервер с Ubuntu, почти все сейчас идут с предустановленной ОС по выбору.

Первое, что необходимо сделать, это включить маршрутизацию пакетов в системе, чтобы сервер мог передавать их между интерфейсами, для этого редактируем **/etc/sysctl.conf**

```bash
sudo nano /etc/sysctl.conf
```

найдем и раскомментируем (либо добавим) строку 

```bash
net.ipv4.ip_forward = 1
```
Чтобы повысить анонимность и исключить определение туннелирования двусторонним пингом, добавим строку

```bash
net.ipv4.icmp_echo_ignore_all=1
```

Для ускорения работы через TCP я лично добавляю сюда же (вы можете этого не дописывать)

```bash
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

Для сохранения и закрытия нажмите **F2**, затем **Y** для подтверждения и **Enter** для записи файла

Обязательно применим настройки командой

```bash
sudo sysctl -p
```

Так как мы будем использовать SSL соединение, то необходимо учесть еще один важный параметр, это совпадение времени между клиентом и сервером, для этого включим и настроим синхронизацию с вышестоящими NTP-серверами используя стандартную службу systemd-timesyncd
Откроем конфигурационный файл

```bash
sudo nano /etc/systemd/timesyncd.conf
```

Раскомментируем параметр NTP и укажем в нем через пробел сервера времени
```bash
NTP=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org
```
Перезапустим службу и проверим статус
```bash
sudo systemctl restart systemd-timesyncd
sudo systemctl status systemd-timesyncd
```
Состояние синхронизации можно проверить командой
```bash
sudo timedatectl
```
Для удобства можете установить свой часовой пояс
```bash
sudo timedatectl list-timezones (посмотреть список зон)
sudo timedatectl set-timezone US/Alaska (установить свою зону, например US/Alsaka)
```
Теперь установим сам сервер OpenConnect:
```bash
sudo apt update
sudo apt install ocserv
```
После установки проверяем статус службы
```bash
sudo systemctl status ocserv
```
В выводе команды нас интересует параметр в строке Loaded следующий после пути к файлу юнита, если там стоит $${\color{green}enabled}$$, то автозагрузка службы включена и ничего делать не нужно
<div align="center">
  <img src="https://github.com/mcmag777/OpenConnect_Server_on_Ubuntu/blob/c4d7933422d4c3f9e6162e38b1709f3230e82c8c/systemctl.jpg" />
</div>

Не пугайтесь надписи $${\color{red}failed}$$ у нас еще не настроен конфиг сервера. Если же состояние **disabled**, то добавим ocserv в автозагрузку командой
```bash
sudo systemctl enable ocserv
```
Дальнейшие действия зависят от того, какой тип сертификата вы решите использовать, я рекомендую использовать сертификаты от Let's Encrypt, в этой статье будет использоваться только этот метод.

## 2.	Получение сертификатов от Let's Encrypt
Для работы с Let's Encrypt нам понадобится доменное имя, доменное имя можно купить, это недорого, от 170 руб. в зоне RU, при том, что домен всегда пригодится.
**Обратите внимание, что после покупки доменного имени и привязки его к серверу, понадобится около 1 суток (чаще меньше около 12ч), для того чтобы ваш домен стал видеться в сети интернет, а соответственно все действия по получению сертификата и дальнейшей настройке сервера нужно делать только после этого.** Если же у вас есть уже сайт, можно сделать поддомен и привязать к IP нашего сервера, тогда работать начнет сразу. Либо можно зарегистрировать поддомен бесплатно на любом ресурсе, например  на **duckdns.org**

Возьмем для примера вымышленный домен **barabashka.com**

Для начала поставим **certbot**
```bash
sudo apt install certbot
```
Затем получим бесплатный сертификат для нашего домена
```bash
sudo certbot certonly -d barabashka.com --standalone
```
При первом запуске вам потребуется ввести рабочий адрес электронной почты и принять условия использования сервиса. Все сертификаты Let's Encrypt выдаются сроком на 90 дней и certbot будет их автоматически продлять, единственное что нам остается сделать, это настроить перезапуск сервера OpenConnect после получения нового сертификата.
Для этого отредактируем конфиг Let's Encrypt нашего сайта
```bash
sudo nano /etc/letsencrypt/renewal/barabashka.com.conf
```
Добавим строчку
```bash
post_hook = systemctl restart ocserv
```
SSL/TLS шифрование немыслимо без совершенной прямой секретности - PFS, поэтому создадим файл с параметрами Диффи-Хеллмана
```bash
sudo openssl dhparam -out /etc/ocserv/dh.pem 3072 (генерироваться файлик будет не быстро, просто подождите)
```
Далее нам нужно настроить конфигурацию сервера, для этого
```bash
nano /etc/ocserv/ocserv.conf
```
Вы можете настроить свои параметры, либо взять уже мой готовый конфиг и подправить под себя:
```bash
auth = "plain[passwd=/etc/ocserv/ocserv.passwd]"

# Номера портов TCP\UDP
tcp-port = 443
udp-port = 443
# пользователь от чьего имени запускать процесс
run-as-user = nobody
run-as-group = daemon

socket-file = /run/ocserv.socket

## Путь к сертификатам

server-cert = /etc/letsencrypt/live/barabashka.com/fullchain.pem
server-key = /etc/letsencrypt/live/barabashka.com/privkey.pem

isolate-workers = true
max-clients = 0
max-same-clients = 5
rate-limit-ms = 100
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-ALL:+VERS-TLS1.2:-ARCFOUR-128"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
log-level = 2
device = vpns
predictable-ips = true

# укажите домен для вашего впна
default-domain = barabashka.com

## Пул адресов выдаваемых впн клиенту.
## так же можно укзать подсеть, например 192.168.200.1/24
ipv4-network = 192.168.100.1
ipv4-netmask = 255.255.255.0

ping-leases = false

## маршруты которые будут пушится клиентам 
## если default то у клиента сменится основной шлюз
## и весь трафик завернет в впн. тогда не забудте
## добавить еще строчку dns = <dns.ip?
#route = 192.168.168.0/255.255.255.0
#route = 192.168.1.0/255.255.255.0
#route = fef4:db8:1000:1001::/64
route = default
tunnel-all-dns = true
dns = 1.1.1.1
dns = 8.8.8.8
dns = 77.88.8.8
# маршруты которые изключить из пуша
#no-route = 192.168.5.0/255.255.255.0

cisco-client-compat = true
dtls-legacy = true
cisco-svc-client-compat = false
client-bypass-protocol = false
camouflage = false
#camouflage_secret = "mysecret"
#camouflage_realm = "Restricted Content"

# HTTP headers
included-http-headers = Strict-Transport-Security: max-age=31536000 ; includeSubDomains
included-http-headers = X-Frame-Options: deny
included-http-headers = X-Content-Type-Options: nosniff
included-http-headers = Content-Security-Policy: default-src 'none'
included-http-headers = X-Permitted-Cross-Domain-Policies: none
included-http-headers = Referrer-Policy: no-referrer
included-http-headers = Clear-Site-Data: "cache","cookies","storage"
included-http-headers = Cross-Origin-Embedder-Policy: require-corp
included-http-headers = Cross-Origin-Opener-Policy: same-origin
included-http-headers = Cross-Origin-Resource-Policy: same-origin
included-http-headers = X-XSS-Protection: 0
included-http-headers = Pragma: no-cache
included-http-headers = Cache-control: no-store, no-cache
```
Не забудте поменять домен на свой в строках
```bash
server-cert = /etc/letsencrypt/live/barabashka.com/fullchain.pem
server-key = /etc/letsencrypt/live/barabashka.com/privkey.pem
default-domain = barabashka.com
```
Cохраняем файл конфигурации и перезапускаем службу
```bash
sudo systemctl restart ocserv
```

## 3.	Создание пользователей OpenConnect
Для создания клиентов воспользуемся утилитой **ocpasswd**:
```bash
ocpasswd -c /etc/ocserv/ocserv.passwd Ivanov
```
Если файл не существует, то при первом выполнении команды он будет создан.

Для блокировки пользователя используйте:
```bash
ocpasswd -c /etc/ocserv/ocserv.passwd -l Ivanov
```
Для разблокировки:
```bash
ocpasswd -c /etc/ocserv/ocserv.passwd -u Ivanov
```
Для удаления пользователя выполните команду:
```bash
ocpasswd -c /etc/ocserv/ocserv.passwd -d Ivanov
```
Файл с паролями читается динамически, перезапуск сервера после операций с пользователями не нужен

## 3.	Дополнение
Не на всех хостингах будет сразу всё работать, где-то необходимо задать правила **iptables**
```bash
sudo iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT
```
Вместо **192.168.100.0/24** нужно подставить значение, которое вы задали в файле **ocserv.conf** в параметре **ipv4-network**

Вместо **eth0** нужно подставить название интерфейса с внешним IP вашего VPS, для того чтобы узнать названия интерфайсов выполните команду
```bash
sudo ip addr
```
Для того чтобы правила iptables сохранились установим утилитку
```bash
apt install iptables-persistent
netfilter-persistent save
```

$${\color{green}**DONE**}$$
