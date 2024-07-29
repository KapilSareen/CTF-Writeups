### Challenge - Crystals

The challenge consists of a Sinatra application which serves a static page on `GET /`. The flag in located in hostname of the container which can be seen as in docker-compose.yml file:
```
version: '3.3'
services:
  deployment:
    hostname: $FLAG
    build: .
    ports:
      - 10001:80

```
Nginx is also set-up using the config file given in the source:
```
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        multi_accept on;
}

http {

        server {
                listen 80;
                server_name 127.0.0.1 localhost;
                location / {
                        proxy_pass http://127.0.0.1:4567;
                }

}

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;Dockerfile

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        gzip on;

        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;


}

```

On researching, we found out that if nginx server gets an error which it cannot identify, it passes the request directly to the backend leaking sensitive info.
So, we just need to make nginx to throw an error.

We tried requesting on `GET /\` using burp suite and it crashed the app leaking hostname(flag) on the error page.

`PS: The following exploit won't work on browsers as they automatically detect and remove invalid characters`