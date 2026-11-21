# syntax=docker/dockerfile:1
FROM php:8.4-apache-bookworm@sha256:5d55c49594dd833e2e4ff677b65f7d8ff48817f443a60691d9b2b382413bba42 AS php-base
RUN apt-get update && apt-get install -y --no-install-recommends libicu-dev libonig-dev libxml2-dev libzip-dev unzip \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql intl mbstring zip opcache \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /var/www/html
ENV APP_ENV=prod APP_DEBUG=0

FROM php-base AS tooling
COPY --from=composer:2@sha256:0c8e663f14c94d07b3c45b175c51f5a14718508f21fe4dd7e54f09488dd0ed71 /usr/bin/composer /usr/local/bin/composer

FROM tooling AS dependencies
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --no-progress --no-scripts

FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS assets
WORKDIR /app
COPY --from=dependencies /var/www/html/vendor/symfony/ux-react/assets ./vendor/symfony/ux-react/assets
COPY package.json package-lock.json .npmrc webpack.config.mjs ./
COPY assets ./assets
RUN npm ci --include=dev && npm run build

FROM php-base AS app
COPY . .
COPY --from=dependencies /var/www/html/vendor ./vendor
COPY --from=assets /app/public/build ./public/build
COPY docker/php.ini /usr/local/etc/php/conf.d/acme.ini
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
COPY docker/entrypoint.sh /usr/local/bin/acme-entrypoint
RUN a2enmod rewrite headers && sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf \
    && echo 'ServerName localhost' >> /etc/apache2/apache2.conf \
    && cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
    && mkdir -p var/cache var/log /var/run/apache2 /var/lock/apache2 \
    && chown -R www-data:www-data var /var/run/apache2 /var/lock/apache2 /var/log/apache2 \
    && chmod +x /usr/local/bin/acme-entrypoint
USER www-data
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=60s --retries=12 CMD php docker/healthcheck.php
ENTRYPOINT ["acme-entrypoint"]
CMD ["apache2-foreground"]
