#!/bin/sh
set -eu
if [ "$1" = apache2-foreground ]; then
    php docker/wait-db.php
    php bin/console doctrine:migrations:migrate --no-interaction --allow-no-migration
    php bin/console cache:clear --no-warmup
    php bin/console cache:warmup
fi
exec "$@"
